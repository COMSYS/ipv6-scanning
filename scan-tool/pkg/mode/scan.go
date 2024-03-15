package mode

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	cp "github.com/otiai10/copy"
	log "github.com/sirupsen/logrus"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"
	"github.com/COMSYS/ipv6-scanning/scan-tool/pkg/appqueue"
	"github.com/COMSYS/ipv6-scanning/scan-tool/pkg/blocklist"
	"github.com/COMSYS/ipv6-scanning/scan-tool/pkg/deduplicator"
	"github.com/COMSYS/ipv6-scanning/scan-tool/pkg/filter"
	"github.com/COMSYS/ipv6-scanning/scan-tool/pkg/helper"
)

func StartScan(params *helper.ScanParameters) {
	time_now := time.Now()
	timestamp := time_now.Format("2006-01-02_15-04-05")

	ctx, cancel := context.WithTimeout(context.TODO(), params.Duration)
	defer cancel()

	var scantargets string
	var scanlisturl string
	replacer := strings.NewReplacer(".", "-", "/", "-")
	if params.IPver == helper.IPv4 {
		scantargets = replacer.Replace(params.Subnet)
	} else if params.IPver == helper.IPv6 {
		if params.IPv6Addressfile == "" {
			scanlisturl = helper.DetermineNewestScanFileHTTP(params.IPv6Http, fmt.Sprintf(`.*_%s.*\.txt\.zst$`, params.Protocol))
			scantargets = strings.Split(path.Base(scanlisturl), ".")[0]
		} else {
			scantargets = strings.Split(path.Base(params.IPv6Addressfile), ".")[0]
		}
	} else {
		log.Panicf("Unknown IP version to scan: %s", params.IPver)
	}

	result_folder := fmt.Sprintf("%s_%s_v%s_%s", timestamp, params.Protocol, params.IPver, scantargets)
	result_path := path.Join(params.ResultRootPath, result_folder)
	os.MkdirAll(result_path, os.ModePerm)

	var log_writer io.Writer
	f_log, err := os.Create(path.Join(result_path, "report.log"))
	if err != nil {
		log.Panicf("error creating file: %s", err)
	}
	defer f_log.Close()

	io.WriteString(f_log, "============ LOG  ============\n\n")

	if err != nil {
		log.Warnf("Unable to write log to file. Unable to create logfile: %s", err)
		log_writer = os.Stdout
	} else {
		log_writer = io.MultiWriter(os.Stdout, f_log)
	}
	log.SetOutput(log_writer)

	address, err := helper.GetIPaddress(params.Interface, params.IPver)
	if err != nil {
		log.Warnf("Unable to get IP address for interface %s (IPv%s): %s", params.Interface, params.IPver, err)
	}

	attrib := &helper.ScanAttributes{
		ResultPath:   result_path,
		IPaddress:    address.String(),
		UDPProbeFile: "none",
	}

	log.Infof("Scan Tool started.")

	log.Infof("Copying meta files to log folder.")
	cp.Copy(params.LogMetaPath, path.Join(result_path, "logs"))
	cp.Copy(params.ConfigRootPath, path.Join(result_path, "measurement_config"))

	log.Debugf("Copying blacklists.")
	cp.Copy(params.Blocklist4Path, path.Join(result_path, "blacklists", "blacklist"))
	cp.Copy(params.Blocklist6Path, path.Join(result_path, "blacklists", "blacklist6"))

	log.Debugf("Generating measurement app queue...")
	apps := appqueue.NewAppQueueFromYAML(params, attrib) // Note that we get from here whether it is a TCP or UDP scan

	log.Debugf("Generating measurement meta information...")
	meta := make(map[string]interface{}, 0)
	meta["date"] = time_now
	meta["params"] = params
	meta["pipeline"] = apps

	helper.WriteMeta(meta, path.Join(result_path, "mes.json"))

	wg := sync.WaitGroup{}
	apps.InitializeApps(ctx, &wg, meta)

	if params.IPver == helper.IPv6 {
		var blist *blocklist.Blocklist
		log.Infof("Loading IPv6 blocklist..")
		blist, err = blocklist.NewBlocklist(params.Blocklist6Path)
		if err != nil {
			log.Panicf("error loading blacklist: %s", err)
		}
		log.Infof("Loaded.")

		var scanFile string
		if params.IPv6Addressfile == "" {
			scanFile = helper.DownloadNewestScanFileHTTP(result_path, params.IPv6Http, scanlisturl)
		} else {
			scanFile = params.IPv6Addressfile
		}

		log.Infof("Getting IPv6 file header")
		scanFileHeader := iplist.GetHeaderFromFile(scanFile)

		writer, err := apps.GetFirstStdIn()
		if err != nil {
			log.Panic(err)
		}

		wg.Add(1)
		go func(writer io.WriteCloser) {
			defer wg.Done()

			c_duplicator_in := make(chan string, 1000000)
			c_zmap_in := make(chan string, 100000000)

			go func() {
				dedup, err := deduplicator.NewDeduplicator("SlidingWindow", &deduplicator.SlidingWindowDeduplicatorSettings{Capacity: uint(params.ScanRate) * 60 * 60})
				if err != nil {
					log.Warnf("error creating deduplicator for input: %s", err)
				}
				dedup.Deduplicate(c_duplicator_in, c_zmap_in)
				close(c_zmap_in)
				dedup.Close()
			}()

			go func(writer io.WriteCloser) {
				for ip := range c_zmap_in {
					if !blist.IsBlocklisted(ip) {
						log.Debugf("pushing ip %s into appqueue", ip)
						_, err = io.WriteString(writer, fmt.Sprintf("%s\n", ip))
						if err != nil {
							log.Warnf("Error writing IP to appqueue: %s", err)
						}
					}
				}
				writer.Close()
			}(writer)

			wg6 := sync.WaitGroup{}
			var cs_scanfile_in []chan *iplist.IPEntry

			for _, g := range params.Generators {
				tmp_c := make(chan *iplist.IPEntry, 100)
				if g == "clean" {
					wg6.Add(1)
					log.Infof("Passing IPv6 addressed directly through.")

					go func(in chan *iplist.IPEntry) {
						defer wg6.Done()

						for i := range in {
							if i != nil {
								c_duplicator_in <- i.GetIPasString(true)
							}
						}
					}(tmp_c)

					cs_scanfile_in = append(cs_scanfile_in, tmp_c)
				} else {
					// approach, budget, colons, srckey, inputnum
					filter_config := strings.SplitN(g, "-", 5)
					approachStr, budgetStr, colonsStr, srckeyStr, inputnumStr := filter_config[0], filter_config[1], filter_config[2], filter_config[3], filter_config[4]

					log.Infof("Enabling generator %s on key %s.", approachStr, srckeyStr)

					budget, err := strconv.Atoi(budgetStr)
					if err != nil {
						log.Errorf("failed to convert budget in %s: %s", g, err)
						cs_scanfile_in = cs_scanfile_in[:len(cs_scanfile_in)-1]
						continue
					}
					colons := colonsStr == "true"
					inputnum, err := strconv.Atoi(inputnumStr)
					if err != nil {
						log.Errorf("failed to convert inputnum in %s: %s", g, err)
						cs_scanfile_in = cs_scanfile_in[:len(cs_scanfile_in)-1]
						continue
					}

					var expectednum int
					if _, ok := scanFileHeader["KEYVAL"]; ok {
						if expectednumStr, ok := scanFileHeader["KEYVAL"][srckeyStr]; ok {
							expectednum, err = strconv.Atoi(expectednumStr)
							if err != nil {
								log.Errorf("failed to convert expectednum in %s: %s", g, err)
								expectednum = 3000000
							}
						} else {
							log.Errorf("failed to get expectednum in %s (missing key in header)", g)
							expectednum = 3000000
						}

					} else {
						log.Errorf("failed to get expectednum in %s (missing header)", g)
						expectednum = 3000000
					}

					tmp_filter := filter.NewFilter(ctx, attrib, approachStr, srckeyStr, inputnum, expectednum, colons, path.Join(params.IPv6SeedRootPath, result_folder), path.Join(params.IPv6ResultRootPath, result_folder), apps.Port, budget)
					wg6.Add(1)
					go func(in chan *iplist.IPEntry) {
						defer wg6.Done()
						defer func() {
							if r := recover(); r != nil {
								log.Errorf("Recovered from failed filter run. Error:\n%s", r)
							}
						}()
						tmp_filter.Run(in, c_duplicator_in)
					}(tmp_c)

					if filter_config[3] == "none" { // Directly close channel when key is none
						close(tmp_c)
					} else {
						cs_scanfile_in = append(cs_scanfile_in, tmp_c)
					}
				}
			}

			// Distribute scanfile to all generators
			wg6.Add(1)
			go func() {
				defer wg6.Done()
				c_scanfile_out := make(chan *iplist.IPEntry, 10)
				go func() {
					iplist.GetIPEntriesFromZSTFile(scanFile, c_scanfile_out)
					close(c_scanfile_out)
				}()
				for ipentry := range c_scanfile_out {
					for _, c := range cs_scanfile_in {
						c <- ipentry
					}
				}
				for _, c := range cs_scanfile_in {
					close(c)
				}
			}()
			wg6.Wait()

			close(c_duplicator_in)
		}(writer)
	}

	err = apps.Run()
	if err != nil {
		log.Warnf("Error executing applications in queue: %s", err)
	}

	log.Infof("Waiting for our WaitingGroup..")
	wg.Wait()

	apps.Wait()

	if params.IPver == helper.IPv6 {
		log.Infof("Copying generated IPs to log folder.")
		moveListFrom, moveListTo := path.Join(params.IPv6ResultRootPath, result_folder), path.Join(result_path, "generatediplists")
		cp.Copy(moveListFrom, moveListTo)
		os.RemoveAll(moveListFrom)
	}

	log.Infof("Processes are done. Finalizing logfile.")

	log.SetOutput(os.Stdout)
	helper.GatherStdErrs("%s/*_err", result_path, f_log)

	log.Infof("Finalized. Compressing folder.")
	f_log.Close()

	result_path_compressed := path.Join(params.ResultRootPath, fmt.Sprintf("%s.tgz", result_folder))
	result_path_compressed_inprogress := fmt.Sprintf("%s.inprogress", result_path_compressed)
	err = helper.CompressFolder(result_path, result_path_compressed_inprogress)
	if err != nil {
		log.Fatalf("error creating compressed result archive: %s", err)
	}

	err = os.Rename(result_path_compressed_inprogress, result_path_compressed)
	if err != nil {
		log.Fatalf("error renaming compressed result archive: %s", err)
	}

	if !params.KeepResults {
		err = os.RemoveAll(result_path)
		if err != nil {
			log.Fatalf("error remove result folder: %s", err)
		}
	}
}
