package mode

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/COMSYS/ipv6-scanning/scan-tool/internal/generators"
	"github.com/COMSYS/ipv6-scanning/scan-tool/pkg/helper"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

func StartSubScan(params *helper.SubScanParameters) {
	logWriters := make(map[string]*os.File)
	logWritersCnt := make(map[string]int)

	seedfilepaths_c := make(chan string, 100)
	err := os.MkdirAll(params.IPv6SeedRootPath, 0700)
	if err != nil {
		log.Warnf("Error creating IPv6 seed path")
		return
	}

	err = filepath.WalkDir(params.IPv6SeedRootPath, func(s string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if filepath.Ext(d.Name()) == ".iplist" && !d.IsDir() {
			seedfilepaths_c <- s
		}
		return nil
	})
	if err != nil {
		log.Warnf("Error iterating over existing seed files: %s", err)
		return
	}

	err = helper.CreateFsNotifier(context.TODO(), seedfilepaths_c, params.IPv6SeedRootPath, `.*\.iplist$`, 0, true)
	if err != nil {
		log.Warnf("Error watching IPv6 seed path")
		return
	}

	for seedfilepath := range seedfilepaths_c {
		splitpath := strings.Split(seedfilepath, "/")
		targetFolder := path.Join(params.IPv6ResultRootPath, splitpath[len(splitpath)-2])
		targetfilepath := path.Join(targetFolder, splitpath[len(splitpath)-1])
		seedfilenamewoext := strings.TrimSuffix(splitpath[len(splitpath)-1], ".iplist")

		err = os.MkdirAll(targetFolder, 0700)
		if err != nil {
			log.Warnf("Error creating IPv6 result path")
			return
		}

		num, ok := logWritersCnt[targetFolder]
		if !ok || num == 0 {
			f, err := os.OpenFile(path.Join(targetFolder, "report.log"), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
			if err != nil {
				log.Warnf("error creating report file in %s", targetFolder)
			}
			logWriters[targetFolder] = f

			lfd_writeclosers := maps.Values(logWriters)
			lfd_writers := make([]io.Writer, len(lfd_writeclosers))

			for i := range lfd_writers {
				lfd_writers[i] = lfd_writeclosers[i]
			}

			log.SetOutput(io.MultiWriter(append(lfd_writers, os.Stdout)...))
		}
		logWritersCnt[targetFolder]++

		log.Infof("Detected new seedfile %s. Expected targetfile is %s.", seedfilepath, targetfilepath)

		seedfilenameinfos := strings.Split(seedfilenamewoext, "-")
		if len(seedfilenameinfos) < 5 {
			log.Warnf("Seedfile does not include scanner parameters and budget. Continuing.")
			continue
		}

		generator, scantype, udpprobefile, port, budget := seedfilenameinfos[0], seedfilenameinfos[1], seedfilenameinfos[2], seedfilenameinfos[3], seedfilenameinfos[4]
		budgetInt, err := strconv.Atoi(budget)
		if err != nil {
			log.Warnf("Error parsing budget: %s", err)
			continue
		}

		portInt, err := strconv.Atoi(port)
		if err != nil {
			log.Warnf("Error parsing port: %s", err)
			continue
		}

		g := generators.NewGenerator(generator, scantype, udpprobefile, seedfilenamewoext, portInt, budgetInt, params.Rate, params.Interface, seedfilepath, targetfilepath)
		if g == nil || (reflect.ValueOf(g).Kind() == reflect.Ptr && reflect.ValueOf(g).IsNil()) {
			log.Warnf("Error instantiating generator.")
			continue
		}

		log.Debugf("Running generator.")
		g.Run()

		err = os.Remove(seedfilepath)
		if err != nil {
			log.Warnf("error removing seedfile %s: %s", seedfilepath, err)
		}

		if _, ok := logWritersCnt[targetFolder]; !ok {
			log.Warnf("error reading map")
		} else {
			logWritersCnt[targetFolder]--
			if logWritersCnt[targetFolder] == 0 {
				tmp_fd := logWriters[targetFolder]
				delete(logWriters, targetFolder)

				lfd_writeclosers := maps.Values(logWriters)
				lfd_writers := make([]io.Writer, len(lfd_writeclosers))

				for i := range lfd_writers {
					lfd_writers[i] = lfd_writeclosers[i]
				}

				log.SetOutput(io.MultiWriter(append(lfd_writers, os.Stdout)...))
				tmp_fd.Sync()
				tmp_fd.Close()
			}

		}
	}
}
