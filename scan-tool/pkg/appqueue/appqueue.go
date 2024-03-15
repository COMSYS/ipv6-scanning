package appqueue

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strconv"
	"sync"

	"github.com/COMSYS/ipv6-scanning/scan-tool/pkg/helper"
	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type App struct {
	cmd     string
	params  []string
	process *exec.Cmd

	amqp_queue   string
	amqp_meta    bool
	amqp_shuffle int
	options      map[string]interface{}
}

type AppQueue struct {
	apps           []*App
	scanparameters *helper.ScanParameters
	scanattributes *helper.ScanAttributes

	Port int

	writeclosers  []io.WriteCloser
	writebuffers  []*bufio.Writer
	postFunctions []func(*AppQueue) error
}

func NewAppQueueFromYAML(parameters *helper.ScanParameters, attributes *helper.ScanAttributes) *AppQueue {
	log.Debugf("Loading configuration.")
	config_path := path.Join(parameters.ConfigRootPath, fmt.Sprintf("%s.yaml", parameters.Protocol))
	config, err := helper.ParseConfigurationToYaml(config_path)
	if err != nil {
		log.Panicf("error parsing configuration: %s", err)
	}

	result := NewAppQueue()
	result.scanparameters = parameters
	result.scanattributes = attributes

	zmap := result.AddApp("zmap")
	zmap.AddParams([]string{"-P", "1"}...)
	zmap.AddParams([]string{"-r", fmt.Sprintf("%d", parameters.ScanRate)}...)
	zmap.AddParams([]string{"-O", "json"}...)

	if parameters.IPver == helper.IPv4 {
		zmap.AddParams([]string{"-b", parameters.Blocklist4Path}...)
	} else if parameters.IPver == helper.IPv6 {
		zmap.AddParams([]string{"--ipv6-source-ip", attributes.IPaddress}...)
		zmap.AddParams([]string{"--ipv6-target-file", "/dev/stdin"}...)
	}

	for _, c := range *config {
		if c.Key.(string) == "zmap" {
			for _, p := range c.Value.(yaml.MapSlice) {
				key := p.Key.(string)
				value := fmt.Sprintf("%v", p.Value)
				if key == "type" {
					if value == "tcp" {
						if parameters.IPver == helper.IPv4 {
							zmap.AddParams([]string{"-f", "saddr,daddr,ipid,ttl,sport,dport,seqnum,acknum,window,options,classification,success,icmp_responder,icmp_type,icmp_code,icmp_unreach_str,repeat,cooldown,timestamp_str"}...)
							zmap.AddParams([]string{"-M", "tcp_synscan"}...)
							attributes.ScanType = "TCP"
						} else {
							zmap.AddParams([]string{"-f", "saddr,daddr,ipid,ttl,sport,dport,seqnum,acknum,window,classification,success,icmp_responder,icmp_type,icmp_code,icmp_unreach_str,repeat,cooldown,timestamp_str"}...)
							zmap.AddParams([]string{"-M", "ipv6_tcp_synscan"}...)
							attributes.ScanType = "TCPv6"
						}
					} else if value == "udp" {
						zmap.AddParams([]string{"-f", "saddr,daddr,ipid,ttl,sport,dport,classification,success,icmp_responder,icmp_type,icmp_code,icmp_unreach_str,repeat,cooldown,timestamp_str"}...)
						if parameters.IPver == helper.IPv4 {
							zmap.AddParams([]string{"-M", "udp"}...)
							attributes.ScanType = "UDP"
						} else {
							zmap.AddParams([]string{"-M", "ipv6_udp"}...)
							attributes.ScanType = "UDPv6"
						}
					} else {
						log.Panicf("invalid config file (unknown type: %s): %s", value, config_path)
					}
				} else if key == "port" {
					zmap.AddParams([]string{"-p", value}...)
					port, _ := strconv.Atoi(value)
					result.Port = port
				} else if key == "probe" {
					zmap.AddParams(fmt.Sprintf("--probe-args=file:/measurement-configuration/probe_files/%s", value))
					attributes.UDPProbeFile = value
				} else {
					zmap.options[key] = p.Value
				}
			}
		} else if c.Key.(string) == "applications" {
			for _, p := range c.Value.(yaml.MapSlice) {
				a := result.AddApp(p.Key.(string))
				switch params := p.Value.(type) {
				case yaml.MapSlice:
					for _, i := range params {
						if i.Key.(string) == "ini" && a.cmd == "zgrab2" {
							a.AddParams([]string{"multiple", "-c", fmt.Sprintf("/measurement-configuration/zgrab2/%s.ini", i.Value.(string))}...)
						} else if i.Key.(string) == "params" {
							for _, v := range i.Value.([]interface{}) {
								a.AddParams(v.(string))
							}
						} else if i.Key.(string) == "amqp" {
							for _, j := range i.Value.(yaml.MapSlice) {
								if j.Key.(string) == "meta" {
									a.amqp_meta = j.Value.(bool)
								} else if j.Key.(string) == "queue" {
									a.amqp_queue = j.Value.(string)
								} else if j.Key.(string) == "shuffle" {
									a.amqp_shuffle = j.Value.(int)
								}
							}
						}
					}
				}
			}
		} else {
			log.Panicf("invalid config file (unknown key: %s): %s", c.Key, config_path)
		}
	}

	if parameters.IPver == helper.IPv4 {
		zmap.params = append(zmap.params, parameters.Subnet)
	}

	log.Infof("Our constructed application list:\n%s", spew.Sdump(result))
	return result
}

func NewAppQueue() *AppQueue {
	return &AppQueue{apps: make([]*App, 0)}
}

func (aq *AppQueue) AddApp(cmd string) *App {
	result := &App{cmd: cmd, options: make(map[string]interface{})}
	aq.apps = append(aq.apps, result)
	return result
}

func (aq *AppQueue) InitializeApps(ctx context.Context, wg *sync.WaitGroup, meta map[string]interface{}) error {
	for i, j := 0, len(aq.apps)-1; i < j; i, j = i+1, j-1 {
		aq.apps[i], aq.apps[j] = aq.apps[j], aq.apps[i]
	}

	for a_num, a := range aq.apps {
		log.Infof("Initializing application %s %v..", a.cmd, a.params)
		a.process = exec.CommandContext(ctx, a.cmd, a.params...)
		a.process.Dir = aq.scanattributes.ResultPath

		f_err, err := os.Create(path.Join(aq.scanattributes.ResultPath, fmt.Sprintf("%s_err", a.cmd)))
		if err != nil {
			log.Panicf("error creating file: %s", err)
			return err
		}
		aq.writeclosers = append(aq.writeclosers, f_err)
		a.process.Stderr = f_err

		f_out, err := os.Create(path.Join(aq.scanattributes.ResultPath, fmt.Sprintf("%s_out", a.cmd)))
		if err != nil {
			log.Panicf("error creating file: %s", err)
		}

		f_out_buf := bufio.NewWriter(f_out)
		aq.writebuffers = append(aq.writebuffers, f_out_buf)

		aq.writeclosers = append(aq.writeclosers, f_out)

		stdout, err := a.process.StdoutPipe()

		cur_reader := stdout.(io.Reader)
		if err != nil {
			log.Panic(err)
			return err
		}

		if a_num > 0 {
			cur_reader = io.TeeReader(cur_reader, f_out_buf)
		}

		if a.cmd == "zmap" {
			zmap_reader, zmap_writer := io.Pipe()
			wg.Add(1)
			go func(reader io.Reader, writer io.WriteCloser) {
				defer wg.Done()

				outputMode := "saddr"
				if _, ok := a.options["outputMode"]; ok {
					outputMode = a.options["outputMode"].(string)
				}

				var outputFields []string
				if _, ok := a.options["outputFields"]; ok {
					outputFields = make([]string, len(a.options["outputFields"].([]interface{})))
					for iof, of := range a.options["outputFields"].([]interface{}) {
						outputFields[iof] = of.(string)
					}
				} else {
					outputFields = []string{"saddr"}
				}

				bufferedwriter := bufio.NewWriter(writer)
				bufferedreader := bufio.NewReaderSize(reader, 2048)

				helper.HandleZmap(bufferedwriter, bufferedreader, (aq.scanparameters.IPver == "6"), outputMode, outputFields)
				bufferedwriter.Flush()
				writer.Close()
			}(cur_reader, zmap_writer)
			cur_reader = bufio.NewReader(zmap_reader)
		}

		if a_num > 0 {
			aq.apps[a_num-1].process.Stdin = cur_reader
		} else {
			wg.Add(1)
			go func(a *App, r io.Reader) {
				defer wg.Done()
				log.Debugf("Start copying to stdout file (%s).", a.cmd)
				io.Copy(f_out, r)
				log.Debugf("Finished copying to stdout file (%s).", a.cmd)
			}(a, cur_reader)
		}
	}
	return nil
}

func (aq *AppQueue) GetFirstStdIn() (io.WriteCloser, error) {
	return aq.apps[len(aq.apps)-1].process.StdinPipe()
}

func (aq *AppQueue) Run() error {
	log.Infof("Starting processes..")
	for _, a := range aq.apps {
		err := a.process.Start()
		if err != nil {
			log.Warnf("error exectuting %s: %s", a.cmd, err)
			return err
		}
	}
	return nil
}

func (aq *AppQueue) Wait() error {
	for _, a := range aq.apps {
		log.Infof("Waiting for %s to finish..", a.cmd)
		err := a.process.Wait()
		if err != nil {
			log.Warnf("error waiting for %s: %s", a.cmd, err)
		}
		log.Infof("%s finished.", a.cmd)
	}

	for _, wb := range aq.writebuffers {
		wb.Flush()
	}

	for _, wc := range aq.writeclosers {
		wc.Close()
	}

	for _, pf := range aq.postFunctions {
		err := pf(aq)
		if err != nil {
			log.Warnf("Error while executing post function: %s", err)
		}
	}

	return nil
}

func (a *App) AddParams(params ...string) {
	a.params = append(a.params, params...)
}

func (a *App) SetAMQPout(queue string, meta bool, shuffle int) {
	a.amqp_queue = queue
	a.amqp_meta = meta
	a.amqp_shuffle = shuffle
}
