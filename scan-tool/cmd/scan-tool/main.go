package main

import (
	"fmt"
	"os"
	"time"

	"github.com/COMSYS/ipv6-scanning/scan-tool/pkg/helper"
	"github.com/COMSYS/ipv6-scanning/scan-tool/pkg/mode"
	"github.com/akamensky/argparse"
	log "github.com/sirupsen/logrus"
)

func main() {
	// Create new parser object
	parser := argparse.NewParser("scan-tool", "Generate a single scanlist by address generation seeded from different sources.")

	p_mode := parser.Selector("m", "mode", []string{"scan", "subscan"}, &argparse.Options{Required: true, Help: "Mode to run. I.e., scan or subscan.", Default: "scan"})

	// Create string flag
	protocol := parser.String("p", "protocol", &argparse.Options{Required: false, Help: "Protocol to scan"})
	scan_rate := parser.Int("r", "rate", &argparse.Options{Required: false, Help: "Scanning rate", Default: 50000})
	netif := parser.String("i", "interface", &argparse.Options{Required: false, Help: "Interface to use", Default: "eth0"})
	result_root_path := parser.String("", "results", &argparse.Options{Required: false, Help: "Path to result folder", Default: "/results"})
	tool_config_path := parser.String("c", "config", &argparse.Options{Required: false, Help: "Path to scan-tool config file", Default: "/config/scan-tool.yaml"})

	config_root_path := parser.String("", "mesconfig", &argparse.Options{Required: false, Help: "Path to measurement config folder", Default: "/measurement-configuration/scan-tool"})
	blacklist4_path := parser.String("", "blacklist4", &argparse.Options{Required: false, Help: "Path to blacklist for IPv4", Default: "/scanner/blacklist"})
	blacklist6_path := parser.String("", "blacklist6", &argparse.Options{Required: false, Help: "Path to blacklist for IPv6", Default: "/scanner/blacklist6"})

	ipver := parser.Selector("", "ipver", []string{helper.IPv4, helper.IPv6}, &argparse.Options{Required: false, Help: "IP Version to scan.", Default: helper.IPv4})
	subnet := parser.String("s", "subnet", &argparse.Options{Required: false, Help: "IPv4 subnet to scan", Default: "0.0.0.0/0"})
	addressfile := parser.String("", "addressfile", &argparse.Options{Required: false, Help: "File of IPv6 addresses to scan. If empty download via HTTP.", Default: ""})

	generator := parser.StringList("", "generators", &argparse.Options{Required: false, Help: "Methods to actively generate IPv6 addresses. Syntax: {approach}-{budget}-{colon}-{srckey}", Default: []string{"clean"}})

	duration := parser.String("", "duration", &argparse.Options{Required: false, Help: "Maximum duration before killing all subprocesses / stop waiting for generators. Valid units: h, m, s.", Default: "24h"})

	debuglevel := parser.Selector("d", "debug-level", []string{"INFO", "DEBUG", "WARN"}, &argparse.Options{Required: false, Help: "Log Level", Default: "INFO"})
	log_meta_path := parser.String("", "logfiles", &argparse.Options{Required: false, Help: "Path to logfiles that must be copied in every result directory.", Default: "/logs"})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		return
	}

	loglevel, err := log.ParseLevel(*debuglevel)
	if err != nil {
		log.Fatalf("Specified log level not allowed: %s", *debuglevel)
	}
	log.SetLevel(loglevel)

	tool_config, err := helper.ParseConfigurationToMap(*tool_config_path)
	if err != nil {
		log.Fatalf("error parsing tool config file (%s): %s", *tool_config_path, err)
	}

	pduration, err := time.ParseDuration(*duration)
	if err != nil {
		log.Errorf("error parsing duration %s: %s", *duration, err)
	}

	// We decide between the scan mode, i.e., the mode running the
	// main zmap instance and piping all responding IP addresses into
	// a subsequent application scanner, and subscans that wait for
	// specific seed IP addresses and run a generator on them
	if *p_mode == "scan" {
		scanparams := &helper.ScanParameters{
			Protocol:           *protocol,
			ScanRate:           *scan_rate,
			Interface:          *netif,
			ConfigRootPath:     *config_root_path,
			Blocklist4Path:     *blacklist4_path,
			Blocklist6Path:     *blacklist6_path,
			IPver:              *ipver,
			Subnet:             *subnet,
			LogMetaPath:        *log_meta_path,
			ResultRootPath:     *result_root_path,
			IPv6SeedRootPath:   tool_config["ipv6-generators"]["seedpath"],
			IPv6ResultRootPath: tool_config["ipv6-generators"]["resultpath"],
			Generators:         *generator,
			Duration:           pduration,
			IPv6Http: helper.HTTPParameters{
				URI:      tool_config["ipv6-scanlist"]["url"],
				Username: tool_config["ipv6-scanlist"]["username"],
				Password: tool_config["ipv6-scanlist"]["password"],
			},
			IPv6Addressfile: *addressfile,
		}

		mode.StartScan(scanparams)
	} else if *p_mode == "subscan" {
		subscanparams := &helper.SubScanParameters{
			IPv6SeedRootPath:   tool_config["ipv6-generators"]["seedpath"],
			IPv6ResultRootPath: tool_config["ipv6-generators"]["resultpath"],
			Rate:               *scan_rate,
			Interface:          *netif,
		}

		mode.StartSubScan(subscanparams)
	}

	log.Infof("Done. Goodbye.")
}
