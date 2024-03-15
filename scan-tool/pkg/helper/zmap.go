package helper

import (
	"bufio"
	"io"
	"strconv"
	"strings"

	"github.com/COMSYS/ipv6-scanning/scan-tool/pkg/deduplicator"
	jsoniter "github.com/json-iterator/go"
	log "github.com/sirupsen/logrus"
)

type enableMap struct {
	Saddr   bool
	Daddr   bool
	Sport   bool
	Dport   bool
	Seqnum  bool
	Acknum  bool
	Window  bool
	Class   bool
	Success bool
	Repeat  bool
}

type PartitialMap struct {
	Saddr   string `json:"saddr,omitempty"`
	Daddr   string `json:"daddr,omitempty"`
	Sport   int    `json:"sport,omitempty"`
	Dport   int    `json:"dport,omitempty"`
	Seqnum  int    `json:"seqnum,omitempty"`
	Acknum  int    `json:"acknum,omitempty"`
	Window  int    `json:"window,omitempty"`
	Class   string `json:"classification,omitempty"`
	Success bool   `json:"success,omitempty"`
	Repeat  bool   `json:"repeat,omitempty"`
}

func CreateCsvLine(options *enableMap, inputMap *PartitialMap) ([]byte, error) {
	var outputStrings []string
	if options.Saddr {
		outputStrings = append(outputStrings, inputMap.Saddr)
	}
	if options.Daddr {
		outputStrings = append(outputStrings, inputMap.Daddr)
	}
	if options.Sport {
		outputStrings = append(outputStrings, strconv.Itoa(inputMap.Sport))
	}
	if options.Dport {
		outputStrings = append(outputStrings, strconv.Itoa(inputMap.Dport))
	}
	if options.Seqnum {
		outputStrings = append(outputStrings, strconv.Itoa(inputMap.Seqnum))
	}
	if options.Acknum {
		outputStrings = append(outputStrings, strconv.Itoa(inputMap.Acknum))
	}
	if options.Window {
		outputStrings = append(outputStrings, strconv.Itoa(inputMap.Window))
	}
	if options.Class {
		outputStrings = append(outputStrings, inputMap.Class)
	}
	if options.Success {
		if inputMap.Success {
			outputStrings = append(outputStrings, strconv.Itoa(1))
		} else {
			outputStrings = append(outputStrings, strconv.Itoa(0))
		}
	}
	if options.Repeat {
		if inputMap.Repeat {
			outputStrings = append(outputStrings, strconv.Itoa(1))
		} else {
			outputStrings = append(outputStrings, strconv.Itoa(0))
		}
	}
	return []byte(strings.Join(outputStrings, ",")), nil
}

func CreateJsonLine(options *enableMap, inputMap *PartitialMap) ([]byte, error) {
	var outputMap PartitialMap
	if options.Saddr {
		outputMap.Saddr = inputMap.Saddr
	}
	if options.Daddr {
		outputMap.Daddr = inputMap.Daddr
	}
	if options.Sport {
		outputMap.Sport = inputMap.Sport
	}
	if options.Dport {
		outputMap.Dport = inputMap.Dport
	}
	if options.Seqnum {
		outputMap.Seqnum = inputMap.Seqnum
	}
	if options.Acknum {
		outputMap.Acknum = inputMap.Acknum
	}
	if options.Window {
		outputMap.Window = inputMap.Window
	}
	if options.Class {
		outputMap.Class = inputMap.Class
	}
	if options.Success {
		outputMap.Success = inputMap.Success
	}
	if options.Repeat {
		outputMap.Repeat = inputMap.Repeat
	}

	out, err := jsoniter.Marshal(outputMap)
	if err != nil {
		log.Warnf("Error marshalling filtered zmap output: %s", err)
		return nil, err
	}
	return out, nil
}

func HandleZmap(in io.Writer, zmap_stdout io.Reader, deduplicate bool, mode string, fields []string) {
	var err error
	var options enableMap

	log.Debugf("Start handling zmap output (mode %s, forward fields %s)", mode, strings.Join(fields, ","))

	scanner := bufio.NewScanner(zmap_stdout)

	dedup, err := deduplicator.NewDeduplicator("NoFalseNegative", &deduplicator.NoFalseNegativeDeduplicatorSettings{EstimatedCapacity: 100000000})
	if err != nil {
		log.Warnf("error creating deduplicator for zmap: %s", err)
	}

	for _, f := range fields {
		options.Saddr = options.Saddr || f == "saddr"
		options.Daddr = options.Daddr || f == "daddr"
		options.Sport = options.Sport || f == "sport"
		options.Dport = options.Dport || f == "dport"
		options.Seqnum = options.Seqnum || f == "seqnum"
		options.Acknum = options.Acknum || f == "acknum"
		options.Window = options.Window || f == "window"
		options.Class = options.Class || f == "classification"
		options.Success = options.Success || f == "success"
		options.Repeat = options.Repeat || f == "repeat"
	}
	if mode == "csv" {
		in.Write([]byte(strings.Join(fields, ",")))
	}

	var inputMap PartitialMap
	for scanner.Scan() {
		log.Debugf("Got line from zmap: %s", scanner.Text())
		err = jsoniter.Unmarshal(scanner.Bytes(), &inputMap)
		if err != nil {
			log.Warnf("Could not parse json from zmap (%s): %s", scanner.Text(), err)
			continue
		}
		if (inputMap.Success && !inputMap.Repeat) && (!deduplicate || !dedup.IsDuplicate(inputMap.Saddr)) {
			log.Debugf("Forwarding line")
			var out []byte
			if mode == "json" {
				out, err = CreateJsonLine(&options, &inputMap)
			} else if mode == "saddr" {
				out = []byte(inputMap.Saddr)
			} else if mode == "csv" {
				out, err = CreateCsvLine(&options, &inputMap)
			}
			if err != nil {
				log.Warnf("Error creating output format (%s): %s", err)
				continue
			}

			_, err = in.Write(out)
			if err != nil {
				log.Warnf("Error writing filtered json to stdin of next application: %s", err)
				continue
			}
			in.Write([]byte{'\n'})
		}
	}

	if err := scanner.Err(); err != nil {
		log.Warnf("Error while scanning zmap input: %s", err)
	}

	dedup.Close()
}
