package filter

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"
	"github.com/COMSYS/ipv6-scanning/scan-tool/pkg/helper"
)

type Filter struct {
	attributes *helper.ScanAttributes

	generator string
	ipkey     string

	all       bool
	selection map[int]bool

	colons bool

	seed_path   string
	result_path string

	port   int
	budget int
	ctx    context.Context
}

func NewFilter(ctx context.Context, attributes *helper.ScanAttributes, generator string, ipkey string, inputnum int, expectednum int, colons bool, seed_path string, result_path string, port int, budget int) *Filter {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	result := &Filter{ctx: ctx, attributes: attributes, generator: generator, ipkey: ipkey, selection: make(map[int]bool), colons: colons, seed_path: seed_path, result_path: result_path, port: port, budget: budget}

	if inputnum >= expectednum || inputnum == 0 {
		result.all = true
	} else {
		rand_num := 0
		for rand_num < inputnum {
			l := r.Intn(expectednum)
			if !result.selection[l] {
				result.selection[l] = true
				rand_num++
			}
		}
	}

	return result
}

func (f *Filter) Run(ipin chan *iplist.IPEntry, ipout chan string) error {
	var err error

	err = os.MkdirAll(f.seed_path, 0700)
	if err != nil {
		log.Warnf("Error creating seed path: %s", err)
		return err
	}

	err = os.MkdirAll(f.result_path, 0700)
	if err != nil {
		log.Warnf("Error creating result path: %s", err)
		return err
	}

	log.Debugf("Running filter for generator %s (ScanType: %s, UDP Packet: %s).", f.generator, f.attributes.ScanType, f.attributes.UDPProbeFile)
	file, err := os.CreateTemp(f.seed_path, fmt.Sprintf("%s-%s-%s-%d-%d-%s.*.iplist.tmp", f.generator, f.attributes.ScanType, f.attributes.UDPProbeFile, f.port, f.budget, f.ipkey))
	if err != nil {
		log.Warn(err)
		return err
	}

	log.Debugf("Created temporary file %s.", path.Join(f.seed_path, file.Name()))

	filePathTmp := file.Name()

	filePathSeed := strings.TrimSuffix(filePathTmp, ".tmp")
	fileNameSeed := path.Base(filePathSeed)

	filePathResult := filepath.Join(f.result_path, fileNameSeed)

	cnt := 0
	for ip := range ipin {
		if ip.KeysContain(f.ipkey) {
			if f.all || f.selection[cnt] {
				file.WriteString(fmt.Sprintf("%s\n", ip.GetIPasString(f.colons)))
			}
			cnt++
		}
	}
	file.Close()

	log.Debugf("Temporary file %s written.", filePathTmp)

	c_resultfilepath := make(chan string, 1)
	helper.CreateFsNotifier(f.ctx, c_resultfilepath, f.result_path, fileNameSeed, 1, false)

	log.Debugf("Rename temporary file %s to %s.", filePathTmp, filePathSeed)
	// This should start our subscanner
	err = os.Rename(filePathTmp, filePathSeed)
	if err != nil {
		log.Warn(err)
		return err
	}

	// Wait for the result file to be created
	resultFilePathNotifier, ok := <-c_resultfilepath
	if !ok {
		log.Warnf("Channel was closed before expected file (%s) was created", filePathResult)
		return nil
	}
	if resultFilePathNotifier != filePathResult {
		log.Warnf("Got notified for different path (%s) than expected (%s)", resultFilePathNotifier, filePathResult)
	}
	log.Debugf("Got result file %s.", filePathResult)

	resultFile, err := os.Open(filePathResult)
	if err != nil {
		log.Warn(err)
		return err
	}
	defer resultFile.Close()

	scanner := bufio.NewScanner(resultFile)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") {
			_, err := iplist.NewIPEntry(line)
			if err != nil {
				log.Warnf("Got invalid IP address: %s (%s)", line, err)
				continue
			}
			ipout <- line
		}
	}

	log.Debugf("Read IPs from result file %s.", filePathResult)

	if err := scanner.Err(); err != nil {
		log.Warn(err)
		return err
	}

	return nil
}
