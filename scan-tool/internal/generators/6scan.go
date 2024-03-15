package generators

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/COMSYS/ipv6-scanning/scan-tool/pkg/helper"
	log "github.com/sirupsen/logrus"
)

type SixScan struct {
	name string

	probetype    string
	udpprobefile string

	port     int
	strategy string
	budget   int
	prescan  bool

	rate  int
	netif string

	sourcelist string
	resultlist string
}

// 6Scan implements various other active IPv6 address generation approaches
func NewSixScan(name string, scantype string, udpprobefile string, port int, budget int, rate int, netif string, sourcelist string, resultlist string) *SixScan {
	result := &SixScan{name: name, probetype: scantype, udpprobefile: udpprobefile, port: port, budget: budget, rate: rate, netif: netif, sourcelist: sourcelist, resultlist: resultlist}

	params := strings.Split(name, ":")
	i_param := 1

	if len(params)-1 < i_param {
		log.Warnf("Error parsing 6scan parameters from filename. Continuing.")
		return nil
	}
	result.strategy = params[i_param]
	i_param++

	if len(params)-1 < i_param {
		log.Warnf("Error parsing 6scan parameters from filename. Continuing.")
		return nil
	}
	result.prescan = (params[i_param] == "prescan")
	i_param++

	return result
}

// Get newest file in dir that has a prefix from prefixes
func findLastFileStartsWith(dir string, prefixes []string) (string, error) {
	var lastFile os.DirEntry
	files, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}

	for _, file := range files {
		if !file.Type().IsRegular() {
			continue
		}
		for _, p := range prefixes {
			if strings.HasPrefix(file.Name(), p) {
				if lastFile == nil {
					lastFile = file
				} else {
					lastFileInfo, _ := lastFile.Info()
					fileInfo, _ := file.Info()
					if lastFileInfo.ModTime().Before(fileInfo.ModTime()) {
						lastFile = file
					}
				}
			}
		}
	}

	if lastFile == nil {
		err = os.ErrNotExist
		return "", err
	}
	return path.Join(dir, lastFile.Name()), err
}

// 6scan requires more than one run of the application to complete. This function cares for a single run.
func (st *SixScan) runStep(name string, params []string, workingDir string) error {
	var run *exec.Cmd
	var err error

	wg := new(sync.WaitGroup)

	run = exec.Command("6scan", params...)
	run.Dir = workingDir

	run_stdout, err := run.StdoutPipe()
	if err != nil {
		log.Error(err)
		return err
	}
	defer run_stdout.Close()

	run_stderr, err := run.StderrPipe()
	if err != nil {
		log.Error(err)
		return err
	}
	defer run_stderr.Close()

	wg.Add(1)
	go func() {
		defer wg.Done()
		helper.LogPipe(workingDir, run_stdout, log.Debug)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		helper.LogPipe(workingDir, run_stderr, log.Warn)
	}()

	log.Debugf("Starting 6scan %s (%s) in %s", name, params, workingDir)
	err = run.Start()
	if err != nil {
		log.Warnf("Error executing 6scan %s in %s: %s", name, workingDir, err)
		return err
	}
	run.Wait()
	wg.Wait()

	log.Debugf("6scan %s (%s) in %s done", name, params, workingDir)

	return nil
}

// This function cares for a complete 6scan run, i.e., all calls of the application.
func (st *SixScan) Run() error {
	var err error
	tmp_folder, err := os.MkdirTemp(path.Dir(st.resultlist), fmt.Sprintf("%s-*", st.name))
	if err != nil {
		log.Warnf("Could not create new temp folder in %s: %s", st.resultlist, err)
		return err
	}

	log.Debugf("Instantiating 6scan scanner in temp folder %s", tmp_folder)

	var params []string
	basic_params := []string{"-I", st.netif, "-b", strconv.Itoa(st.budget), "-r", strconv.Itoa(st.rate)}

	if strings.Contains(st.probetype, "UDPv6") {
		basic_params = append(basic_params, []string{"-t", "UDP6_FILE", "-k", fmt.Sprintf("/measurement-configuration/probe_files/%s", st.udpprobefile)}...)
	} else if strings.Contains(st.probetype, "TCPv6") {
		basic_params = append(basic_params, []string{"-t", "TCP6_ACK"}...)
	} else if st.port != 0 && !strings.Contains(st.probetype, "ICMP") {
		basic_params = append(basic_params, []string{"-p", strconv.Itoa(st.port)}...)
	} else {
		log.Warnf("Unknown probetype: %s", st.probetype)
		return nil
	}

	if st.prescan {
		basic_params = append(basic_params, []string{"-P"}...)
	}

	var country string
	if strings.HasPrefix(st.strategy, "Heuristic") {
		country = st.strategy[len(st.strategy)-2:]

		// Download alias
		params = []string{"-D", "alias"}
		st.runStep("alias download", params, tmp_folder)

		// Download country info
		params = []string{"-D", fmt.Sprintf("country_%s", country)}
		st.runStep("country download", params, tmp_folder)
	}

	if strings.HasPrefix(st.strategy, "Heuristic") {
		params = append([]string{"-A", fmt.Sprintf("country_%s", country)}, basic_params...)
		st.runStep("heuristic scan", params, tmp_folder)
	} else {
		params = append([]string{"-s", st.strategy, "-F", st.sourcelist}, basic_params...)
		st.runStep("scan", params, tmp_folder)
	}

	output, err := findLastFileStartsWith(path.Join(tmp_folder, "output"), []string{"raw", "hitlist"})
	if err != nil {
		log.Errorf("Unable to find 6scan output: %s", err)
		return err
	}

	err = os.Rename(output, st.resultlist)
	if err != nil {
		log.Errorf("Unable to copy 6scan output: %s", err)
		return err
	}
	return nil
}
