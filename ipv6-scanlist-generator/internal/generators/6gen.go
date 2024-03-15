package generators

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/helpers"
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"
	log "github.com/sirupsen/logrus"
)

type SixGen struct {
	source        string
	folder        string
	name          string
	resourcepools []*helpers.ResourcePool
}

func (sgen *SixGen) Run(in chan *iplist.IPEntry, out chan *iplist.IPEntry, num int) error {

	log.Debugf("%s: Started", sgen.name)

	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(context.TODO())
	defer cancel()

	// budget seeds_file blacklist_file range_type output_type output_file_ranges output_file_addresses
	runner := exec.CommandContext(ctx, fmt.Sprintf("%s/tga", sgen.source), fmt.Sprintf("%d", num), "/dev/fd/3", "/dev/fd/4", "loose", "addresses", fmt.Sprintf("%s/ranges", sgen.folder), "/dev/fd/5")
	runner_stdout, err := runner.StdoutPipe()
	if err != nil {
		log.Error(err)
		return err
	}
	defer runner_stdout.Close()
	runner_stderr, err := runner.StderrPipe()
	if err != nil {
		log.Error(err)
		return err
	}
	defer runner_stderr.Close()

	input_r, input_w, err := os.Pipe()
	if err != nil {
		log.Error(err)
		return err
	}

	blacklist_r, blacklist_w, err := os.Pipe()
	if err != nil {
		log.Error(err)
		return err
	}

	output_r, output_w, err := os.Pipe()
	if err != nil {
		log.Error(err)
		return err
	}
	runner.ExtraFiles = []*os.File{input_r, blacklist_r, output_w}

	log.Debugf("%s: Initialized", sgen.name)

	wg := &sync.WaitGroup{}
	wg_extra := &sync.WaitGroup{}

	wg_extra.Add(1)
	go func() {
		defer wg_extra.Done()
		SendHexOutputToIPChan(sgen.name, out, output_r)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		LogPipe(sgen.name, runner_stdout, log.Debug)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		LogPipe(sgen.name, runner_stderr, log.Warn)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		WriteIPChanToWriter(input_w, in, true)
	}()

	err = runner.Start()
	if err != nil {
		log.Error(err)
		return err
	}

	output_w.Close()

	//blacklist_w.WriteString("\n")
	blacklist_w.Close()

	wg.Wait()

	err = runner.Wait()
	if err != nil {
		log.Error(err)
		return err
	}

	output_r.Close()

	wg_extra.Wait()

	log.Debugf("%s: Finished", sgen.name)

	return nil
}

func (sgen *SixGen) GetName() string {
	return sgen.name
}

func (sgen *SixGen) GetFolder() string {
	return sgen.folder
}

func NewSixGen(source string, folder string, name string, resourcepools []*helpers.ResourcePool) *SixGen {
	os.MkdirAll(folder, os.ModePerm)

	return &SixGen{
		source:        source,
		folder:        folder,
		resourcepools: resourcepools,

		name: name,
	}
}
