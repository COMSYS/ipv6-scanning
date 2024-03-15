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

type SixForest struct {
	source        string
	folder        string
	name          string
	resourcepools []*helpers.ResourcePool
}

func (sforest *SixForest) Run(in chan *iplist.IPEntry, out chan *iplist.IPEntry, num int) error {

	log.Debugf("%s: Started", sforest.name)

	// Initialize Convert Process

	var convert_ctx context.Context
	var convert_cancel context.CancelFunc
	convert_ctx, convert_cancel = context.WithCancel(context.TODO())
	defer convert_cancel()

	convert_parameters := []string{fmt.Sprintf("%s/convert.py", sforest.source), "-i", "/dev/stdin", "-o", sforest.folder}
	convert_process := exec.CommandContext(convert_ctx, "python3", convert_parameters...)

	convert_pipe_r, convert_pipe_w, err := os.Pipe()
	if err != nil {
		log.Error(err)
		return err
	}
	convert_process.Stdin = convert_pipe_r

	convert_process_stderr, err := convert_process.StderrPipe()
	if err != nil {
		log.Error(err)
		return err
	}
	defer convert_process_stderr.Close()

	// Initialize Address Generation

	var address_ctx context.Context
	var address_cancel context.CancelFunc
	address_ctx, address_cancel = context.WithCancel(context.TODO())
	defer address_cancel()

	address_parameters := []string{fmt.Sprintf("%s/main.py", sforest.source), "-i", fmt.Sprintf("%sseeds.npy", sforest.folder), "-o", "/dev/fd/3"}
	address_generation := exec.CommandContext(address_ctx, "python3", address_parameters...)

	address_generation_stdout, err := address_generation.StdoutPipe()
	if err != nil {
		log.Error(err)
		return err
	}
	defer address_generation_stdout.Close()

	address_generation_stderr, err := address_generation.StderrPipe()
	if err != nil {
		log.Error(err)
		return err
	}
	defer address_generation_stderr.Close()

	output_r, output_w, err := os.Pipe()
	if err != nil {
		log.Error(err)
		return err
	}
	address_generation.ExtraFiles = []*os.File{output_w}

	log.Debugf("%s: Initialized", sforest.name)

	// Run convert process

	convert_process_wg := &sync.WaitGroup{}
	convert_process_wg.Add(1)
	go func() {
		defer convert_process_wg.Done()
		WriteIPChanToWriter(convert_pipe_w, in, false)
		convert_pipe_w.Close()
	}()

	convert_process_wg.Add(1)
	go func() {
		defer convert_process_wg.Done()
		LogPipe(sforest.name+"_dp", convert_process_stderr, log.Warn)
	}()

	err = convert_process.Start()
	if err != nil {
		log.Error(err)
		return err

	}
	convert_process_wg.Wait()

	err = convert_process.Wait()
	if err != nil {
		log.Error(err)
		return err
	}

	log.Debugf("%s: Convert Process finished", sforest.name)

	// Run address generation

	address_generation_wg := &sync.WaitGroup{}
	address_generation_extra := &sync.WaitGroup{}

	address_generation_extra.Add(1)
	go func() {
		defer address_generation_extra.Done()
		GetIPAddressesFromRegions(sforest.name, out, output_r, sforest.name, num)
	}()

	address_generation_wg.Add(1)
	go func() {
		defer address_generation_wg.Done()
		LogPipe(sforest.name+"_ag", address_generation_stdout, log.Debug)
	}()

	address_generation_wg.Add(1)
	go func() {
		defer address_generation_wg.Done()
		LogPipe(sforest.name+"_ag", address_generation_stderr, log.Warn)
	}()

	err = address_generation.Start()
	if err != nil {
		log.Error(err)
		return err
	}
	output_w.Close()

	address_generation_wg.Wait()

	err = address_generation.Wait()
	if err != nil {
		log.Error(err)
		return err
	}

	output_r.Close()

	address_generation_extra.Wait()

	log.Debugf("%s: Finished", sforest.name)

	return nil
}

func (sforest *SixForest) GetName() string {
	return sforest.name
}

func (sforest *SixForest) GetFolder() string {
	return sforest.folder
}

func (sforest *SixForest) ColonsRequired() bool {
	return true
}

func NewSixForest(source string, folder string, name string, resourcepools []*helpers.ResourcePool) *SixForest {
	os.MkdirAll(folder, os.ModePerm)

	tmp_folder := folder
	if tmp_folder[len(tmp_folder)-1] != '/' {
		tmp_folder = tmp_folder + "/"
	}

	return &SixForest{
		source:        source,
		folder:        tmp_folder,
		name:          name,
		resourcepools: resourcepools,
	}
}
