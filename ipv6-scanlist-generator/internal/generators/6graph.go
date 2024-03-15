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

type SixGraph struct {
	source        string
	folder        string
	name          string
	resourcepools []*helpers.ResourcePool
}

func (sgraph *SixGraph) Run(in chan *iplist.IPEntry, out chan *iplist.IPEntry, num int) error {

	log.Debugf("%s: Started", sgraph.name)

	// Initialize Convert Process

	var convert_ctx context.Context
	var convert_cancel context.CancelFunc
	convert_ctx, convert_cancel = context.WithCancel(context.TODO())
	defer convert_cancel()

	convert_parameters := []string{fmt.Sprintf("%s/convert.py", sgraph.source), "-i", "/dev/stdin", "-o", sgraph.folder}
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

	address_parameters := []string{fmt.Sprintf("%s/main.py", sgraph.source), "-i", fmt.Sprintf("%sseeds.npy", sgraph.folder), "-o", "/dev/fd/3"}
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

	log.Debugf("%s: Initialized", sgraph.name)

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
		LogPipe(sgraph.name+"_dp", convert_process_stderr, log.Warn)
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

	log.Debugf("%s: Convert Process finished", sgraph.name)

	// Run address generation

	address_generation_wg := &sync.WaitGroup{}
	address_generation_wg_extra := &sync.WaitGroup{}

	address_generation_wg_extra.Add(1)
	go func() {
		defer address_generation_wg_extra.Done()
		GetIPAddressesFromRegions(sgraph.name, out, output_r, sgraph.name, num)
	}()

	address_generation_wg.Add(1)
	go func() {
		defer address_generation_wg.Done()
		LogPipe(sgraph.name+"_ag", address_generation_stdout, log.Debug)
	}()

	address_generation_wg.Add(1)
	go func() {
		defer address_generation_wg.Done()
		LogPipe(sgraph.name+"_ag", address_generation_stderr, log.Warn)
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

	address_generation_wg_extra.Wait()

	log.Debugf("%s: Finished", sgraph.name)

	return nil
}

func (sgraph *SixGraph) GetName() string {
	return sgraph.name
}

func (sgraph *SixGraph) GetFolder() string {
	return sgraph.folder
}

func (sgraph *SixGraph) ColonsRequired() bool {
	return true
}

func NewSixGraph(source string, folder string, name string, resourcepools []*helpers.ResourcePool) *SixGraph {
	os.MkdirAll(folder, os.ModePerm)

	tmp_folder := folder
	if tmp_folder[len(tmp_folder)-1] != '/' {
		tmp_folder = tmp_folder + "/"
	}

	return &SixGraph{
		source:        source,
		folder:        tmp_folder,
		name:          name,
		resourcepools: resourcepools,
	}
}
