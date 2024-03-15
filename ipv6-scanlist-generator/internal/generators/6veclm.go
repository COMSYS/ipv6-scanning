package generators

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"sync"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/helpers"
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"
	log "github.com/sirupsen/logrus"
)

type SixVecLm struct {
	source        string
	folder        string
	name          string
	resourcepools []*helpers.ResourcePool
}

func (sveclm *SixVecLm) Run(in chan *iplist.IPEntry, out chan *iplist.IPEntry, num int) error {

	log.Debugf("%s: Started", sveclm.name)

	// Initialize Data Process

	var data_ctx context.Context
	var data_cancel context.CancelFunc
	data_ctx, data_cancel = context.WithCancel(context.TODO())
	defer data_cancel()

	data_parameters := []string{fmt.Sprintf("%s/data_processing.py", sveclm.source), "-i", "/dev/stdin", "-w", path.Join(sveclm.folder, "word"), "-c", path.Join(sveclm.folder, "colon")}
	data_process := exec.CommandContext(data_ctx, "python3", data_parameters...)

	data_process_pipe_r, data_process_pipe_w, err := os.Pipe()
	if err != nil {
		log.Error(err)
		return err
	}
	data_process.Stdin = data_process_pipe_r

	data_process_stdout, err := data_process.StdoutPipe()
	if err != nil {
		log.Error(err)
		return err
	}
	defer data_process_stdout.Close()

	data_process_stderr, err := data_process.StderrPipe()
	if err != nil {
		log.Error(err)
		return err
	}
	defer data_process_stderr.Close()

	// Initialize Vectorization

	var vec_ctx context.Context
	var vec_cancel context.CancelFunc
	vec_ctx, vec_cancel = context.WithCancel(context.TODO())
	defer vec_cancel()

	vec_parameters := []string{fmt.Sprintf("%s/ipv62vec.py", sveclm.source), "-w", path.Join(sveclm.folder, "word"), "-v", path.Join(sveclm.folder, "vec")}
	vectorization := exec.CommandContext(vec_ctx, "python3", vec_parameters...)

	vectorization_stdout, err := vectorization.StdoutPipe()
	if err != nil {
		log.Error(err)
		return err
	}
	defer vectorization_stdout.Close()

	vectorization_stderr, err := vectorization.StderrPipe()
	if err != nil {
		log.Error(err)
		return err
	}
	defer vectorization_stderr.Close()

	// Initialize Transformation (address generation)

	var trans_ctx context.Context
	var trans_cancel context.CancelFunc
	trans_ctx, trans_cancel = context.WithCancel(context.TODO())
	defer trans_cancel()

	trans_parameters := []string{fmt.Sprintf("%s/ipv6_transformer.py", sveclm.source), "-w", path.Join(sveclm.folder, "word"), "-v", path.Join(sveclm.folder, "vec"), "-t", path.Join(sveclm.folder, "torch"), "-o", "/dev/fd/3"}
	transform := exec.CommandContext(trans_ctx, "python3", trans_parameters...)

	transform_stdout, err := transform.StdoutPipe()
	if err != nil {
		log.Error(err)
		return err
	}
	defer transform_stdout.Close()

	transform_stderr, err := transform.StderrPipe()
	if err != nil {
		log.Error(err)
		return err
	}
	defer transform_stderr.Close()

	output_r, output_w, err := os.Pipe()
	if err != nil {
		log.Error(err)
		return err
	}
	transform.ExtraFiles = []*os.File{output_w}

	log.Debugf("%s: Initialized", sveclm.name)

	// Run Data Process

	data_process_wg := &sync.WaitGroup{}
	data_process_wg.Add(1)
	go func() {
		defer data_process_wg.Done()
		LogPipe(sveclm.name+"_dp", data_process_stderr, log.Warn)
	}()

	data_process_wg.Add(1)
	go func() {
		defer data_process_wg.Done()
		LogPipe(sveclm.name+"_dp", data_process_stdout, log.Debug)
	}()

	data_process_wg.Add(1)
	go func() {
		defer data_process_wg.Done()
		WriteIPChanToWriter(data_process_pipe_w, in, true)
		data_process_pipe_w.Close()
	}()

	err = data_process.Start()
	if err != nil {
		log.Error(err)
		return err
	}

	data_process_wg.Wait()

	err = data_process.Wait()
	if err != nil {
		log.Error(err)
		return err
	}

	log.Debugf("%s: Data Process finished", sveclm.name)

	// Run Vectorization

	vectorization_wg := &sync.WaitGroup{}
	vectorization_wg.Add(1)
	go func() {
		defer vectorization_wg.Done()
		LogPipe(sveclm.name+"_v", vectorization_stderr, log.Warn)
	}()

	vectorization_wg.Add(1)
	go func() {
		defer vectorization_wg.Done()
		LogPipe(sveclm.name+"_v", vectorization_stdout, log.Debug)
	}()

	err = vectorization.Start()
	if err != nil {
		log.Error(err)
		return err
	}

	vectorization_wg.Wait()

	err = vectorization.Wait()
	if err != nil {
		log.Error(err)
		return err
	}

	log.Debugf("%s: Vectorization Process finished", sveclm.name)

	// Run Transform (address generation)

	transform_wg := &sync.WaitGroup{}
	transform_wg_extra := &sync.WaitGroup{}

	transform_wg_extra.Add(1)
	go func() {
		defer transform_wg_extra.Done()
		SendHexOutputToIPChan(sveclm.name, out, output_r)
	}()

	transform_wg.Add(1)
	go func() {
		defer transform_wg.Done()
		LogPipe(sveclm.name+"_t", transform_stderr, log.Warn)
	}()

	transform_wg.Add(1)
	go func() {
		defer transform_wg.Done()
		LogPipe(sveclm.name+"_t", transform_stdout, log.Debug)
	}()

	err = transform.Start()
	if err != nil {
		log.Error(err)
		return err
	}

	output_w.Close()

	transform_wg.Wait()

	err = transform.Wait()
	if err != nil {
		log.Error(err)
		return err
	}

	output_r.Close()
	transform_wg_extra.Wait()

	log.Debugf("%s: Finished", sveclm.name)

	return nil
}

func (sveclm *SixVecLm) GetName() string {
	return sveclm.name
}

func (sveclm *SixVecLm) GetFolder() string {
	return sveclm.folder
}

func (sveclm *SixVecLm) ColonsRequired() bool {
	return true
}

func NewSixVecLm(source string, folder string, name string, resourcepools []*helpers.ResourcePool) *SixVecLm {
	os.MkdirAll(folder, os.ModePerm)

	tmp_folder := folder
	if tmp_folder[len(tmp_folder)-1] != '/' {
		tmp_folder = tmp_folder + "/"
	}

	return &SixVecLm{
		source:        source,
		folder:        tmp_folder,
		name:          name,
		resourcepools: resourcepools,
	}
}
