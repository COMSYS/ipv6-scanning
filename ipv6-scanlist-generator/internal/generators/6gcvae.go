package generators

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"sync"
	"time"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/helpers"
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"
	log "github.com/sirupsen/logrus"
)

type SixGcVae struct {
	source        string
	folder        string
	name          string
	resourcepools []*helpers.ResourcePool
	timeout       time.Duration

	options *SixGcVaeOptions
}

type SixGcVaeOptions struct {
	Classifier string
}

func (sgcvae *SixGcVae) Run(in chan *iplist.IPEntry, out chan *iplist.IPEntry, num int) error {
	log.Debugf("%s: Waiting for available GPU", sgcvae.name)

	// GPU
	ids := make(map[string]interface{})
	for _, rp := range sgcvae.resourcepools {
		ids[rp.GetName()] = rp.Aquire()
		defer rp.Release(ids[rp.GetName()])
	}

	// if there is no gpu resource pool, use non-existent GPU id -1, so tensorflow will run on the CPU
	var gpu interface{}
	if val, ok := ids["gpu"]; ok {
		gpu = val
	} else {
		gpu = "-1"
	}

	log.Debugf("%s: Started", sgcvae.name)

	// Initialize Data Process

	var data_ctx context.Context
	var data_cancel context.CancelFunc
	data_ctx, data_cancel = context.WithCancel(context.TODO())
	defer data_cancel()

	data_parameters := []string{fmt.Sprintf("%s/data_process.py", sgcvae.source), "-i", "/dev/stdin", "-d", path.Join(sgcvae.folder, "data")}
	if sgcvae.options.Classifier != "" {
		data_parameters = append(data_parameters, "-c")
		data_parameters = append(data_parameters, sgcvae.options.Classifier)

		data_parameters = append(data_parameters, "-t")
		data_parameters = append(data_parameters, sgcvae.folder)

		if sgcvae.options.Classifier == "unsupervised_clustering" {
			data_parameters = append(data_parameters, "-k")
			data_parameters = append(data_parameters, fmt.Sprint(6))
		}
	}
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

	// Initialize Model Generation

	var model_ctx context.Context
	var model_cancel context.CancelFunc
	model_ctx, model_cancel = context.WithCancel(context.TODO())
	defer model_cancel()

	model_parameters := []string{fmt.Sprintf("%s/gcnn_vae.py", sgcvae.source), "-i", path.Join(sgcvae.folder, "data"), "-o", path.Join(sgcvae.folder, "model"), "-g", gpu.(string)}
	if sgcvae.options.Classifier != "" {
		model_parameters = append(model_parameters, "-c")
		model_parameters = append(model_parameters, sgcvae.options.Classifier)

		if sgcvae.options.Classifier == "unsupervised_clustering" {
			model_parameters = append(model_parameters, "-k")
			model_parameters = append(model_parameters, fmt.Sprint(6))
		}
	}
	model_generation := exec.CommandContext(model_ctx, "python3", model_parameters...)

	model_generation_stdout, err := model_generation.StdoutPipe()
	if err != nil {
		log.Error(err)
		return err
	}
	defer model_generation_stdout.Close()

	model_generation_stderr, err := model_generation.StderrPipe()
	if err != nil {
		log.Error(err)
		return err
	}
	defer model_generation_stderr.Close()

	// Initialize Address Generation

	var address_ctx context.Context
	var address_cancel context.CancelFunc
	address_ctx, address_cancel = context.WithCancel(context.TODO())
	defer address_cancel()

	address_parameters := []string{fmt.Sprintf("%s/generation.py", sgcvae.source), "-i", path.Join(sgcvae.folder, "model"), "-o", "/dev/fd/3", "-n", fmt.Sprintf("%d", num), "-g", gpu.(string)}
	if sgcvae.options.Classifier != "" {
		address_parameters = append(address_parameters, "-c")
		address_parameters = append(address_parameters, sgcvae.options.Classifier)

		if sgcvae.options.Classifier == "unsupervised_clustering" {
			address_parameters = append(address_parameters, "-k")
			address_parameters = append(address_parameters, fmt.Sprint(6))
		}
	}
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

	log.Debugf("%s: Initialized", sgcvae.name)

	// Run Data Process

	data_process_wg := &sync.WaitGroup{}
	data_process_wg.Add(1)
	go func() {
		defer data_process_wg.Done()
		WriteIPChanToWriter(data_process_pipe_w, in, true)
		data_process_pipe_w.Close()
	}()

	data_process_wg.Add(1)
	go func() {
		defer data_process_wg.Done()
		LogPipe(sgcvae.name+"_dp", data_process_stderr, log.Warn)
	}()

	data_process_wg.Add(1)
	go func() {
		defer data_process_wg.Done()
		LogPipe(sgcvae.name+"_dp", data_process_stdout, log.Debug)
	}()

	err = data_process.Start()
	if err != nil {
		log.Error(err)
		return err
	}

	data_process_wg.Wait()

	err = data_process.Wait()
	if err != nil {
		// hard coded exit code in data_process.py
		if err.Error() == "exit status 42" {
			log.Errorf("6GCVAE run %s did not generate any IP addresses due to empty classification of seed IP addresses", sgcvae.name)
			return nil
		}
		log.Error(err)
		return err
	}

	log.Debugf("%s: Data Process finished", sgcvae.name)

	// Run Model Generation

	model_generation_wg := &sync.WaitGroup{}
	model_generation_wg.Add(1)
	go func() {
		defer model_generation_wg.Done()
		LogPipe(sgcvae.name+"_mg", model_generation_stderr, log.Warn)
	}()

	model_generation_wg.Add(1)
	go func() {
		defer model_generation_wg.Done()
		LogPipe(sgcvae.name+"_mg", model_generation_stdout, log.Debug)
	}()

	err = model_generation.Start()
	if err != nil {
		log.Error(err)
		return err
	}

	model_generation_wg.Wait()

	err = model_generation.Wait()
	if err != nil {
		log.Error(err)
		return err
	}

	log.Debugf("%s: Model Generation Process finished", sgcvae.name)

	// Run Address Generation

	address_generation_wg := &sync.WaitGroup{}
	address_generation_wg_extra := &sync.WaitGroup{}

	address_generation_wg_extra.Add(1)
	go func() {
		defer address_generation_wg_extra.Done()
		SendHexOutputToIPChan(sgcvae.name, out, output_r)
	}()

	address_generation_wg.Add(1)
	go func() {
		defer address_generation_wg.Done()
		LogPipe(sgcvae.name+"_ag", address_generation_stderr, log.Warn)
	}()

	address_generation_wg.Add(1)
	go func() {
		defer address_generation_wg.Done()
		LogPipe(sgcvae.name+"_ag", address_generation_stdout, log.Debug)
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

	log.Debugf("%s: Finished", sgcvae.name)

	return nil
}

func (sgcvae *SixGcVae) GetName() string {
	return sgcvae.name
}

func (sgcvae *SixGcVae) GetFolder() string {
	return sgcvae.folder
}

func (sgcvae *SixGcVae) ColonsRequired() bool {
	return true
}

func NewSixGcVae(source string, folder string, name string, resourcepools []*helpers.ResourcePool, options interface{}) *SixGcVae {
	os.MkdirAll(folder, os.ModePerm)

	tmp_folder := folder
	if tmp_folder[len(tmp_folder)-1] != '/' {
		tmp_folder = tmp_folder + "/"
	}

	return &SixGcVae{
		source:        source,
		folder:        tmp_folder,
		name:          name,
		resourcepools: resourcepools,
		options:       options.(*SixGcVaeOptions),
	}
}
