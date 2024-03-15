package generators

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"sync"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/helpers"
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"
	log "github.com/sirupsen/logrus"
)

type SixGan struct {
	source        string
	folder        string
	name          string
	resourcepools []*helpers.ResourcePool

	options *SixGanOptions
}

type SixGanOptions struct {
	Classifier   string
	Aliased_path string
}

func (sgan *SixGan) Run(in chan *iplist.IPEntry, out chan *iplist.IPEntry, num int) error {

	log.Debugf("%s: Waiting for available GPU", sgan.name)

	// GPU
	ids := make(map[string]interface{})
	for _, rp := range sgan.resourcepools {
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

	log.Debugf("%s: Started", sgan.name)

	ip_path := path.Join(sgan.folder, "addresses.tmp")
	log.Debugf("%s: Write IPs to disk (path: %s)", sgan.name, ip_path)
	f, err := os.Create(ip_path)
	if err != nil {
		log.Errorf("error creating ip file %s", ip_path)
	}
	WriteIPChanToWriter(f, in, true)
	f.Close()
	defer os.Remove(ip_path)

	parameters := []string{fmt.Sprintf("%s/train.py", sgan.source), "-i", ip_path, "-o", "/dev/fd/3", "-n", fmt.Sprintf("%d", num), "-t", sgan.folder, "-g", gpu.(string)}
	if sgan.options.Aliased_path != "" {
		parameters = append(parameters, "-a")
		parameters = append(parameters, sgan.options.Aliased_path)
	}

	if sgan.options.Classifier != "" {
		parameters = append(parameters, "-c")
		parameters = append(parameters, sgan.options.Classifier)

		if sgan.options.Classifier == "ec" {
			parameters = append(parameters, "-k")
			parameters = append(parameters, fmt.Sprint(6))
		}
	}

	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(context.TODO())
	defer cancel()

	runner := exec.CommandContext(ctx, "python3", parameters...)
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

	output_r, output_w, err := os.Pipe()
	if err != nil {
		log.Error(err)
		return err
	}
	runner.ExtraFiles = []*os.File{output_w}

	if sgan.options.Aliased_path != "" {
		aliased_r, aliased_w, err := os.Pipe()
		if err != nil {
			log.Error(err)
			return err
		}
		runner.ExtraFiles = append(runner.ExtraFiles, aliased_r)

		fd, err := os.Open(sgan.options.Aliased_path)
		if err != nil {
			log.Errorf("failed opening aliased file.")
		}
		defer fd.Close()

		go func() {
			io.Copy(fd, aliased_w)
			aliased_w.Close()
		}()
	}

	log.Debugf("%s: Initialized", sgan.name)

	wg := &sync.WaitGroup{}
	wg_extra := &sync.WaitGroup{}

	wg_extra.Add(1)
	go func() {
		defer wg_extra.Done()
		SendHexOutputToIPChan(sgan.name, out, output_r)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		LogPipe(sgan.name, runner_stdout, log.Debug)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		LogPipe(sgan.name, runner_stderr, log.Warn)
	}()

	err = runner.Start()
	if err != nil {
		log.Error(err)
		return err
	}
	output_w.Close()

	wg.Wait()

	err = runner.Wait()
	if err != nil {
		// hard coded exit code in train.py
		if err.Error() == "exit status 42" {
			log.Errorf("6GAN run %s did not generate any IP addresses due to empty classification of seed IP addresses", sgan.name)
			return nil
		}
		log.Error(err)
		return err
	}

	output_r.Close()

	wg_extra.Wait()

	log.Debugf("%s: Finished", sgan.name)

	return nil
}

func (sgan *SixGan) GetName() string {
	return sgan.name
}

func (sgan *SixGan) GetFolder() string {
	return sgan.folder
}

func (sgan *SixGan) ColonsRequired() bool {
	return true
}

func NewSixGan(source string, folder string, name string, resourcepools []*helpers.ResourcePool, options interface{}) *SixGan {
	os.MkdirAll(folder, os.ModePerm)

	tmp_folder := folder
	if tmp_folder[len(tmp_folder)-1] != '/' {
		tmp_folder = tmp_folder + "/"
	}

	return &SixGan{
		source:        source,
		folder:        tmp_folder,
		name:          name,
		resourcepools: resourcepools,
		options:       options.(*SixGanOptions),
	}
}
