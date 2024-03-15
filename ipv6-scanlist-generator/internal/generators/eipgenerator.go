package generators

import (
	"context"
	"fmt"
	"sync"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/helpers"
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"
	log "github.com/sirupsen/logrus"

	"os/exec"
)

type EipGenerator struct {
	source        string
	folder        string
	name          string
	resourcepools []*helpers.ResourcePool
}

func (eip *EipGenerator) Run(in chan *iplist.IPEntry, out chan *iplist.IPEntry, num int) error {

	log.Debugf("%s: Started", eip.name)

	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(context.TODO())
	defer cancel()

	convert := exec.CommandContext(ctx, "python2", fmt.Sprintf("%s/eip-convert.py", eip.source), fmt.Sprintf("%s/segments", eip.folder), fmt.Sprintf("%s/analysis", eip.folder), fmt.Sprintf("%s/cpd", eip.folder))
	convert_stdout, err := convert.StdoutPipe()
	if err != nil {
		log.Error(err)
		return err
	}

	convert_stderr, err := convert.StderrPipe()
	if err != nil {
		log.Error(err)
		return err
	}

	generate := exec.CommandContext(ctx, fmt.Sprintf("%s/eip-generator", eip.source), "-N", fmt.Sprintf("%d", num), "/dev/stdin")
	generate.Stdin = convert_stdout
	generate_stdout, err := generate.StdoutPipe()
	if err != nil {
		log.Error(err)
		return err
	}

	generate_stderr, err := generate.StderrPipe()
	if err != nil {
		log.Error(err)
		return err
	}

	log.Debugf("%s: Initialized", eip.name)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		SendHexOutputToIPChan(eip.name, out, generate_stdout)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		LogPipe(eip.name, generate_stderr, log.Debug)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		LogPipe(eip.name, convert_stderr, log.Debug)
	}()

	err = generate.Start()
	if err != nil {
		log.Error(err)
		return err
	}

	err = convert.Start()
	if err != nil {
		log.Error(err)
		return err
	}

	wg.Wait()

	err = generate.Wait()
	if err != nil {
		log.Error(err)
		return err
	}
	log.Debugf("%s: Generate finished", eip.name)

	err = convert.Wait()
	if err != nil {
		log.Error(err)
		return err
	}
	log.Debugf("%s: Convert finished", eip.name)

	log.Debugf("%s: Finished", eip.name)
	return nil
}

func (eip *EipGenerator) SetInputChan(none chan string) bool {
	return false
}

func (eip *EipGenerator) GetFolder() string {
	return eip.folder
}

func (eip *EipGenerator) GetName() string {
	return eip.name
}

func (eip *EipGenerator) ColonsRequired() bool {
	return false
}

func NewEipGenerator(source string, folder string, name string, resourcepools []*helpers.ResourcePool) *EipGenerator {
	return &EipGenerator{
		source:        source,
		folder:        folder,
		name:          name,
		resourcepools: resourcepools,
	}
}
