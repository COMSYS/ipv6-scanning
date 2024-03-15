package generators

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/helpers"
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"
	log "github.com/sirupsen/logrus"
)

type EntropyIp struct {
	source        string
	folder        string
	name          string
	resourcepools []*helpers.ResourcePool
}

func (eip *EntropyIp) GetName() string {
	return eip.name
}

func (eip *EntropyIp) GetFolder() string {
	return eip.folder
}

func (eip *EntropyIp) ColonsRequired() bool {
	return false
}

func (eip *EntropyIp) Run(in chan *iplist.IPEntry, out chan *iplist.IPEntry, num int) error {

	log.Debugf("%s: Started", eip.name)

	var ctx context.Context
	var cancel context.CancelFunc

	ctx, cancel = context.WithCancel(context.TODO())
	defer cancel()

	////////////////////////// A1 //////////////////////////
	a1_path := fmt.Sprintf("%s/segments", eip.folder)
	a1_fd, err := os.Create(a1_path)
	if err != nil {
		log.Error(err)
		return err
	}
	a1 := exec.CommandContext(ctx, "python2", fmt.Sprintf("%s/a1-segments.py", eip.source), "/dev/stdin")
	a1_pipe_r, a1_pipe_w, err := os.Pipe()
	if err != nil {
		log.Error(err)
		return err
	}
	a1.Stdin = a1_pipe_r
	a1.Stdout = a1_fd
	a1_stderr, err := a1.StderrPipe()
	if err != nil {
		log.Error(err)
		return err
	}

	////////////////////////// A2 //////////////////////////
	a2_path := fmt.Sprintf("%s/analysis", eip.folder)
	a2_fd, err := os.Create(a2_path)
	if err != nil {
		log.Error(err)
		return err
	}
	a2 := exec.CommandContext(ctx, "python2", fmt.Sprintf("%s/a2-mining.py", eip.source), "/dev/stdin", a1_path)
	a2_pipe_r, a2_pipe_w, err := os.Pipe()
	if err != nil {
		log.Error(err)
		return err
	}
	a2.Stdin = a2_pipe_r
	a2.Stdout = a2_fd
	a2_stderr, err := a2.StderrPipe()
	if err != nil {
		log.Error(err)
		return err
	}

	////////////////////////// A3 + A4 //////////////////////////
	a3 := exec.CommandContext(ctx, "python2", fmt.Sprintf("%s/a3-encode.py", eip.source), "/dev/stdin", a2_path)
	a3_pipe_r, a3_pipe_w, err := os.Pipe()
	if err != nil {
		log.Error(err)
		return err
	}
	a3.Stdin = a3_pipe_r
	a3_stdout, err := a3.StdoutPipe()
	if err != nil {
		log.Error(err)
		return err
	}
	a3_stderr, err := a3.StderrPipe()
	if err != nil {
		log.Error(err)
		return err
	}

	a4_path := fmt.Sprintf("%s/bnfinput", eip.folder)
	a4_fd, err := os.Create(a4_path)
	if err != nil {
		log.Error(err)
		return err
	}

	// bayes-prepare
	a4 := exec.CommandContext(ctx, "python2", fmt.Sprintf("%s/bin/rewrite-bnf.py", eip.source))
	a4.Stdin = a3_stdout
	a4.Stdout = a4_fd

	a4_stderr, err := a4.StderrPipe()
	if err != nil {
		log.Error(err)
		return err
	}

	////////////////////////// A5 //////////////////////////
	a5_path := fmt.Sprintf("%s/cpd", eip.folder)

	// bnf -s BDE -v -k 8 -e "$1" -c /dev/stderr 3>&2 2>&1 1>&3
	a5 := exec.CommandContext(ctx, "bnf", "-s", "BDE", "-v", "-k", "8", "-e", a4_path, "-c", a5_path)
	a5_stdout, err := a5.StdoutPipe()
	if err != nil {
		log.Error(err)
		return err
	}
	a5_stderr, err := a5.StderrPipe()
	if err != nil {
		log.Error(err)
		return err
	}

	////////////////////////// C1 + C2 //////////////////////////
	c1 := exec.CommandContext(ctx, "python2", fmt.Sprintf("%s/c1-gen.py", eip.source), a5_path, "-n", fmt.Sprintf("%d", num))
	c1_stdout, err := c1.StdoutPipe()
	if err != nil {
		log.Error(err)
		return err
	}
	c1_stderr, err := c1.StderrPipe()
	if err != nil {
		log.Error(err)
		return err
	}

	c2 := exec.CommandContext(ctx, "python2", fmt.Sprintf("%s/c2-decode.py", eip.source), "/dev/stdin", a2_path)
	c2.Stdin = c1_stdout
	c2_stdout, err := c2.StdoutPipe()
	if err != nil {
		log.Error(err)
		return err
	}
	c2_stderr, err := c2.StderrPipe()
	if err != nil {
		log.Error(err)
		return err
	}

	ip_buf := new(bytes.Buffer)
	mw := io.MultiWriter(a1_pipe_w, ip_buf)
	go func() {
		WriteIPChanToWriter(mw, in, false)
		a1_pipe_w.Close()
	}()

	log.Debugf("%s: Initialized", eip.name)

	/// EXECUTE

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		LogPipe(eip.name, a1_stderr, log.Error)
	}()
	err = a1.Start()
	if err != nil {
		log.Error(err)
		return err
	}

	wg.Wait()

	err = a1.Wait()
	if err != nil {
		log.Error(err)
		return err
	}
	a1_fd.Close()
	log.Debugf("%s: A1 finished", eip.name)

	wg.Add(1)
	go func() {
		defer wg.Done()
		LogPipe(eip.name, a2_stderr, log.Error)
	}()

	go func() {
		io.Copy(a2_pipe_w, bytes.NewReader(ip_buf.Bytes()))
		a2_pipe_w.Close()
	}()

	err = a2.Start()
	if err != nil {
		log.Error(err)
		return err
	}

	wg.Wait()

	err = a2.Wait()
	if err != nil {
		log.Error(err)
		return err
	}
	a2_fd.Close()
	log.Debugf("%s: A2 finished", eip.name)

	wg.Add(1)
	go func() {
		defer wg.Done()
		LogPipe(eip.name, a3_stderr, log.Error)
	}()

	go func() {
		io.Copy(a3_pipe_w, ip_buf)
		a3_pipe_w.Close()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		LogPipe(eip.name, a4_stderr, log.Error)
	}()

	err = a3.Start()
	if err != nil {
		log.Error(err)
		return err
	}

	err = a4.Start()
	if err != nil {
		log.Error(err)
		return err
	}

	wg.Wait()

	err = a4.Wait()
	if err != nil {
		log.Error(err)
		return err
	}
	a4_fd.Close()
	log.Debugf("%s: A4 finished", eip.name)

	err = a3.Wait()
	if err != nil {
		log.Error(err)
		return err
	}
	log.Debugf("%s: A3 finished", eip.name)

	wg.Add(1)
	go func() {
		defer wg.Done()
		LogPipe(eip.name, a5_stderr, log.Error)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		LogPipe(eip.name, a5_stdout, log.Debug)
	}()
	err = a5.Start()
	if err != nil {
		log.Error(err)
		return err
	}

	wg.Wait()

	err = a5.Wait()
	if err != nil {
		log.Error(err)
		return err
	}
	log.Debugf("%s: A5 finished", eip.name)

	wg.Add(1)
	go func() {
		defer wg.Done()
		LogPipe(eip.name, c1_stderr, log.Debug)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		SendHexOutputToIPChan(eip.name, out, c2_stdout)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		LogPipe(eip.name, c2_stderr, log.Debug)
	}()

	err = c1.Start()
	if err != nil {
		log.Error(err)
		return err
	}

	err = c2.Start()
	if err != nil {
		log.Error(err)
		return err
	}

	wg.Wait()

	err = c2.Wait()
	if err != nil {
		log.Error(err)
		return err
	}
	log.Debugf("%s: C2 finished", eip.name)

	err = c1.Wait()
	if err != nil {
		log.Error(err)
		return err
	}
	log.Debugf("%s: C1 finished", eip.name)

	log.Debugf("%s: Finished", eip.name)

	return nil
}

func NewEntropyIp(source string, folder string, name string, resourcepools []*helpers.ResourcePool) *EntropyIp {
	os.MkdirAll(folder, os.ModePerm)

	return &EntropyIp{
		source:        source,
		folder:        folder,
		name:          name,
		resourcepools: resourcepools,
	}
}
