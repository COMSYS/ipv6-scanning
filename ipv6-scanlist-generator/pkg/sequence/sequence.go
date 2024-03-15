package sequence

import (
	"context"
	"fmt"
	"path"
	"strings"
	"sync"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"
	"go.uber.org/atomic"

	log "github.com/sirupsen/logrus"
)

// StepInfo holds meta information for a step
type StepInfo struct {
	list   *iplist.IPList
	file   string
	folder string

	sourceHash string

	listLog []*iplist.IPList
	fileLog []string

	name string
}

func NewStepInfo(from *StepInfo, name string, list *iplist.IPList, file string, folder string) *StepInfo {
	result := &StepInfo{
		name:   name,
		list:   list,
		file:   file,
		folder: folder,
	}

	vars := 0
	if file != "" {
		result.fileLog = append(result.fileLog, file)
		result.sourceHash = strings.Split(path.Base(file), "_")[0]
		vars++
	}
	result.fileLog = append(result.fileLog, from.fileLog...)

	if list != nil {
		result.listLog = append(result.listLog, list)
		result.sourceHash = list.GetHash()
		vars++
	}
	result.listLog = append(result.listLog, from.listLog...)

	if folder != "" && vars == 0 {
		result.sourceHash = from.sourceHash
	}

	if vars > 1 {
		log.Fatalf("Invalid number of pick up points in StepInfo %s (only 1 allowed, got %d (list: %v, file: %s))", name, vars, list, file)
	}

	return result
}

// Get all IPs generated in this step.
func (s *StepInfo) GetAllIPs(ctx context.Context, c chan *iplist.IPEntry) {
	if s.list != nil {
		s.list.GetAllIPs(ctx, c)
		return
	} else if s.file != "" {
		iplist.NewIPListFromZSTPath(s.file).GetAllIPs(ctx, c)
		return
	} else if s.folder != "" {
		return
	}

	log.Errorf("Got stepinfo %s without any IPs, but were ask to get IPs.", s.name)
}

// A sequence is built from several steps.
// Each step has a list of next steps to start when this step is done.
type Step struct {
	name  string
	lists []*iplist.IPList
	files []string

	globaltype string
	options    interface{}

	infoIn    []chan *StepInfo
	infoOut   []chan *StepInfo
	nextSteps []*Step

	started *atomic.Bool
	done    *sync.WaitGroup
}

func newStep(name string, globaltype string, options interface{}) *Step {
	s := &Step{
		name:       name,
		globaltype: globaltype,
		options:    options,

		infoIn:  make([]chan *StepInfo, 0),
		infoOut: make([]chan *StepInfo, 0),

		nextSteps: make([]*Step, 0),

		started: atomic.NewBool(false),
		done:    &sync.WaitGroup{},
	}

	return s
}

func (step *Step) asString() string {
	return fmt.Sprintf("(%p) %+v", step, step)
}

func (step *Step) printSequence(tabs int) {
	for _, s := range step.nextSteps {
		log.Printf(fmt.Sprintf("%sS: %s", strings.Repeat("\t", tabs), s.asString()))
		s.printSequence(tabs + 1)
	}
}

func (step *Step) PrintSequence() {
	log.Printf(fmt.Sprint(step.asString()))
	step.printSequence(1)
}

// Creates a subsequent step performed for each run of the current step.
func (step *Step) AddNextStep(name string, globaltype string, options interface{}) *Step {
	c := make(chan *StepInfo, 10)

	newStep := newStep(name, globaltype, options)
	newStep.infoIn = append(newStep.infoIn, c)

	step.infoOut = append(step.infoOut, c)
	step.nextSteps = append(step.nextSteps, newStep)

	return newStep
}

// Follow a sequence to its end and get all leaf steps.
func (step *Step) GetLastSteps() []*Step {
	tmp := make([]*Step, 0)

	if len(step.nextSteps) == 0 {
		return []*Step{step}
	} else {
		for _, s := range step.nextSteps {
			tmp = append(tmp, s.GetLastSteps()...)
		}
	}

	steps := make(map[*Step]bool)
	result := make([]*Step, 0)
	for _, item := range tmp {
		if _, value := steps[item]; !value {
			steps[item] = true
			result = append(result, item)
		}
	}
	return result
}

// Creates a subsequent steps on all subsequences
func (step *Step) AddNextLastSteps(name string, globaltype string, options interface{}) []*Step {
	newsteps := make([]*Step, 0)

	last_steps := step.GetLastSteps()
	for _, s := range last_steps {
		newsteps = append(newsteps, s.AddNextStep(name, globaltype, options))
	}

	return newsteps
}

// A join step merges the IPLists of all steps
func (step *Step) AddJoinStep(name string, globaltype string, options interface{}, steps []*Step) *Step {
	new_step := newStep(name, globaltype, options)
	tmp_steps := make([]*Step, 0, len(steps)+1)

	tmp_steps = append(tmp_steps, step)
	tmp_steps = append(tmp_steps, steps...)

	for _, s := range tmp_steps {
		c := make(chan *StepInfo, 10)

		s.nextSteps = append(s.nextSteps, new_step)
		s.infoOut = append(s.infoOut, c)
		new_step.infoIn = append(new_step.infoIn, c)
	}

	return new_step
}

// Join all last steps in step's sequence.
func (step *Step) AddLastJoinStep(name string, globaltype string, options interface{}) *Step {
	last_steps := step.GetLastSteps()
	return last_steps[0].AddJoinStep(name, globaltype, options, last_steps[1:])
}

// Run the sequence.
func (step *Step) Start() {
	for _, n := range step.nextSteps {
		log.Debugf("From step %s: Starting step %s", step.name, n.name)
		n.Start()
	}
	step.start()
}

// Wait for this and all future steps to complete.
func (step *Step) Wait() {
	log.Infof("Waiting for step %s to finish", step.name)
	step.done.Wait()
	log.Debugf("Step %s finished", step.name)

	for _, n_s := range step.nextSteps {
		n_s.Wait()
	}
}

// Get the IP lists of all last steps.
func (step *Step) GetLastIPList() *iplist.IPList {
	last_steps := step.GetLastSteps()
	var last_iplists []*iplist.IPList

	for _, s := range last_steps {
		if s.lists != nil {
			last_iplists = append(last_iplists, s.lists...)
		}
	}

	if len(last_iplists) == 0 {
		return nil
	}

	if len(last_iplists) > 1 {
		for _, l := range last_iplists[1:] {
			if l != last_iplists[0] {
				log.Errorf("Last IP lists differ.")
			}
		}
	}

	return last_iplists[0]
}

func (step *Step) start() {
	if !step.started.CAS(false, true) {
		return
	}

	log.Infof("Initiating step %s", step.name)
	step.done.Add(1)

	inInfo := make(chan *StepInfo, 10)
	outInfo := make(chan *StepInfo, 10)

	wgPusher := &sync.WaitGroup{}
	wgGetter := &sync.WaitGroup{}

	if len(step.infoIn) == 0 {
		inInfo <- &StepInfo{}
	} else {
		for _, c := range step.infoIn {
			wgGetter.Add(1)
			go func(c chan *StepInfo) {
				for i := range c {
					var list_info string
					if i.list != nil {
						list_info = fmt.Sprintf("iplist has len %d. (addr: %p)", i.list.Len(), i.list)
					} else {
						list_info = "iplist is nil"
					}
					log.Infof("step %s received input on channel %p: %v (%p). %s", step.name, c, i, i, list_info)
					inInfo <- i
				}
				wgGetter.Done()
			}(c)
		}
	}

	go func() {
		wgGetter.Wait()
		close(inInfo)
		log.Infof("step %s closed its input", step.name)
	}()

	wgPusher.Add(1)
	go func() {
		for i := range outInfo {
			var list_info string
			if i.list != nil {
				list_info = fmt.Sprintf("iplist has len %d. (addr: %p)", i.list.Len(), i.list)
			} else {
				list_info = "iplist is nil"
			}

			log.Infof("step %s sends input: %v (%p). %s", step.name, i, i, list_info)
			if i.list != nil {
				step.lists = append(step.lists, i.list)
			}

			if i.file != "" {
				step.files = append(step.files, i.file)
			}

			for _, c := range step.infoOut {
				c <- i
			}
		}
		for _, c := range step.infoOut {
			close(c)
		}
		wgPusher.Done()
	}()

	go func() {
		wgPusher.Wait()
		step.done.Done()
	}()

	go func() {
		log.Infof("step %s started runner (type: %s)", step.name, step.globaltype)
		StartRun(step.name, step.globaltype, step.options, inInfo, outInfo)
		log.Infof("step %s finished runner (type: %s)", step.name, step.globaltype)
		close(outInfo)
	}()
	log.Debugf("Step %s initiated", step.name)
}

func (step *Step) GetName() string {
	return step.name
}

func NewSequence(name string) *Step {
	return newStep(name, "dummy", nil)
}
