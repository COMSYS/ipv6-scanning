package sequence

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/internal/generators"
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/getter"
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/helpers"
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"
	log "github.com/sirupsen/logrus"
)

type GetterRun struct {
	getter getter.Getter
}

func NewGetterRun(options *GetterOption) *GetterRun {
	return &GetterRun{getter: options.Getter}
}

func (gr *GetterRun) Run(inInfo chan *StepInfo, outInfo chan *StepInfo) {
	for i := range inInfo {
		list := i.list
		if list == nil {
			list = iplist.NewIPList(gr.getter.GetName())
		}

		gr.getter.GetIPs(list)

		outInfo <- NewStepInfo(i, gr.getter.GetName(), list, "", "")
	}
}

type MergeRun struct {
	name string
}

func (mr *MergeRun) Run(inInfo chan *StepInfo, outInfo chan *StepInfo) {
	wg := &sync.WaitGroup{}
	wg_from_file := &sync.WaitGroup{}
	c := make(chan *iplist.IPList, 100)

	names := make([]string, 0)

	var first *iplist.IPList
	for i := range inInfo {
		names = append(names, i.name)
		for _, f := range i.fileLog {
			wg_from_file.Add(1)
			go func(path string) {
				defer wg_from_file.Done()
				c <- iplist.NewIPListFromZSTPath(path)
			}(f)
		}

		for _, l := range i.listLog {
			if first == nil {
				first = l

				wg.Add(1)
				go func() {
					first.MergeFromChan(c)
					wg.Done()
				}()
			} else {
				c <- l
			}
		}
	}
	wg_from_file.Wait()
	close(c)
	wg.Wait()

	if first == nil {
		log.Panicf("Merge step %s did not receive any input.", mr.name)
	}

	outInfo <- &StepInfo{list: first, name: fmt.Sprintf("%s-merged(%s)", mr.name, strings.Join(names, "+"))}
}

type GeneratorRuns struct {
	name    string
	options *GeneratorOption
}

func NewGeneratorRuns(name string, options *GeneratorOption) *GeneratorRuns {
	log.Debugf("creating new generator run %s", name)
	return &GeneratorRuns{
		name:    name,
		options: options,
	}
}

func (gr *GeneratorRuns) Run(inInfo chan *StepInfo, outInfo chan *StepInfo) {
	wg := &sync.WaitGroup{}
	for i := range inInfo {
		wg.Add(1)
		go func(i *StepInfo) {
			defer wg.Done()
			var cacheFilePath string
			name := i.name + "-" + gr.name

			if hash := i.sourceHash; hash != "" && gr.options.CachePath != "" {
				cacheFilePath = path.Join(gr.options.CachePath, fmt.Sprintf("%s_%s(%s_%d).txt.zst", hash, name, gr.options.Innertype, gr.options.Num))
			}

			if cacheFilePath != "" {
				os.MkdirAll(gr.options.CachePath, os.ModePerm)
			}

			folder_exists := false
			var folder_root string
			if gr.options.TmpPath != "" {
				folder_root = path.Join(gr.options.TmpPath, name)
			} else if i.folder != "" {
				folder_root = i.folder
				folder_exists = true
			} else {
				fallbackTmp := "/tmp"
				log.Warnf("No folder for generator %s specified. Assuming %s.", name, fallbackTmp)
				folder_root = path.Join(fallbackTmp, name)
			}

			var folder string
			if !folder_exists {
				err := os.MkdirAll(folder_root, os.ModePerm)
				if err != nil {
					log.Errorf("error creating root folder for generator %s in folder %s: %s", name, folder_root, err)
				}
				folder, err = os.MkdirTemp(folder_root, "*")
				if err != nil {
					log.Errorf("error creating tmp folder for generator %s in folder %s: %s", name, folder_root, err)
				}
				err = os.Chmod(folder, os.ModePerm)
				if err != nil {
					log.Errorf("error changing permission for tmp folder %s for generator %s in folder %s: %s", folder, name, folder_root, err)
				}
			} else {
				folder = folder_root
			}

			log.Infof("initiating generator run %s (folder: %s)", name, folder)
			g := generators.NewGenerator(gr.options.Innertype, folder, name, gr.options.ResourcePools, gr.options.Timeout)

			g_in := make(chan *iplist.IPEntry, 10000)
			g_out := make(chan *iplist.IPEntry, 10000)

			ctx, cancel := context.WithCancel(context.TODO())
			go func() {
				i.GetAllIPs(ctx, g_in)
				close(g_in)
			}()

			result := iplist.NewIPList(name)

			wg := sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				result.InsertFromChan(g_out, 1)
			}()

			err := g.Run(g_in, g_out, gr.options.Num)
			cancel()
			if err != nil {
				log.Errorf("Generator %s returned with error. pruning sequence path. error was: %s", g.GetName(), err)
				return
			}
			close(g_out)

			wg.Wait()

			// after generator run, merge possibly generated duplicates
			result.Sort()
			result.MergeDuplicateIPAddresses()

			result.CommentAll(name, nil)

			log.Infof("generator run %s finished (folder: %s)", name, folder)

			var info *StepInfo
			if cacheFilePath != "" {
				log.Infof("storing %s to cache file %s", result.GetName(), cacheFilePath)
				result.WriteRunList(cacheFilePath, true, true)
				info = NewStepInfo(i, name, nil, cacheFilePath, folder)
				info.sourceHash = i.sourceHash
			} else {
				// this code leads to a deadlock with geneipgen runs
				// reason is unclear
				// so for now just use cacheFile
				log.Error("reached possible deadlock code section")

				log.Infof("merging %s into %s", result.GetName(), i.list.GetName())
				i.list.Merge(result)
				// does not reach this point (maybe waiting for mutex in Merge)
				log.Infof("merge finished (%s -> %s)", name, i.list.GetName())
				info = NewStepInfo(i, name, i.list, "", folder)
				info.sourceHash = i.sourceHash
			}
			outInfo <- info

		}(i)
	}
	wg.Wait()
}

type SelectionRuns struct {
	name    string
	options *SelectionOption
}

func NewSelectionRuns(name string, options *SelectionOption) *SelectionRuns {
	return &SelectionRuns{
		name:    name,
		options: options,
	}
}

func (sr *SelectionRuns) sendListOnceAndCache(info *StepInfo, out chan *StepInfo, cache bool, name string, run int, id int) {
	if info.list.Len() == 0 {
		log.Errorf("Caught empty selection list: %s_%s(%s_%s_%d-%d-%d)", info.sourceHash, name, sr.options.Innertype, sr.options.Key, sr.options.Num, run, id)
		return
	}

	if sr.options.CachePath != "" && cache {
		info.list.WriteRunList(filepath.Join(sr.options.CachePath, fmt.Sprintf("%s_%s(%s_%s_%d-%d-%d).txt.zst", info.sourceHash, name, sr.options.Innertype, sr.options.Key, sr.options.Num, run, id)), true, false)
	}
	out <- info
}

func (sr *SelectionRuns) Run(inInfo chan *StepInfo, outInfo chan *StepInfo) {
	wg := &sync.WaitGroup{}
	for i := range inInfo {

		for j := 0; j < sr.options.Runs; j++ {
			wg.Add(1)
			go func(i *StepInfo, j int) {
				defer wg.Done()

				name := fmt.Sprintf("%s-%s(%d)", i.name, sr.name, j)

				// for the v4 getter we need to set the source hash here (hash of merged list from cert_sanip,cert_subjectcn,cert_sandns,rdns)
				if strings.Contains(i.name, "v4") {
					i.sourceHash = i.list.GetHash()
				}

				if sr.options.CachePath != "" {
					os.MkdirAll(sr.options.CachePath, os.ModePerm)
				}

				switch sr.options.Innertype {
				// Selection for random
				case "random":
					result := i.list.GetRandom(sr.options.Num).CommentAll(name, nil)
					step := NewStepInfo(i, name, result, "", "")
					step.sourceHash = i.sourceHash
					sr.sendListOnceAndCache(step, outInfo, true, name, j, 0)
				// Selection for eip-aliasing
				case "onePerKey":
					result := i.list.GetOnePerKey(sr.options.Key, sr.options.ValueExcept, sr.options.Num, i.name, j)
					if result != nil {
						result = result.CommentAll(name, nil)
						step := NewStepInfo(i, name, result, "", "")
						step.sourceHash = i.sourceHash
						sr.sendListOnceAndCache(step, outInfo, true, name, j, 0)
					}
				// Selection for eip-as
				case "randomPerKey":
					for k, l := range i.list.GetRandomPerKey(sr.options.Key, sr.options.Num, i.name, j) {
						if sr.options.MinNum != 0 && l.Len() < sr.options.MinNum {
							continue
						}
						result := l.CommentAll(name, nil)
						step := NewStepInfo(i, name, result, "", "")
						step.sourceHash = i.sourceHash
						sr.sendListOnceAndCache(step, outInfo, true, name, j, k)
					}
				}
			}(i, j)
		}
	}
	wg.Wait()
}

type DummyRuns struct {
	name string
}

func (dr *DummyRuns) Run(inInfo chan *StepInfo, outInfo chan *StepInfo) {
	for i := range inInfo {
		outInfo <- i
	}
}

type SelectionOption struct {
	Innertype   string
	Num         int
	Runs        int
	Key         string
	ValueExcept []interface{}
	MinNum      int
	CachePath   string
}

type GeneratorOption struct {
	Innertype string
	Num       int

	TmpPath       string
	Option        interface{}
	ResourcePools []*helpers.ResourcePool
	CachePath     string
	Timeout       time.Duration
}

type GetterOption struct {
	Getter getter.Getter
}

func newRuns(name string, globaltype string, options interface{}) Runs {
	switch globaltype {
	case "selection":
		return NewSelectionRuns(name, options.(*SelectionOption))
	case "generator":
		return NewGeneratorRuns(name, options.(*GeneratorOption))
	case "merge":
		return &MergeRun{name: name}
	case "getter":
		return NewGetterRun(options.(*GetterOption))
	case "dummy":
		return &DummyRuns{name: name}
	default:
		log.Errorf("Unknown Runtype.")
		return nil
	}
}

func StartRun(name string, globaltype string, options interface{}, inInfo chan *StepInfo, outInfo chan *StepInfo) {
	r := newRuns(name, globaltype, options)
	r.Run(inInfo, outInfo)
}
