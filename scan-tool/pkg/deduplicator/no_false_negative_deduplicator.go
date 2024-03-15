package deduplicator

import (
	"io/ioutil"
	"os"
	"path"
	"sync"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/helpers"
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"
	log "github.com/sirupsen/logrus"
	"github.com/timtadh/fs2/bptree"
	"github.com/timtadh/fs2/fmap"
	boom "github.com/tylertreat/boomfilters"
)

type toTree struct {
	ipentry *iplist.IPEntry
	decide  bool
}

type NoFalseNegativeDeduplicator struct {
	tmpDir string
	file   *fmap.BlockFile

	bloom *boom.BloomFilter
	tree  *bptree.BpTree
}

type NoFalseNegativeDeduplicatorSettings struct {
	EstimatedCapacity uint
}

func NewNoFalseNegativeDeduplicator(settings *NoFalseNegativeDeduplicatorSettings) (*NoFalseNegativeDeduplicator, error) {
	var err error

	d := &NoFalseNegativeDeduplicator{
		bloom: boom.NewBloomFilter(settings.EstimatedCapacity, 0.01),
	}

	d.tmpDir, err = ioutil.TempDir("/tmp", "scan-tool-")
	if err != nil {
		return nil, err
	}

	d.file, err = fmap.CreateBlockFile(path.Join(d.tmpDir, "deduplicator"))
	if err != nil {
		return nil, err
	}

	d.tree, err = bptree.New(d.file, 16, 1)
	if err != nil {
		return nil, err
	}

	return d, nil
}

func (d *NoFalseNegativeDeduplicator) Deduplicate(in chan string, out chan string) error {
	ctoTree := make(chan *toTree, 100000000)
	defer d.Close()

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		d.treeHandler(in, out, ctoTree)
	}()

	for ip := range in {
		ipentry, err := iplist.NewIPEntry(ip)
		if err != nil {
			log.Warnf("deduplicator was not able to parse ip (%s): %s", ip, err)
			continue
		}
		d.isDuplicateAsync(ipentry, out, ctoTree)
	}

	close(ctoTree)
	wg.Wait()

	return nil
}

func (d *NoFalseNegativeDeduplicator) treeHandler(in chan string, out chan string, toTree chan *toTree) {
	for tT := range toTree {
		has, err := d.tree.Has(tT.ipentry.GetIP())
		if err != nil {
			log.Warnf("error checking for IP (%s) in b+tree: %s", tT.ipentry.GetIPasString(true), err)
			continue
		} else if has {
			continue
		}
		if tT.decide {
			out <- tT.ipentry.GetIPasString(true)
		}

		err = d.tree.Add(tT.ipentry.GetIP(), []byte{1})
		if err != nil {
			log.Warnf("error inserting ip in deduplication tree: %s", err)
		}
	}
}

func (d *NoFalseNegativeDeduplicator) Close() (err error) {
	err = d.file.Close()
	err = os.RemoveAll(d.tmpDir)

	return
}

func (d *NoFalseNegativeDeduplicator) IsDuplicate(ip string) bool {
	encodedIP := helpers.EncodeIP(ip)
	if d.bloom.TestAndAdd(encodedIP) {
		// Ask tree
		has, err := d.tree.Has(encodedIP)
		if err != nil {
			log.Warnf("error checking for IP (%s) in b+tree: %s", encodedIP, err)
		}
		if !has {
			d.tree.Add(encodedIP, []byte{1})
			return false
		}
	} else { // if bloomfilter does not contain bypass tree for decision
		// Insert into tree
		d.tree.Add(encodedIP, []byte{1})
		return false
	}

	return true
}

func (d *NoFalseNegativeDeduplicator) isDuplicateAsync(ipentry *iplist.IPEntry, out chan string, ctoTree chan *toTree) {
	if d.bloom.TestAndAdd(ipentry.GetIP()) {
		ctoTree <- &toTree{ipentry: ipentry, decide: true}
	} else { // if bloomfilter does not contain bypass tree for decision
		out <- ipentry.GetIPasString(true)
		ctoTree <- &toTree{ipentry: ipentry, decide: false}
	}
}
