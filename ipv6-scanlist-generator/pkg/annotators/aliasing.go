package annotators

import (
	"net/url"
	"os"
	"sync"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/helpers"
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"
	log "github.com/sirupsen/logrus"
)

type AliasingAnnotator struct {
	lpm *longestprefixmatching

	root     *url.URL
	username string
	password string
	cache    string

	newest_url_aliased    *url.URL
	newest_url_nonaliased *url.URL

	aliased_path string
	aliased_num  int
}

func (a *AliasingAnnotator) getNewestURLs() (*url.URL, *url.URL, error) {
	var result *url.URL
	var err error

	if a.newest_url_aliased == nil {
		result, err = helpers.TraverseToNewestFile(a.root, `.*-aliased\.txt\.xz`, a.username, a.password)
		if err != nil {
			return nil, nil, err
		}
		a.newest_url_aliased = result
	}

	if a.newest_url_nonaliased == nil {
		result, err = helpers.TraverseToNewestFile(a.root, `.*-nonaliased\.txt\.xz`, a.username, a.password)
		if err != nil {
			return nil, nil, err
		}
		a.newest_url_nonaliased = result
	}

	return a.newest_url_aliased, a.newest_url_nonaliased, nil
}

func (a *AliasingAnnotator) convert(line string) (string, interface{}) {
	a.aliased_num++
	return line, a.aliased_num
}

func (a *AliasingAnnotator) initLPM() {
	c_lpm_entry := make(chan *lpmEntry, 10)
	wg_get := &sync.WaitGroup{}
	wg_insert := &sync.WaitGroup{}

	url_aliased, url_nonaliased, err := a.getNewestURLs()
	if err != nil || url_aliased == nil || url_nonaliased == nil {
		log.Errorf("unable to retrieve newest urls: %s (%s ; %s)", err, url_aliased, url_nonaliased)
	}

	wg_get.Add(1)
	go func() {
		a.aliased_path = insertURLinLPM(url_aliased, a.username, a.password, a.cache, a.convert, c_lpm_entry)
		wg_get.Done()
	}()

	wg_get.Add(1)
	go func() {
		insertURLinLPM(url_nonaliased, a.username, a.password, a.cache, func(line string) (string, interface{}) { return line, 0 }, c_lpm_entry)
		wg_get.Done()
	}()

	for i := 0; i < 1000; i++ {
		wg_insert.Add(1)
		go func() {
			a.lpm.fillTree(c_lpm_entry)
			wg_insert.Done()
		}()
	}

	wg_get.Wait()
	close(c_lpm_entry)
	wg_insert.Wait()
}

func (a *AliasingAnnotator) Annotate(e *iplist.IPEntry) {
	info := a.lpm.findLongestPrefix(e)

	if info == nil {
		e.AddComment("aliased", 0)
	} else {
		e.AddComment("aliased", info.(int))
	}
}

func (a *AliasingAnnotator) GetAliasedFilePath() string {
	return a.aliased_path
}

func (a *AliasingAnnotator) Init() {
	a.initLPM()
}

func NewAliasingAnnotator(root_url string, username string, password string, cache string) *AliasingAnnotator {
	_ = os.MkdirAll(cache, os.ModePerm)

	root, err := url.Parse(root_url)
	if err != nil {
		log.Errorf("Error parsing root url: %s", err)
		return nil
	}

	a := &AliasingAnnotator{
		lpm: newLPM(),

		root:     root,
		username: username,
		password: password,
		cache:    cache,
	}

	return a
}
