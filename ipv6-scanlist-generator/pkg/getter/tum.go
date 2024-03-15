package getter

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sync"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/helpers"
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"
	log "github.com/sirupsen/logrus"
	"go.uber.org/atomic"
)

type Tum struct {
	name string

	root     *url.URL
	username string
	password string
	cache    string

	newest_url *url.URL
}

// Traverse to the newest tum list
func (t *Tum) getNewestURL() (*url.URL, error) {
	var result *url.URL
	var err error

	log.Debugf("Getting newest %s list", t.GetName())
	result = nil

	if t.newest_url == nil {
		result, err = helpers.TraverseToNewestFile(t.root, `.*\.txt\.xz`, t.username, t.password)
		if err != nil {
			return nil, err
		}
		t.newest_url = result
	} else {
		result = t.newest_url
	}

	return result, nil
}

func (t *Tum) GetID() string {
	url, err := t.getNewestURL()
	if err != nil {
		log.Errorf("unable to get newest URL: %s", err)
	}

	h := sha256.New()
	h.Write([]byte(filepath.Base(url.String())))
	return hex.EncodeToString(h.Sum(nil))
}

func (t *Tum) GetName() string {
	return t.name
}

// Get all IPs from the found file
func (t *Tum) GetIPs(list *iplist.IPList) {
	//from testing, just one workers seems to fit well (otherwise to much time is lost during merging of sublists)
	worker := 1

	c_str := make(chan string, worker*10000)
	c_e := make(chan *iplist.IPEntry, worker*10000)

	wg_comp := &sync.WaitGroup{}
	wg_entries := &sync.WaitGroup{}
	wg_insert := &sync.WaitGroup{}

	log.Infof("Get IPs (tum: %s)", t.name)

	url, err := t.getNewestURL()
	if err != nil {
		log.Errorf("unable to retrieve newest url: %s", err)
	}

	numIPs := atomic.NewUint32(0)

	for i := 0; i < worker; i++ {
		wg_entries.Add(1)
		go func() {
			for ip_str := range c_str {
				numIPs.Inc()
				ip, err := iplist.NewIPEntryWithAnnotate(ip_str)
				if ip != nil && err == nil {
					ip.AddComment(t.GetName(), nil)
					c_e <- ip
				}
			}
			wg_entries.Done()
		}()
	}

	wg_comp.Add(1)
	go func() {
		cf := helpers.NewCompFile(path.Base(url.String()), t.cache)
		if cf.IsCached() {
			cf.PutLinesFromCacheToChan(c_str)
		} else {
			d_fd, err := helpers.HttpGetFile(url, t.username, t.password, t.cache)
			if err != nil {
				log.Errorf("unable to download file: %s", err)
			}

			cf.PutLinesToChan(d_fd, c_str)
			d_fd.Close()
		}
		wg_comp.Done()
	}()

	wg_insert.Add(1)
	go func() {
		defer wg_insert.Done()
		list.InsertFromChan(c_e, worker)
	}()

	wg_comp.Wait()
	close(c_str)
	wg_entries.Wait()
	close(c_e)
	wg_insert.Wait()

	log.Infof("tum (%s): got %d IPs.", t.name, list.Len())
}

func NewTum(name string, root_url string, username string, password string, cache string) *Tum {
	_ = os.MkdirAll(cache, os.ModePerm)

	root, err := url.Parse(root_url)
	if err != nil {
		log.Errorf("error parsing root url")
		return nil
	}

	return &Tum{
		name:     name,
		root:     root,
		username: username,
		password: password,
		cache:    cache,
	}
}
