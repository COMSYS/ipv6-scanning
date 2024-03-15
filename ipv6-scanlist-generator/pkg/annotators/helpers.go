package annotators

import (
	"net"
	"net/url"
	"path"
	"sync"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/helpers"
	log "github.com/sirupsen/logrus"
)

// Download files with CIDR blocks (one block per line) and adds it to longest prefix matching
func insertURLinLPM(url *url.URL, username string, password string, cache string, convert_fn func(string) (string, interface{}), c chan<- *lpmEntry) string {
	cachePath := ""

	if url == nil {
		log.Errorf("Cannot insert nil url in lpm...")
	}

	c_raw := make(chan string, 10)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		for l := range c_raw {
			l_net, l_info := convert_fn(l)

			if l_net == "" {
				continue
			}

			_, network, err := net.ParseCIDR(l_net)
			if err != nil {
				log.Warnf("Error parsing CIDR %s: %s", l, err)
			} else {
				c <- &lpmEntry{ipNet: *network, info: l_info}
			}
		}
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cf := helpers.NewCompFile(path.Base(url.String()), cache)
		if cf.IsCached() {
			cf.PutLinesFromCacheToChan(c_raw)
		} else {
			d_fd, err := helpers.HttpGetFile(url, username, password, cache)
			if err != nil {
				log.Errorf("Unable to download file: %s", err)
			}
			cf.PutLinesToChan(d_fd, c_raw)
		}
		close(c_raw)

		if cf.IsCached() {
			cachePath = cf.GetCachePath()
		}

		wg.Done()
	}()

	wg.Wait()
	return cachePath
}
