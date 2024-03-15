package getter

import (
	"bufio"
	"net/url"
	"path"
	"sort"
	"strings"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/helpers"
	log "github.com/sirupsen/logrus"
)

type URLSlice []*url.URL

func (u URLSlice) Len() int {
	return len(u)
}

func (u URLSlice) Less(i, j int) bool {
	return strings.Compare(u[i].String(), u[j].String()) == -1
}

func (x URLSlice) Swap(i, j int) { x[i], x[j] = x[j], x[i] }

// Sort is a convenience method: x.Sort() calls Sort(x).
func (x URLSlice) Sort() { sort.Sort(x) }

func download_worker(id int, urls <-chan *url.URL, to_converter chan string, username string, password string, cachepath string) {
	for u := range urls {
		cf := helpers.NewCompFile(path.Base(u.String()), cachepath)

		d_fd, err := helpers.HttpGetFile(u, username, password, cachepath)
		if err != nil {
			log.Errorf("unable to download file: %s", err)
		}
		cf.PutLinesToChan(bufio.NewReader(d_fd), to_converter)
	}
}
