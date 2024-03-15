package blocklist

import (
	"bufio"
	"net"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/yl2chen/cidranger"
)

type Blocklist struct {
	list cidranger.Ranger
}

func NewBlocklist(path string) (*Blocklist, error) {
	result := &Blocklist{list: cidranger.NewPCTrieRanger()}

	f, err := os.Open(path)
	if err != nil {
		log.Warnf("error: %s", err)
		return nil, err
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		l_net := strings.TrimSpace(strings.Split(line, "#")[0])
		if len(l_net) == 0 {
			continue
		}
		_, blocked_network, err := net.ParseCIDR(l_net)
		if err != nil {
			log.Warnf("blacklist: error parsing line %s: %s", line, err)
			continue
		}
		result.list.Insert(cidranger.NewBasicRangerEntry(*blocked_network))
	}

	return result, nil
}

// True if ip is blocklisted.
func (b *Blocklist) IsBlocklisted(ip string) bool {
	contains, err := b.list.Contains(net.ParseIP(ip))
	if err != nil {
		log.Warnf("error checking ip %s against blacklist: %s", ip, err)
		return false
	}
	return contains
}
