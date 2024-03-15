package annotators

import (
	"net"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"
	"github.com/yl2chen/cidranger"

	log "github.com/sirupsen/logrus"
)

type lpmEntry struct {
	ipNet net.IPNet
	info  interface{}
}

func (a *lpmEntry) Network() net.IPNet {
	return a.ipNet
}

type longestprefixmatching struct {
	ranger cidranger.Ranger
}

func (l *longestprefixmatching) findLongestPrefix(e *iplist.IPEntry) interface{} {
	networks, err := l.ranger.ContainingNetworks(net.ParseIP(e.ToOutput(true, false)))

	if err != nil {
		log.Warnf("Containing networks error: %s", err)
		return nil
	}

	if len(networks) == 0 {
		return nil
	}

	mostSpecific := (networks[len(networks)-1]).(*lpmEntry)

	return mostSpecific.info
}

func (l *longestprefixmatching) fillTree(inputChan <-chan *lpmEntry) {
	for e := range inputChan {
		l.ranger.Insert(e)
	}
}

func newLPM() *longestprefixmatching {
	return &longestprefixmatching{ranger: cidranger.NewPCTrieRanger()}
}
