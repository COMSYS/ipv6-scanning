package deduplicator

import (
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"
	log "github.com/sirupsen/logrus"
	boom "github.com/tylertreat/boomfilters"
)

type SlidingWindowDeduplicator struct {
	bloom *boom.InverseBloomFilter
}

type SlidingWindowDeduplicatorSettings struct {
	Capacity uint
}

func NewSlidingWindowDeduplicator(settings *SlidingWindowDeduplicatorSettings) (*SlidingWindowDeduplicator, error) {
	d := &SlidingWindowDeduplicator{
		bloom: boom.NewInverseBloomFilter(settings.Capacity),
	}

	return d, nil
}

func (d *SlidingWindowDeduplicator) Deduplicate(in chan string, out chan string) error {
	for ip := range in {
		if !d.IsDuplicate(ip) {
			out <- ip
		}
	}
	return nil
}

func (d *SlidingWindowDeduplicator) IsDuplicate(ip string) bool {
	ipentry, err := iplist.NewIPEntry(ip)
	if err != nil {
		log.Warnf("deduplicator was not able to parse ip (%s): %s", ip, err)
		return true
	}
	return d.bloom.TestAndAdd(ipentry.GetIP())
}

func (d *SlidingWindowDeduplicator) Close() error {
	return nil
}
