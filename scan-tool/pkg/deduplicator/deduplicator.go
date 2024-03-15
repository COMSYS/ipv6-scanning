package deduplicator

import "fmt"

type Deduplicator interface {
	Deduplicate(in chan string, out chan string) error
	IsDuplicate(in string) bool
	Close() error
}

func NewDeduplicator(t string, settings interface{}) (Deduplicator, error) {
	if t == "NoFalseNegative" {
		return NewNoFalseNegativeDeduplicator(settings.(*NoFalseNegativeDeduplicatorSettings))
	} else if t == "SlidingWindow" {
		return NewSlidingWindowDeduplicator(settings.(*SlidingWindowDeduplicatorSettings))
	}

	return nil, fmt.Errorf("deduplicator type not implemented")
}
