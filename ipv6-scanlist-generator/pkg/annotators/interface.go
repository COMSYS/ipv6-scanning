package annotators

import "github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"

type Annotator interface {
	Init()
	Annotate(*iplist.IPEntry)
}
