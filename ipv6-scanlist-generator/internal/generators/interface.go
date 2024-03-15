package generators

import "github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"

type Generator interface {
	Run(in chan *iplist.IPEntry, out chan *iplist.IPEntry, num int) error

	GetName() string
	GetFolder() string
}
