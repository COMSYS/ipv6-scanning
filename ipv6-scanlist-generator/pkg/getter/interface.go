package getter

import "github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"

type Getter interface {
	GetName() string
	GetID() string
	GetIPs(*iplist.IPList)
}
