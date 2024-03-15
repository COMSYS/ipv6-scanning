package helpers

import (
	crand "crypto/rand"
	"math/big"
	"net"
	"sort"

	log "github.com/sirupsen/logrus"
)

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func ConvertCidrToIPs(net *net.IPNet, c chan string) {
	ip := net.IP
	for ip := ip.Mask(net.Mask); net.Contains(ip); inc(ip) {
		c <- ip.String()
	}
}

func contains(s []*net.IP, e *net.IP) bool {
	if len(s) == 0 {
		return false
	}

	i := sort.Search(len(s)-1, func(i int) bool { return s[i].Equal(*e) })
	return s[i].Equal(*e)
}

func appendSorted(s []*net.IP, e *net.IP) []*net.IP {
	i := sort.Search(len(s), func(i int) bool { return s[i].Equal(*e) })
	tmp := append(s, nil)
	copy(tmp[i+1:], tmp[i:])
	tmp[i] = e
	return tmp
}

func ConvertCidrToShareIPs(pnet *net.IPNet, c chan string, num int) {
	numBI := big.NewInt(int64(num))

	ones, bits := pnet.Mask.Size()
	hostmasklen := bits - ones

	quotient := ones / 8
	remainder := ones % 8

	netSize := big.NewInt(0)
	netSize = netSize.Exp(big.NewInt(int64(2)), big.NewInt(int64(hostmasklen)), nil)

	log.Debugf("randomly selecting %d IPs from %s (%d IPs)", num, pnet.String(), netSize)

	rand_ips := make([]*net.IP, 0)

	if numBI.Cmp(netSize) >= 0 {
		log.Debugf("selecting all IPs from %s (%d IPs)", pnet.String(), netSize)

		ip := pnet.IP
		for ip := ip.Mask(pnet.Mask); pnet.Contains(ip); inc(ip) {
			c <- ip.String()
		}
	} else {
		for len(rand_ips) < num {
			r := make([]byte, 16)
			crand.Read(r)

			for i := 0; i <= quotient; i++ {
				if i == quotient {
					shifted := byte(r[i]) >> remainder
					r[i] = ^pnet.IP[i] & shifted
				} else {
					r[i] = pnet.IP[i]
				}
			}
			ip := &net.IP{r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]}

			if !ip.Equal(pnet.IP) && !contains(rand_ips, ip) {
				rand_ips = appendSorted(rand_ips, ip)
				c <- ip.String()
			}
		}
	}
}

func CidrIntersect(n1, n2 *net.IPNet) bool {
	return n2.Contains(n1.IP) || n1.Contains(n2.IP)
}

var reserved = []string{"::/128", "::1/128", "::ffff:0:0/96", "::ffff:0:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001:0000::/32", "2001:20::/28", "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8"}
var reservedParsed []*net.IPNet

func IsReservedIPv6(n *net.IPNet) bool {
	if len(reservedParsed) == 0 {
		for _, r := range reserved {
			_, tmpNet, err := net.ParseCIDR(r)
			if err != nil {
				log.Errorf("error parsing reserved cidr %s: %s", r, err)
			} else {
				reservedParsed = append(reservedParsed, tmpNet)
			}
		}
	}

	for _, r := range reservedParsed {
		if CidrIntersect(r, n) {
			return true
		}
	}

	return false
}
