package helper

import (
	"fmt"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	IPv4 = "4"
	IPv6 = "6"
)

func GetIPaddress(ifName string, version string) (net.IP, error) {
	netIf, err := net.InterfaceByName(ifName)
	if err != nil {
		log.Warnf("error getting network interface: %s", err)
		return nil, err
	}

	addresses, err := netIf.Addrs()
	if err != nil {
		log.Warnf("error getting IP address: %s", err)
		return nil, err
	}

	for _, a := range addresses {
		parsed_ip, _, _ := net.ParseCIDR(a.String())
		parsed := parsed_ip.To4()
		if version == IPv4 && parsed != nil {
			return parsed_ip, nil
		} else if version == IPv6 && parsed == nil {
			if !strings.HasPrefix(parsed_ip.String(), "fe80") {
				return parsed_ip, nil
			} else {
				continue
			}
		} else {
			continue
		}
	}

	err = fmt.Errorf("interface %s does not have an IP address of version %s", ifName, version)
	log.Warnf("error getting ip address: %s", err)

	return nil, err
}
