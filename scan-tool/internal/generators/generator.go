package generators

import (
	"strings"

	log "github.com/sirupsen/logrus"
)

type generator interface {
	Run() error
}

func NewGenerator(generator string, scantype string, udpprobefile string, name string, port int, budget int, rate int, netif string, sourcelist string, resultlist string) generator {
	log.Debugf("Instantiating new %s generator.", generator)

	if strings.HasPrefix(generator, "6scan") {
		return NewSixScan(name, scantype, udpprobefile, port, budget, rate, netif, sourcelist, resultlist)
	}

	return nil
}
