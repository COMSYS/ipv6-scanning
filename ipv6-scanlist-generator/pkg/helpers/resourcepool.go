package helpers

import log "github.com/sirupsen/logrus"

type ResourcePool struct {
	name string
	c    chan interface{}
}

func NewResourcePool(name string, init []interface{}) *ResourcePool {
	log.Infof("Initializing resource pool %v with resources: %v", name, init)

	rp := &ResourcePool{name: name, c: make(chan interface{}, len(init))}
	for _, i := range init {
		rp.c <- i
	}

	return rp
}

func (rp *ResourcePool) GetName() string {
	return rp.name
}

func (rp *ResourcePool) Aquire() interface{} {
	i := <-rp.c
	log.Infof("Got resource from ressource pool %v: %v", rp.name, i)
	return i
}

func (rp *ResourcePool) Release(i interface{}) {
	log.Infof("Release resource from resource pool %v: %v", rp.name, i)
	rp.c <- i
}
