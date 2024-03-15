package helper

import (
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	yaml "gopkg.in/yaml.v2"
)

type HTTPParameters struct {
	URI      string
	Username string
	Password string
}

type ScanParameters struct {
	Protocol       string
	ScanRate       int
	Interface      string
	ConfigRootPath string
	Blocklist4Path string
	Blocklist6Path string
	IPver          string
	Subnet         string

	KeepResults bool

	LogMetaPath string

	ResultRootPath string

	// IPv6 options
	IPv6SeedRootPath   string
	IPv6ResultRootPath string
	Generators         []string
	Duration           time.Duration
	IPv6Http           HTTPParameters
	IPv6Addressfile    string
}

type ScanAttributes struct {
	ResultPath string
	IPaddress  string

	ScanType     string // true if tcp scan (set when constructing appqueue)
	UDPProbeFile string
}

type SubScanParameters struct {
	IPv6SeedRootPath   string
	IPv6ResultRootPath string
	Rate               int
	Interface          string
}

func ParseConfigurationToYaml(path string) (*yaml.MapSlice, error) {
	conf, err := os.ReadFile(path)
	if err != nil {
		log.Warnf("error reading config file: %s", err)
		return nil, err
	}

	data := new(yaml.MapSlice)
	err = yaml.Unmarshal(conf, &data)
	if err != nil {
		log.Warnf("error parsing config file: %s", err)
		return nil, err
	}

	return data, err
}

func ParseConfigurationToMap(path string) (map[string]map[string]string, error) {
	var err error

	data, err := ParseConfigurationToYaml(path)
	if err != nil {
		return nil, err
	}

	datamap := make(map[string]map[string]string)
	for _, m_c := range *data {
		main_key := m_c.Key.(string)
		datamap[main_key] = make(map[string]string)
		for _, c := range m_c.Value.(yaml.MapSlice) {
			datamap[main_key][c.Key.(string)] = c.Value.(string)
		}
	}

	return datamap, err
}
