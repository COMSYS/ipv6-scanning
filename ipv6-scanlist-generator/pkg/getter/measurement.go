package getter

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/x509"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/converter"
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/helpers"
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"
	jsoniter "github.com/json-iterator/go"
	log "github.com/sirupsen/logrus"
)

type PartialGrab struct {
	IP     string                         `json:"ip,omitempty"`
	Domain string                         `json:"domain,omitempty"`
	Data   map[string]PartialScanResponse `json:"data,omitempty"`
	Ptr    []string                       `json:"ptr,omitempty"`
}

type PartialScanResponse struct {
	Status    string                         `json:"status"`
	Protocol  string                         `json:"protocol"`
	Result    map[string]jsoniter.RawMessage `json:"result,omitempty"`
	Timestamp string                         `json:"timestamp"`
	Error     string                         `json:"error,omitempty"`
}

var json = jsoniter.ConfigDefault

var reIP = regexp.MustCompile(` ?(<nil>|([0-9]+.){3}[0-9]+(:[0-9]+)?)(->([0-9]+.){3}[0-9]+(:[0-9]+)?)?`)
var reOversized = regexp.MustCompile(`^tls: oversized record received with length \d+`)
var reInvalidCode = regexp.MustCompile(`^Invalid response function code 0x(..).*`)

const max_reader_buffer_size = 500 * 1024 * 1024 // 500 MB max size of single line

type Measurement struct {
	name string

	protocol_name string
	converter     *converter.Converter

	searchurl *url.URL
	username  string
	password  string
	fileurl   *url.URL
	cachepath string
	ipver     string
	ipsonly   bool

	iplist *iplist.IPList
	m      *sync.Mutex
}

// We get our newest measurement files from an HTTP server.
func (m *Measurement) findFile() {
	var err error
	if m.fileurl == nil {
		m.fileurl, err = helpers.TraverseToNewestFile(m.searchurl, fmt.Sprintf(`.*_%s_%s_.*\.tgz$`, m.protocol_name, m.ipver), m.username, m.password)
		if err != nil {
			log.Errorf("Error finding newest file: %s", err)
		}
	}
}

func (m *Measurement) GetName() string {
	return m.name
}

// We extract information that may lead to a new IPv6 address from a certificate.
func extractFromCertificate(c chan string, cert *x509.Certificate) {
	c <- cert.Subject.CommonName
	for _, dn := range cert.DNSNames {
		c <- dn
	}
	for _, ea := range cert.EmailAddresses {
		c <- strings.Split(ea, "@")[1]
	}
	for _, ip := range cert.IPAddresses {
		c <- ip.String()
	}
	for _, uri := range cert.URIs {
		c <- strings.Split(uri.Host, ":")[0]
	}
	for _, dn := range cert.PermittedDNSDomains {
		c <- dn
	}
	for _, dn := range cert.ExcludedDNSDomains {
		c <- dn
	}
	for _, net := range cert.PermittedIPRanges {
		helpers.ConvertCidrToIPs(net, c)
	}
	for _, net := range cert.ExcludedIPRanges {
		helpers.ConvertCidrToIPs(net, c)
	}
	for _, ea := range cert.PermittedEmailAddresses {
		c <- strings.Split(ea, "@")[1]
	}
	for _, ea := range cert.ExcludedEmailAddresses {
		c <- strings.Split(ea, "@")[1]
	}
	for _, dn := range cert.PermittedURIDomains {
		c <- dn
	}
	for _, dn := range cert.ExcludedURIDomains {
		c <- dn
	}
}

// Extract and parse a line from zgrab2 output
func (m *Measurement) extractLine(c chan string, line []byte) error {
	it := json.BorrowIterator(line)
	var grab PartialGrab
	it.ReadVal(&grab)
	if it.Error != nil {
		log.Warn(it.Error)
		json.ReturnIterator(it)
		return it.Error
	}
	json.ReturnIterator(it)
	if grab.IP == "" {
		log.Warnf("line has no ip address. Skipping entry...")
		return nil
	}

	if m.ipsonly {
		c <- grab.IP
	} else {
		for _, ptr := range grab.Ptr {
			c <- ptr
		}

		for _, scanResponse := range grab.Data {
			if scanResponse.Protocol == "opcua" { // parse OPC UA Certificates
				if opcuaEndpointJson, ok := scanResponse.Result["endpoints"]; ok {
					var endpoints []map[string]jsoniter.RawMessage
					iter := json.BorrowIterator(opcuaEndpointJson)
					iter.ReadVal(&endpoints)
					if it.Error != nil {
						log.Warnf("unable to decode opcua endpoints: %s", it.Error)
						json.ReturnIterator(iter)
						continue
					}
					json.ReturnIterator(iter)

					for _, e := range endpoints {
						if opcuaCertificate, ok := e["ServerCertificate"]; ok {
							if len(opcuaCertificate) > 0 {
								var certificate []byte
								iter := json.BorrowIterator(opcuaCertificate)
								iter.ReadVal(&certificate)
								if it.Error != nil {
									log.Warnf("unable to decode opcua certificate: %s", it.Error)
									json.ReturnIterator(iter)
									continue
								}
								json.ReturnIterator(iter)

								cert, err := x509.ParseCertificate(certificate)
								if err != nil {
									log.Warnf("unable to parse opcua certificate: %s", it.Error)
									continue
								}

								extractFromCertificate(c, cert)
							}
						}
					}
				}
			} else {
				var path []string
				if scanResponse.Protocol == "http" {
					path = []string{"response", "request", "tls_log", "handshake_log", "server_certificates", "certificate", "raw"}
				} else {
					path = []string{"tls", "server_certificates", "certificate", "raw"}
				}
				if first, ok := scanResponse.Result[path[0]]; ok {
					r := jsoniter.Get(first, path[1:])
					if r != nil {
						cert, err := x509.ParseCertificate([]byte(r.ToString()))
						if err != nil {
							log.Warnf("unable to parse certificate: %s", it.Error)
							continue
						}

						extractFromCertificate(c, cert)
					}
				}
			}
			if scanResponse.Error != "" {
				scanResponse.Error = reIP.ReplaceAllString(scanResponse.Error, "")
				scanResponse.Error = reOversized.ReplaceAllString(scanResponse.Error, "tls: oversized record received")
				scanResponse.Error = reInvalidCode.ReplaceAllString(scanResponse.Error, "Invalid response function code 0x$1")
			}
		}
	}

	return nil
}

// Get newest measurement file, decompress it, and iterate over all scan results.
func (m *Measurement) retrieveIPs() {
	m.findFile()
	log.Debugf("Retrieving entries from %s (%s)...", m.GetName(), m.fileurl.String())

	to_converter := make(chan string, 10000)
	from_converter := make(chan converter.ConvertResult, 10000)
	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		log.Debugf("Converting measurement results... (%s)", m.GetName())
		m.converter.Convert(to_converter, from_converter)
		log.Debugf("Converting measurement results done. (%s)", m.GetName())
		close(from_converter)
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		log.Debugf("Handling responses... (%s)", m.GetName())
		for res := range from_converter {
			if len(res.Result) > 0 {
				log.Debugf("Got from converter: %v (%s)", res, m.GetName())
				m.iplist.InsertWithAnnotate(res.Result, m.name, res.Remark)
				log.Debugf("Inserted: %v (%s)", res, m.GetName())
			}
		}
		log.Debugf("Handling responses done. (%s)", m.GetName())
		wg.Done()
	}()

	func() {
		r, err := helpers.HttpGetFile(m.fileurl, m.username, m.password, m.cachepath)
		if err != nil {
			log.Error(err)
		}

		uncompressedStream, err := gzip.NewReader(r)
		if err != nil {
			log.Errorf("ExtractTarGz: NewReader failed")
		}

		tarReader := tar.NewReader(uncompressedStream)

		for {
			header, err := tarReader.Next()
			if err == io.EOF {
				break
			}

			if err != nil {
				log.Errorf("ExtractTarGz: Next() failed: %s", err)
				return
			}

			if header.Typeflag == tar.TypeReg && strings.HasSuffix(header.Name, "zgrab2_out") {
				scanner := bufio.NewScanner(tarReader)
				buf := make([]byte, 64*1024)
				scanner.Buffer(buf, max_reader_buffer_size)

				scanner.Split(bufio.ScanLines)
				for scanner.Scan() {
					if len(scanner.Bytes()) > 0 {
						m.extractLine(to_converter, scanner.Bytes())
					}
				}
				if scanner.Err() != nil {
					log.Errorf("ExtractTarGz: Scanner failed: %s", err)
					return
				}

			}
		}
	}()

	close(to_converter)
	log.Debugf("Sending completed. (%s)", m.GetName())

	wg.Wait()
}

func (m *Measurement) GetID() string {
	m.m.Lock()
	defer m.m.Unlock()

	m.findFile()
	return m.fileurl.Path
}

func (m *Measurement) GetIPs(list *iplist.IPList) {
	m.m.Lock()
	defer m.m.Unlock()

	log.Infof("Get IPs (measurement: %s)...", m.name)

	// list must not be sorted at all times, only in the end
	m.iplist.DisableSorting()

	m.retrieveIPs()

	m.iplist.Sort()
	list.Merge(m.iplist)

	list.Sort()
	list.MergeDuplicateIPAddresses()

	log.Infof("measurement (%s): got %d IPs", m.name, list.Len())
}

func NewMeasurement(name string, p_url string, username string, password string, protocol_name string, ipver string, ipsonly bool, converter *converter.Converter, cachepath string) *Measurement {
	log.Debug("Creating new measurement...")
	searchurl, err := url.Parse(p_url)
	if err != nil {
		log.Errorf("Error parsing url %s: %s", p_url, err)
	}

	return &Measurement{
		name: name,

		protocol_name: protocol_name,
		converter:     converter,

		searchurl: searchurl,
		username:  username,
		password:  password,
		ipver:     ipver,
		ipsonly:   ipsonly,

		cachepath: cachepath,

		iplist: iplist.NewIPList(name),
		m:      &sync.Mutex{},
	}
}
