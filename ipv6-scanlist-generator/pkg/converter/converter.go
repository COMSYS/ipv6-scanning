package converter

import (
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/helpers"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"go.uber.org/atomic"
	"go.uber.org/ratelimit"
)

type Converter struct {
	mode        string
	privateNets []*net.IPNet
	resolver    string
	rl          ratelimit.Limiter

	Convert func(chan string, chan ConvertResult)
}

type ConvertResult struct {
	Remark string
	Result string
}

// Check if an IP is in a reserved range
func (c *Converter) isPrivateIp(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	for _, block := range c.privateNets {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// Establish TCP connection to DNS resolver
func (c *Converter) establishDNSConn() *dns.Conn {
	conn, err := dns.DialTimeout("tcp", c.resolver, 30*time.Second)
	if err != nil {
		log.Errorf("Error establishing connection to DNS resolver: %s", err)
	} else {
		log.Debugf("Connected to resolver %s", c.resolver)
	}

	return conn
}

// Perform reverse lookup of IP
func reverseIP(ip string) string {
	var bytes []string
	var domain string

	if strings.Contains(ip, ".") {
		// IPv4
		bytes = strings.Split(ip, ".")
		domain = "in-addr"
	} else if strings.Contains(ip, ":") {
		bytes = strings.Split(strings.Replace(hex.EncodeToString(helpers.EncodeIP(ip)), ":", "", -1), "")
		domain = "ip6"
	} else {
		return ""
	}

	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}

	return fmt.Sprintf("%s.%s.arpa.", strings.Join(bytes, "."), domain)
}

// Perform lookup depending on type, e.g., AAAA
func (c *Converter) lookupX(in chan string, out chan ConvertResult, typ string) {
	var t uint16

	worker := 750
	wg := &sync.WaitGroup{}

	c_in := make(chan string, worker*100)
	c_out := make(chan string, worker*100)

	done := atomic.NewBool(false)

	go func() {
		for in != nil || c_out != nil {
			select {
			case req, ok := <-in:
				if !ok {
					in = nil
					done.Store(true)
				} else {
					c_in <- req
				}
			case req, ok := <-c_out:
				if !ok {
					c_out = nil
				} else {
					c_in <- req
				}
			}
		}
	}()

	log.Debugf("Looking up %v records", typ)
	for i := 0; i < worker; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			var val string

			cname_sent := make(map[string]bool)

			conn := c.establishDNSConn()

			for conn == nil {
				time.Sleep(2000 * time.Millisecond)
				conn = c.establishDNSConn()
			}

			switch typ {
			case "AAAA":
				t = dns.TypeAAAA
			case "PTR":
				t = dns.TypePTR
			default:
				log.Errorf("lookup type %s not implemented", typ)
			}
		R:
			for {
				// at max ~ 1000/1 = 1 DNS requests per worker per second
				time.Sleep(1000 * time.Millisecond)

				msg := &dns.Msg{}
				select {
				case req := <-c_in:
					c.rl.Take()

					if typ == "PTR" {
						msg.SetQuestion(dns.Fqdn(reverseIP(req)), t)
					} else {
						msg.SetQuestion(dns.Fqdn(req), t)
					}
					msg.Id = dns.Id()

					log.Debugf("Sending dns request: %v", msg)
					conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
					err := conn.WriteMsg(msg)
					if err != nil {
						log.Warnf("error during dns request: %s (msg was: %v)", err, msg)
						if err != dns.ErrRdata && err != dns.ErrFqdn {
							conn = c.establishDNSConn()
							for conn == nil {
								time.Sleep(2000 * time.Millisecond)
								conn = c.establishDNSConn()
							}
							c_out <- req
						}
						continue R
					}

					conn.SetReadDeadline(time.Now().Add(60 * time.Second))
					res, err := conn.ReadMsg()
					if err != nil {
						log.Warnf("error reading dns response: %s, %s", err, res)
						conn = c.establishDNSConn()
						for conn == nil {
							time.Sleep(2000 * time.Millisecond)
							conn = c.establishDNSConn()
						}
						c_out <- req
						continue R
					}
					log.Debugf("Received dns answer: %v", res)

					if len(res.Answer) != 0 {
						question := msg.Question[0].Name
					S:
						for _, a := range res.Answer {
							switch a := a.(type) {
							case *dns.AAAA:
								val = a.AAAA.String()
								if typ != "AAAA" {
									log.Warnf("Received AAAA (%s) but wanted %s (Requested for %s)", val, typ, question)
									continue S
								}

								ip := net.ParseIP(val)
								if ip == nil {
									log.Warnf("Got invalid IP in dns response (Requested for %s, wanted %s): %s", typ, val, question)
									continue S
								} else if ip.To4() != nil {
									log.Warnf("Got IPv4 address in AAAA record (Requested for %s, wanted %s): %s", typ, val, question)
									continue S
								}

							case *dns.PTR:
								val = a.Ptr
								if typ != "PTR" {
									log.Warnf("Received PTR (%s) but wanted %s (Requested for %s)", val, typ, question)
									continue S
								}
							case *dns.CNAME:
								t := a.Target
								if _, ok := cname_sent[t]; ok {
									continue S
								} else {
									cname_sent[t] = true
									c_out <- t
									continue S
								}
							default:
								continue S
							}
							log.Debugf("Sending result to out.. (conn: %p, type: %s)", conn, typ)
							out <- ConvertResult{Remark: question, Result: val}
							log.Debugf("Sent.. (conn: %p, type: %s)", conn, typ)
						}
					}
				case <-time.After(60 * time.Second):
					if done.Load() {
						break R
					}
				}
			}
			conn.Close()
		}()
	}

	wg.Wait()
	close(c_out)
	close(c_in)
}

// Perform AAAA lookup
func (c *Converter) lookupDNS(in chan string, out chan ConvertResult) {
	c.lookupX(in, out, "AAAA")
}

// Perform RDNS lookup
func (c *Converter) lookupRNDS(in chan string, out chan ConvertResult) {
	r1 := make(chan ConvertResult)
	pipe := make(chan string)
	wg := &sync.WaitGroup{}

	log.Debugf("Looking up RDNS...")

	wg.Add(1)
	go func() {
		log.Debugf("RDNS: Performing PTR lookups...")
		c.lookupX(in, r1, "PTR")
		log.Debugf("RDNS: Performing PTR lookups done.")
		close(r1)
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		log.Debugf("RDNS: Performing AAAA lookups...")
		c.lookupX(pipe, out, "AAAA")
		log.Debugf("RDNS: Performing AAAA lookups done.")
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		log.Debugf("RDNS: Sending PTR results to AAAA requests...")
		for r := range r1 {
			pipe <- r.Result
		}
		log.Debugf("RDNS: Sending PTR results to AAAA requests done.")
		close(pipe)
		wg.Done()
	}()

	wg.Wait()
	log.Debugf("RDNS lookup done.")
}

// Detect input string and select corresponding request type
func (c *Converter) detect(in chan string, out chan ConvertResult) {
	dnslookup := make(chan string, 10000)
	rdnslookup := make(chan string, 10000)

	re, err := regexp.Compile(`[^0-9a-fA-F:\.]`)
	if err != nil {
		log.Error(err)
	}

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go func() {
		c.lookupDNS(dnslookup, out)
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		c.lookupRNDS(rdnslookup, out)
		wg.Done()
	}()

	for i := range in {
		ip := net.ParseIP(re.ReplaceAllString(i, ""))
		if ip != nil {
			if c.isPrivateIp(ip) {
				continue
			}

			if ip.To4() != nil {
				//Reverse DNS (Ipv4 address)
				rdnslookup <- ip.String()
			} else {
				out <- ConvertResult{"", i}
			}
		} else {
			trimmed_domain := strings.Trim(i, "*.")
			if strings.Contains(trimmed_domain, ".") {
				// Might be a domain
				dnslookup <- trimmed_domain
			}
		}
	}

	close(rdnslookup)
	close(dnslookup)
	wg.Wait()
}

func NewConverter(mode string, resolver string) *Converter {
	var privateIPBlocks []*net.IPNet

	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}

	c := &Converter{mode: mode, privateNets: privateIPBlocks, rl: ratelimit.New(6000)}

	switch mode {
	case "DNS":
		c.Convert = c.lookupDNS
	case "ZDNS":
		c.Convert = handleZdns
	case "DETECT":
		c.Convert = c.detect
	default:
		log.Errorf("Unknown mode %s", mode)
	}

	c.resolver = resolver

	return c
}
