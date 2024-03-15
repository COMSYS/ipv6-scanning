package helpers

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/google/uuid"
	"github.com/hashicorp/go-retryablehttp"
	log "github.com/sirupsen/logrus"
)

const max_reader_buffer_size = 500 * 1024 * 1024 // 500 MB max size of single line

func EncodeIP(ip string) []byte {
	var ip_string string
	var ip_byte []byte

	ip_string = ip

	if strings.Contains(ip_string, ",") {
		ip_string = strings.Split(ip_string, ",")[1]
	}

	if !strings.Contains(ip_string, ":") {
		if len(ip_string) == 32 {
			ip_byte, _ = hex.DecodeString(ip_string)
		} else {
			log.Warnf("Got IP with unexpected length: %s", ip_string)
		}
	} else {
		addr := net.ParseIP(ip_string)
		if addr == nil {
			log.Warnf("Got unparsable IP: %s", ip_string)
		} else {
			ip_byte = append(ip_byte, addr...)
		}
	}

	if len(ip_byte) != net.IPv6len {
		ip_byte = make([]byte, 0)
	}

	return ip_byte
}

func putLinesToChan(rd io.Reader, c chan string) {
	scanner := bufio.NewScanner(rd)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, max_reader_buffer_size)

	for scanner.Scan() {
		c <- scanner.Text()
	}
	if err := scanner.Err(); err != nil {
		log.Errorf("Error while scanning in putLinesToChan(): %s", err)
	}
}

func TraverseToNewestFile(p_url *url.URL, regex string, username string, password string) (*url.URL, error) {
	return TraverseToNewestFileNotNewerAs(p_url, regex, username, password, nil)
}

func TraverseToNewestFileNotNewerAs(p_url *url.URL, regex string, username string, password string, notNewerAs *time.Time) (*url.URL, error) {
	log.Debugf("Traversing to newest file in %s (looking for regex: %s)", p_url.String(), regex)

	if strings.HasSuffix(p_url.String(), "/") {
		doc, err := HtmlGetDocument(p_url, username, password)
		if err != nil {
			return nil, err
		}
		links := doc.Find("a")

		log.Debugf("Found %d links in %s", links.Length(), p_url.String())
		for i := 1; i < links.Length(); i++ {
			link, exists := links.Eq(-i).Attr("href")
			if !exists {
				continue
			}

			parsed_link, err := url.Parse(link)
			if err != nil {
				return nil, err
			}

			new_url := p_url.ResolveReference(parsed_link)
			log.Debugf("Found link text %s parsed to url %s and resolved to %s", link, parsed_link.String(), new_url.String())
			url, _ := TraverseToNewestFileNotNewerAs(new_url, regex, username, password, notNewerAs)
			if url != nil {
				return url, nil
			}
		}

		return nil, errors.New("no matching file found")
	} else {
		matched, err := regexp.Match(regex, []byte(p_url.String()))
		if err != nil {
			return nil, err
		}

		if matched {
			log.Debugf("Found matching url: %s (on regex: %s).", p_url, regex)

			if notNewerAs != nil {
				client := &http.Client{
					Timeout: time.Second * 30,
				}
				// Get the data
				req, err := http.NewRequest("HEAD", p_url.String(), nil)
				if err != nil {
					log.Errorf("Error during HTTP request: %s", err)
					return nil, err
				}
				req.SetBasicAuth(username, password)
				response, err := client.Do(req)
				if err != nil {
					log.Errorf("Error during HTTP request: %s", err)
					return nil, err
				}
				defer response.Body.Close()
				if response.StatusCode != 200 {
					log.Errorf("Status code error: %d %s", response.StatusCode, response.Status)
					return nil, err
				}

				sizestr := response.Header.Get("Content-Length")
				if sizestr != "" {
					size, err := strconv.Atoi(sizestr)
					if err != nil {
						log.Warnf("Got invalid content length (%s): %s", err, sizestr)
						return nil, nil
					} else if size == 0 {
						return nil, nil
					}
				} else {
					return nil, nil
				}

				lastmodified, err := http.ParseTime(response.Header.Get("Last-Modified"))
				if err != nil {
					log.Errorf("Error parsing Last modified time: %s", err)
					return nil, nil
				}

				if lastmodified.Before(*notNewerAs) {
					return p_url, nil
				}

				return nil, nil
			}

			return p_url, nil
		} else {
			log.Debugf("Found no matching url (on regex: %s).", regex)
			return nil, nil
		}
	}
}

func HttpGetFile(url *url.URL, username string, password string, cachepath string) (io.ReadCloser, error) {
	var err error
	var cachefile string

	log.Debugf("Getting file via http: %s", url.String())

	filename := path.Base(url.String())
	if cachepath != "" {
		// Path to store cachefile to
		cachefile = path.Join(cachepath, filename)
	}

	// File is not cached
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	http_client_retry := retryablehttp.NewClient()
	http_client_retry.Logger = nil
	http_client_retry.HTTPClient.Transport = tr

	http_client := http_client_retry.StandardClient()

	// Get the data
	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return nil, err
	}

	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}
	response, err := http_client.Do(req)
	if err != nil {
		return nil, err
	}

	if cachepath != "" {
		err = os.MkdirAll(cachepath, os.ModePerm)
		if err != nil {
			log.Errorf("Error creating cache folder. No caching.")
		} else {
			// Create the file
			cache, err := os.Create(cachefile)
			if err != nil {
				log.Errorf("Error creating cachefile: %s", cachefile)
				return nil, err
			}
			io.Copy(cache, response.Body)
			cache.Close()

			cache, err = os.Open(cachefile)
			if err != nil {
				log.Errorf("Error reopening cachefile: %s", cachefile)
				return nil, err
			}
			return cache, nil
		}
	} else {
		return response.Body, nil
	}

	return nil, nil
}

func HtmlGetDocument(url *url.URL, username string, password string) (*goquery.Document, error) {
	log.Debugf("Requesting %s", url)

	client := &http.Client{
		Timeout: time.Second * 30,
	}
	// Get the data
	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		log.Errorf("Error during HTTP request: %s", err)
		return nil, err
	}
	req.SetBasicAuth(username, password)
	response, err := client.Do(req)
	if err != nil {
		log.Errorf("Error during HTTP request: %s", err)
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		log.Errorf("Status code error: %d %s", response.StatusCode, response.Status)
		return nil, err
	}

	// Load the HTML document
	doc, err := goquery.NewDocumentFromReader(response.Body)
	if err != nil {
		log.Error(err)
	}

	return doc, nil
}

func CalculateUUIDHash() string {
	id := uuid.New()
	bytes := []byte(id.String())
	hash := sha256.Sum256(bytes)
	hashstring := fmt.Sprintf("%x", hash)
	return hashstring
}

func LogPipeProcess(process_name string, in io.Reader, fn func(...interface{})) {
	scanner := bufio.NewScanner(in)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, max_reader_buffer_size)

	for scanner.Scan() {
		fn(process_name, ": ", scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Errorf("Error while scanning output from process %s: %s", process_name, err)
	}
}

func CopyFile(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}
