package helper

import (
	"io"
	"net/url"
	"os"
	"path"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/helpers"
	log "github.com/sirupsen/logrus"
)

func DetermineNewestScanFileHTTP(httpparams HTTPParameters, regex string) string {
	root_url, err := url.Parse(httpparams.URI)
	if err != nil {
		log.Fatalf("could not parse url: %s", err)
	}
	if root_url == nil {
		log.Fatalf("error parsing root url: empty (input was %s)", httpparams.URI)
	}

	file_url, err := helpers.TraverseToNewestFile(root_url, regex, httpparams.Username, httpparams.Password)
	if err != nil {
		log.Fatalf("could not retrieve newest scan file: %s", err)
	}
	if file_url == nil {
		log.Fatalf("error getting file url: empty")
	}

	return file_url.String()
}

func DownloadNewestScanFileHTTP(result_path string, httpparams HTTPParameters, p_directurl string) string {
	file_url, err := url.Parse(p_directurl)
	if err != nil {
		log.Fatalf("could not parse url: %s", err)
	}

	file_http, err := helpers.HttpGetFile(file_url, httpparams.Username, httpparams.Password, "")
	if err != nil {
		log.Fatalf("could not download scan file: %s", err)
	}

	target := path.Join(result_path, path.Base(file_url.String()))
	log.Infof("Downloading %s to %s", path.Base(file_url.String()), target)
	// Create the file
	out, err := os.Create(target)
	if err != nil {
		log.Fatalf("could not create local scan file: %s", err)
	}

	// Write the body to file
	_, err = io.Copy(out, file_http)
	if err != nil {
		log.Fatalf("could not download scan file: %s", err)
	}
	out.Close()

	return target
}
