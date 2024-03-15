package helpers

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/cosnicolaou/pbzip2"
	"github.com/ulikunitz/xz"

	gzip "github.com/klauspost/pgzip"
	log "github.com/sirupsen/logrus"
)

type CompFile struct {
	filename string

	path string

	cache       string
	compression string
}

func (cfile *CompFile) GetCachePath() string {
	return path.Join(cfile.cache, fmt.Sprintf("%s.decompressed", cfile.filename))
}

func (cfile *CompFile) GetCachePathTmp() string {
	return path.Join(cfile.cache, fmt.Sprintf("%s.decompressed.tmp", cfile.filename))
}

func (cfile *CompFile) IsCached() bool {
	if cfile.cache != "" {
		_, err := os.Stat(cfile.GetCachePath())
		return err == nil
	}
	return false
}

func (cfile *CompFile) PutLinesFromCacheToChan(c chan string) {
	fd, err := os.Open(cfile.GetCachePath())
	if err != nil {
		log.Errorf("Error opening file %s: %s", cfile.path, err)
	}
	defer fd.Close()

	reader := bufio.NewReader(fd)

	putLinesToChan(reader, c)
}

func (cfile *CompFile) getUncompressedReader(rd io.Reader) io.Reader {
	var reader io.Reader
	var err error

	if cfile.compression == "xz" {
		config := xz.ReaderConfig{
			SingleStream: true,
		}

		reader, err = config.NewReader(rd)
		if err != nil {
			log.Errorf("xz reader error %s", err)
		}
	} else if cfile.compression == "gz" {
		reader, err = gzip.NewReader(rd)
		if err != nil {
			log.Errorf("gzip reader error %s", err)
		}
	} else if cfile.compression == "bz2" {
		reader = pbzip2.NewReader(context.TODO(), rd)
		if err != nil {
			log.Errorf("gzip reader error %s", err)
		}
	} else {
		log.Infof("compression type %s is unknown. no decompression is applied", cfile.compression)
		reader = rd
	}

	return reader
}

func (cfile *CompFile) PutLinesToChan(rd io.Reader, c chan string) {
	var r io.Reader
	var w io.WriteCloser

	urd := cfile.getUncompressedReader(rd)

	if cfile.cache != "" {
		writer_cache, err := os.Create(cfile.GetCachePathTmp())
		if err != nil {
			log.Errorf("Error opening new cache file: %s", err)
		}

		r = io.TeeReader(urd, writer_cache)

		putLinesToChan(r, c)

		writer_cache.Close()

		// Rename tmp uncompressed file to uncompressed file
		err = os.Rename(cfile.GetCachePathTmp(), cfile.GetCachePath())
		if err != nil {
			log.Errorf("Error renaming file: %s", err)
		}

	} else {
		r, w = io.Pipe()
		go func() {
			// write everything into the pipe. Decompression happens in this goroutine.
			_, err := io.Copy(w, urd)
			if err != nil {
				log.Errorf("Failed to copy ips to chan: %v", err)
			}

			w.Close()
		}()

		putLinesToChan(r, c)
	}
}

func NewCompFile(filename string, cache string) *CompFile {
	filename_split := strings.Split(filename, ".")

	cfile := CompFile{
		filename:    filename,
		cache:       cache,
		compression: filename_split[len(filename_split)-1],
	}
	return &cfile
}
