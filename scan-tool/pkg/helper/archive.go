package helper

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/icza/backscanner"
	log "github.com/sirupsen/logrus"
)

func WriteMeta(meta map[string]interface{}, path string) {
	jsonStr, err := json.Marshal(meta)
	if err != nil {
		log.Warnf("error generating json containing meta information: %s", err.Error())
	} else {
		f, err := os.Create(path)
		if err != nil {
			log.Warnf("error creating json meta file: %s", err.Error())
		} else {
			f.WriteString(string(jsonStr))
			f.Close()
		}
	}
}

func GatherStdErrs(globregex string, path string, writer io.Writer) {
	io.WriteString(writer, "\n\n============ errs ============\n\n")
	stderrs, _ := filepath.Glob(fmt.Sprintf(globregex, path))
	for _, stderr := range stderrs {
		io.WriteString(writer, fmt.Sprintf("---- %s ----\n", filepath.Base(stderr)))
		f, err := os.Open(stderr)
		if err != nil {
			log.Warn("error: %s", err)
		}
		fi, err := f.Stat()
		if err != nil {
			log.Warn("error: %s", err)
		}
		defer f.Close()

		tail_lines := 10
		scanner := backscanner.New(f, int(fi.Size()))
		lines := make([]string, tail_lines)
		for i := tail_lines - 1; i > 0; i-- {
			line, _, err := scanner.Line()
			if err != nil {
				if err != io.EOF {
					log.Warnf("error reading %s", stderr)
				}
				break
			}
			lines[i] = line
		}

		for _, line := range lines {
			if line != "" {
				io.WriteString(writer, line+"\n")
			}
		}
		io.WriteString(writer, "\n")
	}
}

func CompressFolder(src_path string, dest_file string) error {
	fileToWrite, err := os.Create(dest_file)
	if err != nil {
		log.Warn("error: %s", err)
		return err
	}
	defer fileToWrite.Close()

	buf := bufio.NewWriter(fileToWrite)
	defer buf.Flush()

	// tar > gzip > buf
	zr := gzip.NewWriter(buf)
	defer zr.Close()

	tw := tar.NewWriter(zr)
	defer tw.Close()

	// walk through every file in the folder
	err = filepath.Walk(src_path, func(file string, fi os.FileInfo, err error) error {
		if err != nil {
			log.Warnf("error with file %s: %s", file, err)
			return nil
		}

		// if not a dir, write file content
		if !fi.IsDir() {
			// generate tar header
			header, ierr := tar.FileInfoHeader(fi, file)
			if ierr != nil {
				log.Warnf("error getting file info of %s: %s", file, ierr)
				return ierr
			}

			// must provide real name
			// (see https://golang.org/src/archive/tar/common.go?#L626)
			rel, ierr := filepath.Rel(src_path, file)
			if ierr != nil {
				log.Warnf("error getting relative path of %s: %s", file, ierr)
				return ierr
			}

			header.Name = filepath.ToSlash(rel)

			// write header
			if ierr := tw.WriteHeader(header); ierr != nil {
				log.Warnf("error writing file header of %s to tar: %s", file, ierr)
				return ierr
			}

			data, ierr := os.Open(file)
			if ierr != nil {
				log.Warnf("error opening %s: %s", file, ierr)
				return ierr
			}
			defer data.Close()

			if _, ierr := io.Copy(tw, data); ierr != nil {
				log.Warnf("error writing file %s to tar: %s", file, ierr)
				return ierr
			}
		}
		return nil
	})
	if err != nil {
		log.Warnf("error walking result files: %s", err)
		return err
	}

	return nil
}
