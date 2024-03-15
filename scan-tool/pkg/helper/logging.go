package helper

import (
	"bufio"
	"io"

	log "github.com/sirupsen/logrus"
)

func LogPipe(prefix string, in io.Reader, fn func(...interface{})) {
	buf := make([]byte, 0, 64*1024)
	scanner := bufio.NewScanner(in)
	scanner.Buffer(buf, 10*1024*1024)
	for scanner.Scan() {
		fn(prefix, ": ", scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Warnf("error while getting output from logpipe of generator %s: %s", prefix, err)
	}
}
