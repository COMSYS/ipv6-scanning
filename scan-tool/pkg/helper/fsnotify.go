package helper

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	log "github.com/sirupsen/logrus"
)

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func CreateFsNotifier(ctx context.Context, out chan string, path string, regex string, num int, recursive bool) error {
	r, err := regexp.Compile(regex)
	if err != nil {
		log.Warnf("Error compiling regex for notification: %s", err)
		return err
	}

	err = os.MkdirAll(path, 0700)
	if err != nil {
		log.Warn("Error creating folder to watch")
		return err
	}

	ticker := time.NewTicker(5 * time.Second)

	// Now wait for the result file
	go func(ctx context.Context, out chan string, r *regexp.Regexp, num int) {
		defer close(out)

		count := 0
		lastMatchingObjects := make([]string, 0)

		for {
			select {
			case <-ticker.C:
				log.Debugf("Checking for created file system object")
				matchingObjects := make([]string, 0)

				err := filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
					if r.MatchString(d.Name()) {
						matchingObjects = append(matchingObjects, path)

						if !contains(lastMatchingObjects, path) && !(num > 0 && count >= num) {
							out <- path
							count++
						}
					}
					return nil
				})
				lastMatchingObjects = matchingObjects

				if err != nil {
					log.Warnf("error checking for file system changes: %s", err)
				}

				if num > 0 && count >= num {
					return
				}
			case <-ctx.Done():
				// Abort / return early
				return
			}
		}

	}(ctx, out, r, num)
	return nil
}
