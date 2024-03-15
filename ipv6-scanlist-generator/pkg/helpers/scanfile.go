package helpers

import (
	"fmt"
	"path"
	"path/filepath"
	"sort"

	log "github.com/sirupsen/logrus"
)

func GetLastScanFile(folder string, extension string) string {
	log.Debugf("Getting last scan file in folder %s", folder)
	files, _ := filepath.Glob(path.Join(folder, fmt.Sprintf("*.%s", extension)))

	if len(files) == 0 {
		log.Debug("No files in folder.")
		return ""
	}

	sort.Strings(files)

	file := files[len(files)-1]
	log.Debugf("Select file %s", file)

	return file
}

func CheckStamps(current map[string]string, fromFile map[string]string) bool {
	log.Debug("Comparing stamps")

	for k, v := range current {
		if val, ok := fromFile[k]; ok {
			if val != v {
				return false
			}
		} else {
			return false
		}
	}
	return true
}
