package iplist

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/helpers"
	log "github.com/sirupsen/logrus"
)

var annotators []func(*IPEntry)

func AddAnnotator(fn func(*IPEntry)) {
	annotators = append(annotators, fn)
}

func annotate(e *IPEntry) {
	for _, a := range annotators {
		a(e)
	}
}

type IPEntry struct {
	ip       []byte
	comments *comments
}

// Generate new IP Entry from string
func newIPEntry(ip string) (*IPEntry, error) {
	var err error
	err = nil

	result := &IPEntry{
		ip:       helpers.EncodeIP(strings.TrimSpace(ip)),
		comments: newComments(),
	}

	if len(result.ip) == 0 {
		result = nil
		err = fmt.Errorf("ip was unparsable: %s (len: %d)", ip, len(ip))
	}

	return result, err
}

func NewIPEntry(ip string) (*IPEntry, error) {
	result, err := newIPEntry(ip)

	return result, err
}

// Generate new IP Entry from string and annotate it with all annotators
func NewIPEntryWithAnnotate(ip string) (*IPEntry, error) {
	result, err := newIPEntry(ip)
	if result != nil && err == nil {
		annotate(result)
	}

	return result, err
}

// Read IP Entry from our own file format, i.e., also read comments that have been saved.
func NewIPEntryFromLine(line string) (*IPEntry, error) {
	var err error
	err = nil

	split := strings.Split(line, "#")
	ip := split[0]

	result, err := newIPEntry(ip)
	if err != nil {
		return result, err
	}

	if len(split) > 1 && split[1] != "" && split[1] != " " {
		tmp := strings.Split(strings.TrimSpace(split[1]), ",")
		for _, t := range tmp {
			var vs []string
			kvs := strings.Split(t, ":")
			if len(kvs) > 1 {
				vs = strings.Split(kvs[1], ";")
			}

			if len(vs) == 0 {
				result.AddComment(kvs[0], nil)
			} else {
				for _, v := range vs {
					result.AddComment(kvs[0], v)
				}
			}
		}
	}

	return result, err
}

// Get string from IP Entry with or without colons
func (e *IPEntry) GetIPasString(colons bool) string {
	ip := hex.EncodeToString(e.ip)

	if colons {
		return fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s:%s", ip[0:4], ip[4:8], ip[8:12], ip[12:16], ip[16:20], ip[20:24], ip[24:28], ip[28:])
	} else {
		return ip
	}
}

func (e *IPEntry) GetIP() []byte {
	return e.ip
}

func (e *IPEntry) GetCommentKeys() []string {
	return e.comments.getKeys()
}

func (e *IPEntry) AddComment(key string, value interface{}) bool {
	return e.comments.add(key, value)
}

func (e *IPEntry) KeysContain(key string) bool {
	return e.comments.keysContain(key)
}

func (e *IPEntry) CommentsContain(key string, value interface{}) bool {
	return e.comments.contain(key, value)
}

func (e *IPEntry) GetComments(key string) map[interface{}]bool {
	return e.comments.get(key)
}

func (e *IPEntry) MergeComments(f *IPEntry) {
	e.comments.merge(f.comments)
}

func (e *IPEntry) Less(f *IPEntry) bool {
	return (bytes.Compare(e.ip, f.ip) == -1)
}

func (e *IPEntry) EqualIP(f *IPEntry) bool {
	return (bytes.Equal(e.ip, f.ip))
}

// Write IP Entry and all comments to our own file format
func (e *IPEntry) ToOutput(colons bool, withComments bool) string {
	var result string

	if withComments {
		keys := e.GetCommentKeys()
		sort.Strings(keys)

		comments := make([]string, 0)

		for _, k := range keys {
			v_str := make([]string, 0)
			for v_in := range e.comments.get(k) {
				if v_in != nil {
					v_str = append(v_str, fmt.Sprintf("%v", v_in))
				}
			}
			if len(v_str) > 0 {
				sort.Strings(v_str)
				comments = append(comments, fmt.Sprintf("%s:%v", k, strings.Join(v_str, ";")))
			} else {
				comments = append(comments, k)
			}
		}

		result = fmt.Sprintf("%s # %s", e.GetIPasString(colons), strings.Join(comments, ","))
	} else {
		result = e.GetIPasString(colons)
	}

	return result
}

func (e *IPEntry) GetCommentsAsMap() map[string][]string {
	keys := e.GetCommentKeys()
	comments := make(map[string][]string, 0)
	for _, k := range keys {
		comments[k] = make([]string, 0)
		for v_in := range e.comments.get(k) {
			if v_in != nil {
				comments[k] = append(comments[k], fmt.Sprintf("%v", v_in))
			}
		}
	}
	return comments
}

func (e *IPEntry) WriteIPToWriter(w io.Writer, colons bool, withComments bool) {
	_, err := io.WriteString(w, fmt.Sprintf("%s\n", e.ToOutput(colons, withComments)))
	if err != nil {
		log.Errorf("Error writing IP to file: %s", err)
	}
}
