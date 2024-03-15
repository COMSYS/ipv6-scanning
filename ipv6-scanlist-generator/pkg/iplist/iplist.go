package iplist

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/helpers"
	"github.com/klauspost/compress/zstd"
	log "github.com/sirupsen/logrus"
	"go.uber.org/atomic"
)

type IPList struct {
	name     string
	filepath string
	rw_mu    *sync.RWMutex
	sorted   *atomic.Bool
}

const parent_dir = "/tmp/ipv6-scanlist-generator"
const max_reader_buffer_size = 500 * 1024 * 1024 // 500 MB max size of single line

func NewIPList(name string) *IPList {
	err := os.MkdirAll(parent_dir, os.ModePerm)
	if err != nil {
		log.Errorf("Error creating directory: %s", err)
	}
	name = name + "_" + helpers.CalculateUUIDHash()
	filepath := parent_dir + "/" + name

	tmp, err := os.Create(filepath)
	if err != nil {
		log.Errorf("Error creating file: %s", err)
	}
	defer tmp.Close()
	return &IPList{
		name:     name,
		filepath: filepath,
		rw_mu:    &sync.RWMutex{},
		sorted:   atomic.NewBool(true),
	}
}

// Puts every listfile in a different directory.
// Used in getPerKey() to avoid large number of files in same directory
func NewIPListForGetPerKey(name string, pathextension string, runnum int) *IPList {

	tmp_parent_dir := fmt.Sprintf("%s_getPerKey_%s_%d/%s", parent_dir, pathextension, runnum, helpers.CalculateUUIDHash())

	err := os.MkdirAll(tmp_parent_dir, os.ModePerm)
	if err != nil {
		log.Errorf("Error creating directory: %s", err)
	}

	name = name + "_" + helpers.CalculateUUIDHash()
	filepath := tmp_parent_dir + "/withSubDirectory"

	tmp, err := os.Create(filepath)
	if err != nil {
		log.Errorf("Error creating file: %s", err)
	}
	defer tmp.Close()
	return &IPList{
		name:     name,
		filepath: filepath,
		rw_mu:    &sync.RWMutex{},
		sorted:   atomic.NewBool(true),
	}
}

// Create IP List from zstd file
func NewIPListFromZSTPath(path string) *IPList {
	result := NewIPList("FromZSTPath")

	c := make(chan *IPEntry, 10000)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		result.InsertFromChan(c, 1)
	}()

	GetIPEntriesFromZSTFile(path, c)
	close(c)
	wg.Wait()

	return result
}

// Read header from our own IPList file format
func GetHeaderFromFile(path string) map[string]map[string]string {
	log.Debugf("Get header from file %s", path)

	result := make(map[string]map[string]string)

	fd, err := os.Open(path)
	if err != nil {
		log.Errorf("Error opening file %s: %s", path, err)
	}
	defer fd.Close()

	reader, err := zstd.NewReader(fd)
	if err != nil {
		log.Errorf("NewReader error %s", err)
	}

	re_ip, _ := regexp.Compile("[0-9a-fA-F]{4}:[0-9a-fA-F]{4}:[0-9a-fA-F]{4}:[0-9a-fA-F]{4}:[0-9a-fA-F]{4}:[0-9a-fA-F]{4}:[0-9a-fA-F]{4}:[0-9a-fA-F]{4}.*")
	re_head, _ := regexp.Compile("##### (?P<header>.*) #####")
	re_kv, _ := regexp.Compile("# (?P<key>.*) - (?P<value>.*)")

	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, max_reader_buffer_size)

	head := ""
	for scanner.Scan() {
		line := scanner.Text()

		if re_ip.MatchString(line) {
			break
		}

		match_head := re_head.FindStringSubmatch(line)
		if len(match_head) > 0 {
			for i := range re_head.SubexpNames() {
				if i > 0 && i <= len(match_head) {
					head = match_head[i]
				}
			}
			result[head] = make(map[string]string)
		}

		match_kv := re_kv.FindStringSubmatch(line)
		if len(match_kv) > 0 {
			paramsMap := make(map[string]string)
			for i, name := range re_kv.SubexpNames() {
				if i > 0 && i <= len(match_kv) {
					paramsMap[name] = match_kv[i]
				}
			}

			result[head][paramsMap["key"]] = paramsMap["value"]
		}
	}
	if err := scanner.Err(); err != nil {
		log.Errorf("Error while scanning in GetStampsFromFile(): %s", err)
	}

	log.Debugf("Read header values: %v", result)
	return result
}

// Get IP Entries from a zstd compressed IP List
func GetIPEntriesFromZSTFile(path string, c chan *IPEntry) {
	log.Debugf("Reading scanfile from %s", path)

	//opening file to write to
	f_in, err := os.Open(path)
	if err != nil {
		log.Errorf("Error opening file: %s", err)
	}
	defer f_in.Close()

	gf, err := zstd.NewReader(f_in)
	if err != nil {
		log.Errorf("Error opening zstd writer: %s", err)
	}

	scanner := bufio.NewScanner(gf)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, max_reader_buffer_size)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		entry, err := NewIPEntryFromLine(line)
		if err != nil {
			log.Warnf("Unable to insert line %s from ip list file: %s", line, err)
			continue
		}

		c <- entry
	}
	if err := scanner.Err(); err != nil {
		log.Errorf("Error while scanning in GetIPEntriesFromZSTFile(): %s", err)
	}
}

func (l *IPList) AquireRead() {
	l.rw_mu.RLock()
}

func (l *IPList) DoneRead() {
	l.rw_mu.RUnlock()
}

func (l *IPList) AquireWrite() {
	l.rw_mu.Lock()
}

func (l *IPList) DoneWrite() {
	l.rw_mu.Unlock()
}

func (l *IPList) DisableSorting() {
	l.sorted.Store(false)
}

func (l *IPList) Len() int {
	l.AquireRead()
	defer l.DoneRead()

	return l.len()
}

func (l *IPList) len() int {
	file, err := os.Open(l.filepath)
	if err != nil {
		log.Errorf("Error opening file: %s", err)
	}
	defer file.Close()
	lines, err := lineCounter(file)
	if err != nil {
		log.Errorf("Error reading length of file: %s", err)
	}
	return lines
}

func lineCounter(r io.Reader) (int, error) {
	buf := make([]byte, 32*1024)
	count := 0
	lineSep := []byte{'\n'}

	for {
		c, err := r.Read(buf)
		count += bytes.Count(buf[:c], lineSep)

		switch {
		case err == io.EOF:
			return count, nil

		case err != nil:
			return count, err
		}
	}
}

func (l *IPList) Less(i, j int) bool {
	l.AquireRead()
	defer l.DoneRead()

	return l.less(i, j)
}

func (l *IPList) less(i, j int) bool {
	return l.Get(i).Less(l.Get(j))
}

// Merge IP Lists from a channel into this list
func (l *IPList) MergeFromChan(c <-chan *IPList) {
	num_merges := atomic.NewInt32(0)
	done := atomic.NewBool(false)

	intermediate_c := make(chan *IPList, 100)

	log.Debugf("Merging from chan into %s..", l.name)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		a := l
		for num_merges.Load() > 0 || !done.Load() {
			log.Debugf("num_merges: %d, done: %t", num_merges.Load(), done.Load())

			incoming_l := <-intermediate_c

			// if channel was "closed", we read a nil pointer
			if incoming_l == nil {
				break
			}

			if a == nil {
				a = incoming_l
				log.Debugf("Stored list %s as a.", incoming_l.name)
			} else {
				b := incoming_l
				log.Debugf("Stored list %s as b.", incoming_l.name)
				if b == l {
					a, b = b, a
					log.Debugf("Swapping.")
				}

				go func(a, b *IPList) {
					log.Debugf("Merging %s into %s.", b.name, a.name)
					a.Merge(b)
					intermediate_c <- a
					num_merges.Dec()
				}(a, b)
				a = nil
			}
		}
		wg.Done()
	}()

	already_merged := make(map[string]bool)
	for l_c := range c {
		log.Debugf("Received list %s for merging into %s..", l_c.name, l.name)
		name := l_c.name
		if _, ok := already_merged[name]; ok {
			log.Debugf("Was already merged (%s and %s).", l_c.name, l.name)
		} else {
			intermediate_c <- l_c
			num_merges.Inc()
			already_merged[name] = true
		}
	}
	done.Store(true)
	// wait for merges to finish and close channel (sending nil) afterwards
	for num_merges.Load() > 0 {
	}
	close(intermediate_c)
	log.Debugf("Retriving no more lists for merge into %s. Waiting to complete..", l.name)
	wg.Wait()
	log.Debugf("Merge from chan into %s completed.", l.name)
}

// Merge another list in this list
func (l *IPList) Merge(m *IPList) {
	// same list: nothing to do
	if l == m {
		return
	}

	// set mutex
	l.AquireWrite()
	m.AquireRead()
	defer l.DoneWrite()
	defer m.DoneRead()

	l.merge(m)
}

func (l *IPList) merge(m *IPList) {

	// Same list: nothing to do
	if l == m {
		return
	}

	// Initialize variables
	i, j := 0, 0
	l_len := l.len()
	m_len := m.len()

	log.Debugf("Merging %s into %s. Length are %d and %d.", m.name, l.name, m_len, l_len)

	// If l is empty, copy all contents of m's file into l's file
	if l_len == 0 {
		log.Debugf("%s is empty, copying %s into it.", m.name, l.name)
		err := helpers.CopyFile(m.filepath, l.filepath)
		if err != nil {
			log.Errorf("Error copying from %s to %s: %s", m.filepath, l.filepath, err)
		}
		log.Debugf("Copied %s into %s.", m.name, l.name)
		return
	}

	// If list, which is to be merged into l, is empty, we are done
	if m_len == 0 {
		log.Debugf("%s is empty, nothing to merge here.", m.name)
		return
	}

	// Creating new file to write to
	merged_list_path := parent_dir + "/merge_" + helpers.CalculateUUIDHash()
	merged_list, err := os.Create(merged_list_path)
	if err != nil {
		log.Errorf("Error creating file: %s", err)
	}
	defer merged_list.Close()

	merged_list_writer := bufio.NewWriter(merged_list)
	defer merged_list_writer.Flush()

	// Open listfiles and prepare for reading lines
	fl, err := os.Open(l.filepath)
	if err != nil {
		log.Errorf("Error opening file: %s", err)
	}
	defer fl.Close()
	fm, err := os.Open(m.filepath)
	if err != nil {
		log.Errorf("Error opening file: %s", err)
	}
	defer fm.Close()

	scanner_l := bufio.NewScanner(fl)
	buf_l := make([]byte, 0, 64*1024)
	scanner_l.Buffer(buf_l, max_reader_buffer_size)

	scanner_m := bufio.NewScanner(fm)
	buf_m := make([]byte, 0, 64*1024)
	scanner_m.Buffer(buf_m, max_reader_buffer_size)

	// read first lines
	scanner_l.Scan()
	if err := scanner_l.Err(); err != nil {
		log.Errorf("Error while scanning in merge(): %s", err)
	}
	ip_l, err := NewIPEntryFromLine(scanner_l.Text())
	if err != nil {
		log.Errorf("Error reading IP from line: %s", err)
	}

	scanner_m.Scan()
	if err := scanner_m.Err(); err != nil {
		log.Errorf("Error while scanning in merge(): %s", err)
	}
	ip_m, err := NewIPEntryFromLine(scanner_m.Text())
	if err != nil {
		log.Errorf("Error reading IP from line: %s", err)
	}

	// if sorted, merge
	if l.sorted.Load() {
		for i < l_len && j < m_len {
			if ip_l.Less(ip_m) {
				ip_l.WriteIPToWriter(merged_list_writer, true, true)
				if scanner_l.Scan() {
					ip_l, err = NewIPEntryFromLine(scanner_l.Text())
					if err != nil {
						log.Errorf("Error reading IP from line: %s", err)
					}
				}
				if err := scanner_l.Err(); err != nil {
					log.Errorf("Error while scanning in merge(): %s", err)
				}
				i++
			} else if ip_m.Less(ip_l) {
				ip_m.WriteIPToWriter(merged_list_writer, true, true)
				if scanner_m.Scan() {
					ip_m, err = NewIPEntryFromLine(scanner_m.Text())
					if err != nil {
						log.Errorf("Error reading IP from line: %s", err)
					}
				}
				if err := scanner_m.Err(); err != nil {
					log.Errorf("Error while scanning in merge(): %s", err)
				}
				j++
			} else if bytes.Equal(ip_l.GetIP(), ip_m.GetIP()) {
				ip_l.MergeComments(ip_m)
				ip_l.WriteIPToWriter(merged_list_writer, true, true)
				if scanner_l.Scan() {
					ip_l, err = NewIPEntryFromLine(scanner_l.Text())
					if err != nil {
						log.Errorf("Error reading IP from line: %s", err)
					}
				}
				if err := scanner_l.Err(); err != nil {
					log.Errorf("Error while scanning in merge(): %s", err)
				}
				i++
				if scanner_m.Scan() {
					ip_m, err = NewIPEntryFromLine(scanner_m.Text())
					if err != nil {
						log.Errorf("Error reading IP from line: %s", err)
					}
				}
				if err := scanner_m.Err(); err != nil {
					log.Errorf("Error while scanning in merge(): %s", err)
				}
				j++
			}
		}
	}
	log.Debugf("First step completed (%d, %d).", j, i)

	// append rest of one file or append if not sorted in the first place
	for i < l_len {
		ip_l.WriteIPToWriter(merged_list_writer, true, true)
		if scanner_l.Scan() {
			ip_l, err = NewIPEntryFromLine(scanner_l.Text())
			if err != nil {
				log.Errorf("Error reading IP from line: %s", err)
			}
		}
		if err := scanner_l.Err(); err != nil {
			log.Errorf("Error while scanning in merge(): %s", err)
		}
		i++
	}
	log.Debugf("Second step completed (%d, %d).", j, i)

	for j < m_len {
		ip_m.WriteIPToWriter(merged_list_writer, true, true)
		if scanner_m.Scan() {
			ip_m, err = NewIPEntryFromLine(scanner_m.Text())
			if err != nil {
				log.Errorf("Error reading IP from line: %s", err)
			}
		}
		if err := scanner_m.Err(); err != nil {
			log.Errorf("Error while scanning in merge(): %s", err)
		}
		j++
	}
	log.Debugf("Third step completed (%d, %d).", j, i)

	//rename merged file to be l's file (replaces old file)
	err = os.Rename(merged_list_path, l.filepath)
	if err != nil {
		log.Errorf("Error renaming file: %s", err)
	}
}

// Append another list to this list
func (l *IPList) Append(m *IPList) {

	l.AquireWrite()
	defer l.DoneWrite()

	m.AquireRead()
	defer m.DoneRead()

	l.append(m)
}

func (l *IPList) append(m *IPList) {

	// Opening file to append to and to append
	fl, err := os.OpenFile(l.filepath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Errorf("Error opening file: %s", err)
	}
	defer fl.Close()

	fm, err := os.Open(m.filepath)
	if err != nil {
		log.Errorf("Error opening file: %s", err)
	}
	defer fm.Close()

	// Scanner for reading m
	scanner_m := bufio.NewScanner(fm)
	buf_m := make([]byte, 0, 64*1024)
	scanner_m.Buffer(buf_m, max_reader_buffer_size)

	// Loop over m and append IP entries to l
	for scanner_m.Scan() {
		ip_m, err := NewIPEntryFromLine(scanner_m.Text())
		if err != nil {
			log.Errorf("Error reading IP from line: %s", err)
		}
		// Append IP to file
		_, err = fl.WriteString(fmt.Sprintf("%s\n", ip_m.ToOutput(true, true)))
		if err != nil {
			log.Errorf("Error appending IP address to file: %s", err)
		}
	}
	if err := scanner_m.Err(); err != nil {
		log.Errorf("Error while scanning in push(): %s", err)
	}
}

// Add an IP Entry to this list.
func (l *IPList) Push(x interface{}) {

	l.AquireWrite()
	defer l.DoneWrite()

	l.push(x)
}

func (l *IPList) push(x interface{}) {

	insert := x.(*IPEntry)

	//if l is sorted, insert the new ip in the right spot; append otherwise
	if l.sorted.Load() {
		// open listfile and prepare for reading lines
		fl, err := os.Open(l.filepath)
		if err != nil {
			log.Errorf("Error opening file: %s", err)
		}
		defer fl.Close()

		scanner_l := bufio.NewScanner(fl)
		buf_l := make([]byte, 0, 64*1024)
		scanner_l.Buffer(buf_l, max_reader_buffer_size)

		//create new file to write to
		push_list_path := parent_dir + "/pushsorted_" + helpers.CalculateUUIDHash()
		push_list, err := os.Create(push_list_path)
		if err != nil {
			log.Errorf("Error opening file: %s", err)
		}
		defer push_list.Close()

		push_list_writer := bufio.NewWriter(push_list)
		defer push_list_writer.Flush()

		//if list is empty, insert the new IP address directly
		if l.len() == 0 {
			insert.WriteIPToWriter(push_list_writer, true, true)
		} else {
			//loop over existing list file finding the correct position for insertion
			insert_written := false
			for scanner_l.Scan() {
				ip_l, err := NewIPEntryFromLine(scanner_l.Text())
				if err != nil {
					log.Errorf("Error reading IP from line: %s", err)
				}
				if !insert_written {
					if ip_l.Less(insert) {
						ip_l.WriteIPToWriter(push_list_writer, true, true)
					} else if insert.Less(ip_l) {
						insert.WriteIPToWriter(push_list_writer, true, true)
						ip_l.WriteIPToWriter(push_list_writer, true, true)
						insert_written = true
					} else if bytes.Equal(ip_l.GetIP(), insert.GetIP()) {
						ip_l.MergeComments(insert)
						ip_l.WriteIPToWriter(push_list_writer, true, true)
						insert_written = true
					}
				} else {
					ip_l.WriteIPToWriter(push_list_writer, true, true)
				}
			}
			if err := scanner_l.Err(); err != nil {
				log.Errorf("Error while scanning in push(): %s", err)
			}
			if !insert_written {
				insert.WriteIPToWriter(push_list_writer, true, true)
				insert_written = true
			}
		}

		//rename new file with pushed IP address to be l's file (replaces old file)
		err = os.Rename(push_list_path, l.filepath)
		if err != nil {
			log.Errorf("Error renaming file: %s", err)
		}
	} else {
		//opening file to append to
		push_list, err := os.OpenFile(l.filepath, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Errorf("Error opening file: %s", err)
		}
		defer push_list.Close()

		//write IP to file
		_, err = push_list.WriteString(fmt.Sprintf("%s\n", insert.ToOutput(true, true)))
		if err != nil {
			log.Errorf("Error appending IP address to file: %s", err)
		}
	}
}

// Insert a IP from string into this list.
func (l *IPList) Insert(ip string, key string, value interface{}) error {
	e, err := NewIPEntry(ip)
	if err != nil {
		return err
	}
	_ = e.AddComment(key, value)
	l.Push(e)

	return nil
}

// Insert a IP from string into this list and annotate it.
func (l *IPList) InsertWithAnnotate(ip string, key string, value interface{}) error {
	e, err := NewIPEntryWithAnnotate(ip)
	if err != nil {
		return err
	}
	_ = e.AddComment(key, value)
	l.Push(e)

	return nil
}

// Sort the list.
func (l *IPList) Sort() *IPList {
	l.AquireWrite()
	defer l.DoneWrite()

	return l.sort()
}

func (l *IPList) sort() *IPList {

	// Use Linux sort with memory limit

	log.Debugf("Sorting %s", l.name)

	// Initialize
	var ctx context.Context
	var cancel context.CancelFunc

	ctx, cancel = context.WithCancel(context.TODO())
	defer cancel()

	sorted_list_path := parent_dir + "/sorted_" + helpers.CalculateUUIDHash()
	sort_parameters := []string{l.filepath, "-o", sorted_list_path, "-u", "-S 5G"}
	sort_process := exec.CommandContext(ctx, "sort", sort_parameters...)

	sort_stdout, err := sort_process.StdoutPipe()
	if err != nil {
		log.Error(err)
	}
	defer sort_stdout.Close()

	sort_stderr, err := sort_process.StderrPipe()
	if err != nil {
		log.Error(err)
	}
	defer sort_stderr.Close()

	// Run process

	sort_process_wg := &sync.WaitGroup{}
	sort_process_wg.Add(1)
	go func() {
		defer sort_process_wg.Done()
		helpers.LogPipeProcess("sort", sort_stdout, log.Debug)
	}()

	sort_process_wg.Add(1)
	go func() {
		defer sort_process_wg.Done()
		helpers.LogPipeProcess("sort", sort_stderr, log.Error)
	}()

	err = sort_process.Start()
	if err != nil {
		log.Error(err)

	}
	sort_process_wg.Wait()

	err = sort_process.Wait()
	if err != nil {
		log.Error(err)
	}

	//rename sorted file to be l's file (replaces old file)
	err = os.Rename(sorted_list_path, l.filepath)
	if err != nil {
		log.Errorf("Error renaming file: %s", err)
	}

	l.sorted.Store(true)

	log.Debugf("Sorted %s", l.name)

	return l
}

// Iterate through the list to merge duplicate IP entries, i.e., merge their comments.
func (l *IPList) MergeDuplicateIPAddresses() {
	l.AquireWrite()
	defer l.DoneWrite()

	l.mergeDuplicateIPAddresses()
}

func (l *IPList) mergeDuplicateIPAddresses() {

	log.Debugf("Removing duplicates from list %s", l.name)

	if !l.sorted.Load() {
		log.Errorf("List %s is not sorted, so no duplicate removal possible", l.name)
		return
	}

	//initialize variables
	i := 0
	l_len := l.len()

	// nothing to do
	if l_len <= 1 {
		return
	}

	//creating new file to write to
	removed_duplicates_path := parent_dir + "/removed_duplicates_" + helpers.CalculateUUIDHash()
	removed_duplicate_list, err := os.Create(removed_duplicates_path)
	if err != nil {
		log.Errorf("Error creating file: %s", err)
	}
	defer removed_duplicate_list.Close()

	removed_duplicate_list_writer := bufio.NewWriter(removed_duplicate_list)
	defer removed_duplicate_list_writer.Flush()

	// open listfile and prepare for reading lines
	fl, err := os.Open(l.filepath)
	if err != nil {
		log.Errorf("Error opening file: %s", err)
	}
	defer fl.Close()

	scanner_l := bufio.NewScanner(fl)
	buf_l := make([]byte, 0, 64*1024)
	scanner_l.Buffer(buf_l, max_reader_buffer_size)

	// read first lines
	scanner_l.Scan()
	if err := scanner_l.Err(); err != nil {
		log.Errorf("Error while scanning in removeDuplicateIPAddresses(): %s", err)
	}
	ip_1, err := NewIPEntryFromLine(scanner_l.Text())
	if err != nil {
		log.Errorf("Error reading IP from line: %s", err)
	}
	i++

	scanner_l.Scan()
	if err := scanner_l.Err(); err != nil {
		log.Errorf("Error while scanning in removeDuplicateIPAddresses(): %s", err)
	}
	ip_2, err := NewIPEntryFromLine(scanner_l.Text())
	if err != nil {
		log.Errorf("Error reading IP from line: %s", err)
	}
	i++

	end := false

	for {
		//if we found a duplicate of IP addresses, merge them and look for further duplicate of that pair
		for bytes.Equal(ip_1.GetIP(), ip_2.GetIP()) {
			ip_1.MergeComments(ip_2)

			if i < l_len {
				scanner_l.Scan()
				if err := scanner_l.Err(); err != nil {
					log.Errorf("Error while scanning in removeDuplicateIPAddresses(): %s", err)
				}
				ip_2, err = NewIPEntryFromLine(scanner_l.Text())
				if err != nil {
					log.Errorf("Error reading IP from line: %s", err)
				}
				i++
			} else {
				end = true
				break
			}
		}
		ip_1.WriteIPToWriter(removed_duplicate_list_writer, true, true)

		if end {
			break
		}

		ip_1, err = NewIPEntryFromLine(scanner_l.Text())
		if err != nil {
			log.Errorf("Error reading IP from line: %s", err)
		}

		if i < l_len {
			scanner_l.Scan()
			if err := scanner_l.Err(); err != nil {
				log.Errorf("Error while scanning in removeDuplicateIPAddresses(): %s", err)
			}
			ip_2, err = NewIPEntryFromLine(scanner_l.Text())
			if err != nil {
				log.Errorf("Error reading IP from line: %s", err)
			}
			i++
		} else {
			ip_1.WriteIPToWriter(removed_duplicate_list_writer, true, true)
			break
		}

	}

	//rename removed duplicates file to be l's file (replaces old file)
	err = os.Rename(removed_duplicates_path, l.filepath)
	if err != nil {
		log.Errorf("Error renaming file: %s", err)
	}

	log.Debugf("Removed duplicates from list %s", l.name)
}

// Get a specific IP entry.
func (l *IPList) Get(i int) *IPEntry {
	l.AquireRead()
	defer l.DoneRead()

	// open listfile and prepare for reading lines
	fl, err := os.Open(l.filepath)
	if err != nil {
		log.Errorf("Error opening file: %s", err)
	}
	defer fl.Close()

	scanner_l := bufio.NewScanner(fl)
	buf_l := make([]byte, 0, 64*1024)
	scanner_l.Buffer(buf_l, max_reader_buffer_size)

	//loop over existing list file
	j := 0
	for scanner_l.Scan() {
		if i == j {
			ip_l, err := NewIPEntryFromLine(scanner_l.Text())
			if err != nil {
				log.Errorf("Error reading IP from line: %s", err)
			}
			return ip_l
		}
		j++
	}
	if err := scanner_l.Err(); err != nil {
		log.Errorf("Error while scanning in Get(): %s", err)
	}
	return nil
}

// Insert IP Entries from a channel.
func (l *IPList) InsertFromChan(c chan *IPEntry, workers int) {
	log.Debugf("Inserting IPs from channel")

	sort := l.sorted.Load()

	wg := &sync.WaitGroup{}
	iplist_c := make(chan *IPList, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			//creating new list and prepare writing to it
			target := NewIPList("InsertFromChan")

			//opening file to append to
			ftarget, err := os.OpenFile(target.filepath, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				log.Errorf("Error opening file: %s", err)
			}
			defer ftarget.Close()

			//write IP addresses from channel to file
			for e := range c {
				//write IP to file
				_, err = ftarget.WriteString(fmt.Sprintf("%s\n", e.ToOutput(true, true)))
				if err != nil {
					log.Errorf("Error appending IP address to file: %s", err)
				}
			}
			log.Debugf("Channel was closed.")
			if sort {
				target.sort()
			}
			target.sorted.Store(sort)

			iplist_c <- target
		}(i)
	}

	wg_merge := &sync.WaitGroup{}
	wg_merge.Add(1)
	go func() {
		defer wg_merge.Done()
		l.MergeFromChan(iplist_c)
	}()

	wg.Wait()
	close(iplist_c)
	wg_merge.Wait()

	log.Debugf("Insert from channel completed")
}

// Add a specific comment to all IPs within a list.
func (l *IPList) CommentAll(key string, value interface{}) *IPList {
	l.AquireWrite()
	defer l.DoneWrite()

	log.Debugf("CommentAll %s on list %s", key, l.name)

	//creating new file to write to
	commentall_path := parent_dir + "/commentall_" + helpers.CalculateUUIDHash()
	commentall_list, err := os.Create(commentall_path)
	if err != nil {
		log.Errorf("Error creating file: %s", err)
	}
	defer commentall_list.Close()

	commentall_list_writer := bufio.NewWriter(commentall_list)
	defer commentall_list_writer.Flush()

	// open listfile and prepare for reading lines
	fl, err := os.Open(l.filepath)
	if err != nil {
		log.Errorf("Error opening file: %s", err)
	}
	defer fl.Close()

	scanner_l := bufio.NewScanner(fl)
	buf_l := make([]byte, 0, 64*1024)
	scanner_l.Buffer(buf_l, max_reader_buffer_size)

	//loop over existing list file
	for scanner_l.Scan() {
		ip_l, err := NewIPEntryFromLine(scanner_l.Text())
		if err != nil {
			log.Errorf("Error reading IP from line: %s", err)
		}
		ip_l.AddComment(key, value)
		ip_l.WriteIPToWriter(commentall_list_writer, true, true)
	}
	if err := scanner_l.Err(); err != nil {
		log.Errorf("Error while scanning in CommentAll(): %s", err)
	}

	//rename new file to be l's file (replaces old file)
	err = os.Rename(commentall_path, l.filepath)
	if err != nil {
		log.Errorf("Error renaming file: %s", err)
	}

	log.Debugf("Finished CommentAll %s on list %s", key, l.name)

	return l
}

func (l *IPList) GetName() string {
	return l.name
}

func (l *IPList) GetFilepath() string {
	return l.filepath
}

func (l *IPList) getPerKey(key string, sort_lists bool, pathextension string, runnum int) []*IPList {

	log.Debugf("Getting per key on %s with key %s", l.name, key)

	// Initialize variables
	tmp_lists := make(map[interface{}]*IPList, 0)
	result := make([]*IPList, 0)

	// Open listfile and prepare for reading lines
	fl, err := os.Open(l.filepath)
	if err != nil {
		log.Errorf("Error opening file: %s", err)
	}
	defer fl.Close()

	scanner_l := bufio.NewScanner(fl)
	buf_l := make([]byte, 0, 64*1024)
	scanner_l.Buffer(buf_l, max_reader_buffer_size)

	// Loop over existing list file
	for scanner_l.Scan() {
		ip_l, err := NewIPEntryFromLine(scanner_l.Text())
		if err != nil {
			log.Errorf("Error reading IP from line: %s", err)
		}
		values := ip_l.GetComments(key)

		// Loop over values of key of comment
		for v := range values {
			var tmpList *IPList
			if l_tmp, ok := tmp_lists[v]; ok {
				tmpList = l_tmp
			} else {
				tmpList = NewIPListForGetPerKey(fmt.Sprintf("tmpListgetPerKey_%s", key), pathextension, runnum)
				tmpList.DisableSorting()
				tmp_lists[v] = tmpList
			}
			tmpList.push(ip_l)
		}
	}
	if err := scanner_l.Err(); err != nil {
		log.Errorf("Error while scanning in getPerKey(): %s", err)
	}

	for _, v := range tmp_lists {
		if sort_lists {
			v.sort()
		}
		result = append(result, v)
	}

	log.Debugf("Got per key on %s with key %s", l.name, key)

	return result
}

// Get all IP Entries with a specific key.
func (l *IPList) GetPerKey(key string, sort_lists bool, pathexttension string, runnum int) []*IPList {
	l.AquireRead()
	defer l.DoneRead()

	return l.getPerKey(key, sort_lists, pathexttension, runnum)
}

func (l *IPList) getOnePerKey(key string, valueExcept []interface{}, maxNum int, pathextension string, runnum int) *IPList {

	log.Debugf("Getting one per key on %s with key %s", l.name, key)

	lists := l.getPerKey(key, false, pathextension, runnum)

	result := NewIPList(fmt.Sprintf("getOnePerKey_%s", key))
	result.DisableSorting()

E:
	for _, tmp_l := range lists {
		ip_entry := tmp_l.GetRandomIPEntry()
		if ip_entry == nil {
			log.Warnf("nil IPEntry returned from GetRandomIPEntry() on list %s", l.name)
			continue
		}
		values := ip_entry.GetComments(key)
		for _, e := range valueExcept {
			_, ok := values[e]
			if ok {
				result.append(tmp_l.GetRandom(maxNum))
				continue E
			}
		}
		result.push(ip_entry)
	}

	result.sort()
	result.mergeDuplicateIPAddresses()

	log.Debugf("Got one per key on %s with key %s", l.name, key)

	if result.len() == 0 {
		result = nil
	}

	return result
}

// Get the first maxNum IP Entries per key.
func (l *IPList) GetOnePerKey(key string, valueExcept []interface{}, maxNum int, pathextension string, runnum int) *IPList {
	l.AquireRead()
	defer l.DoneRead()

	return l.getOnePerKey(key, valueExcept, maxNum, pathextension, runnum)
}

// Get random maxNum IP Entries per key.
func (l *IPList) GetRandomPerKey(key string, max int, pathextension string, runnum int) []*IPList {
	l.AquireRead()
	defer l.DoneRead()

	return l.getRandomPerKey(key, max, pathextension, runnum)
}

func (l *IPList) getRandomPerKey(key string, max int, pathextension string, runnum int) []*IPList {
	result := make([]*IPList, 0)

	for _, k := range l.getPerKey(key, true, pathextension, runnum) {
		result = append(result, k.GetRandom(max))
	}

	return result
}

// Get random max IP Entries from complete list.
func (l *IPList) GetRandom(max int) *IPList {
	l.AquireRead()
	defer l.DoneRead()

	log.Debugf("Getting %d entries from list %s", max, l.name)

	l_len := l.len()

	if max <= l_len {

		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		marked_list := NewIPList(fmt.Sprintf("GetRandom_%d", max))
		marked_list.DisableSorting()

		rand_map := make(map[int]bool)
		rand_num := 0
		for rand_num < max {
			l := r.Intn(l_len)
			if !rand_map[l] {
				rand_map[l] = true
				rand_num++
			}
		}

		// open listfile and prepare for reading lines
		fl, err := os.Open(l.filepath)
		if err != nil {
			log.Errorf("Error opening file: %s", err)
		}
		defer fl.Close()

		scanner_l := bufio.NewScanner(fl)
		buf_l := make([]byte, 0, 64*1024)
		scanner_l.Buffer(buf_l, max_reader_buffer_size)

		//iterate over list and get all IP addresses that are marked in the random map
		i := 0
		marked := 0
		for scanner_l.Scan() {
			_, s := rand_map[i]
			if s {
				ip_l, err := NewIPEntryFromLine(scanner_l.Text())
				if err != nil {
					log.Errorf("Error reading IP from line: %s", err)
				}
				marked_list.push(ip_l)
				marked++
			}
			i++
		}
		if err := scanner_l.Err(); err != nil {
			log.Errorf("Error while scanning in GetRandom(): %s", err)
		}

		marked_list.sort()

		log.Debugf("Got %d entries from list %s", marked, l.name)

		return marked_list
	} else {
		log.Infof("Tried to select more IPs randomly than in list %s. returning copy of list", l.name)

		return_list := NewIPList(fmt.Sprintf("GetRandom_%d", l_len))
		return_list.DisableSorting()

		// open listfile and prepare for reading lines
		fl, err := os.Open(l.filepath)
		if err != nil {
			log.Errorf("Error opening file: %s", err)
		}
		defer fl.Close()

		scanner_l := bufio.NewScanner(fl)
		buf_l := make([]byte, 0, 64*1024)
		scanner_l.Buffer(buf_l, max_reader_buffer_size)

		//loop over file
		for scanner_l.Scan() {
			ip_l, err := NewIPEntryFromLine(scanner_l.Text())
			if err != nil {
				log.Errorf("Error reading IP from line: %s", err)
			}
			return_list.push(ip_l)
		}
		if err := scanner_l.Err(); err != nil {
			log.Errorf("Error while scanning in CommentAll(): %s", err)
		}

		return_list.sort()

		log.Infof("Returned list %s with %d entries", l.name, l_len)

		return return_list
	}
}

// Get a single random IP Entry.
func (l *IPList) GetRandomIPEntry() *IPEntry {
	l.AquireRead()
	defer l.DoneRead()

	l_len := l.len()

	if l_len == 0 {
		return nil
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	rand_int := r.Intn(l_len)

	// open listfile and prepare for reading lines
	fl, err := os.Open(l.filepath)
	if err != nil {
		log.Errorf("Error opening file: %s", err)
	}
	defer fl.Close()

	scanner_l := bufio.NewScanner(fl)
	buf_l := make([]byte, 0, 64*1024)
	scanner_l.Buffer(buf_l, max_reader_buffer_size)

	//iterate over list and get all IP addresses that are marked in the random map
	var ip_l *IPEntry
	i := 0
	for scanner_l.Scan() {
		if i == rand_int {
			ip_l, err = NewIPEntryFromLine(scanner_l.Text())
			if err != nil {
				log.Errorf("Error reading IP from line: %s", err)
			}
			break
		}
		i++
	}
	if err := scanner_l.Err(); err != nil {
		log.Errorf("Error while scanning in GetRandom(): %s", err)
	}

	return ip_l
}

// Get all IPs.
func (l *IPList) GetAllIPs(ctx context.Context, c chan *IPEntry) {
	l.AquireRead()
	defer l.DoneRead()

	l.getAllIPs(ctx, c)
}

func (l *IPList) getAllIPs(ctx context.Context, c chan *IPEntry) {
	// open listfile and prepare for reading lines
	fl, err := os.Open(l.filepath)
	if err != nil {
		log.Errorf("Error opening file: %s", err)
	}
	defer fl.Close()

	scanner_l := bufio.NewScanner(fl)
	buf_l := make([]byte, 0, 64*1024)
	scanner_l.Buffer(buf_l, max_reader_buffer_size)

	//loop over existing list file
	for scanner_l.Scan() {
		ip_l, err := NewIPEntryFromLine(scanner_l.Text())
		if err != nil {
			log.Errorf("Error reading IP from line: %s", err)
		}
		select {
		case <-ctx.Done():
			return
		default:
			c <- ip_l
		}
	}
	if err := scanner_l.Err(); err != nil {
		log.Errorf("Error while scanning in GetAllIPs(): %s", err)
	}
}

// Get number of IP addresses per key.
func (l *IPList) GetNumberPerKey() map[string]int {
	l.AquireRead()
	defer l.DoneRead()

	return l.getNumberPerKey()
}

func (l *IPList) getNumberPerKey() map[string]int {
	num_workers := 10

	result := make(map[string]int)

	c_in := make(chan *IPEntry, 1000000)
	c_out := make(chan map[string]int, num_workers)

	for i := 0; i < num_workers; i++ {
		go func() {
			result_inner := make(map[string]int)

			for ip := range c_in {
				for _, k := range ip.GetCommentKeys() {
					result_inner[k]++
				}
			}

			c_out <- result_inner
		}()
	}

	l.getAllIPs(context.TODO(), c_in)
	close(c_in)

	for i := 0; i < num_workers; i++ {
		r := <-c_out
		for k, v := range r {
			result[k] = result[k] + v
		}
	}

	return result
}

// Shuffle complete list.
func (l *IPList) Shuffle() {
	l.AquireWrite()
	defer l.DoneWrite()

	// Use Linux shuf

	log.Debugf("Shuffling %s", l.name)

	// Initialize
	var ctx context.Context
	var cancel context.CancelFunc

	ctx, cancel = context.WithCancel(context.TODO())
	defer cancel()

	shuffled_list_path := parent_dir + "/shuffled_" + helpers.CalculateUUIDHash()
	shuf_parameters := []string{l.filepath, "-o", shuffled_list_path}
	shuf_process := exec.CommandContext(ctx, "shuf", shuf_parameters...)

	shuf_stdout, err := shuf_process.StdoutPipe()
	if err != nil {
		log.Error(err)
	}
	defer shuf_stdout.Close()

	shuf_stderr, err := shuf_process.StderrPipe()
	if err != nil {
		log.Error(err)
	}
	defer shuf_stderr.Close()

	// Run process

	shuf_process_wg := &sync.WaitGroup{}
	shuf_process_wg.Add(1)
	go func() {
		defer shuf_process_wg.Done()
		helpers.LogPipeProcess("shuf", shuf_stdout, log.Debug)
	}()

	shuf_process_wg.Add(1)
	go func() {
		defer shuf_process_wg.Done()
		helpers.LogPipeProcess("shuf", shuf_stderr, log.Error)
	}()

	err = shuf_process.Start()
	if err != nil {
		log.Error(err)
	}

	shuf_process_wg.Wait()

	err = shuf_process.Wait()
	if err != nil {
		log.Error(err)
	}

	//rename shuffled file to be l's file (replaces old file)
	err = os.Rename(shuffled_list_path, l.filepath)
	if err != nil {
		log.Errorf("Error renaming file: %s", err)
	}

	l.sorted.Store(false)

	log.Debugf("Shuffled %s", l.name)
}

// Write list to writer.
func (l *IPList) WriteToFD(fd io.Writer, colons bool, withComments bool) error {

	l.AquireRead()
	defer l.DoneRead()

	//open listfile and prepare for reading lines
	fl, err := os.Open(l.filepath)
	if err != nil {
		log.Errorf("Error opening file: %s", err)
	}
	defer fl.Close()

	scanner_l := bufio.NewScanner(fl)
	buf_l := make([]byte, 0, 64*1024)
	scanner_l.Buffer(buf_l, max_reader_buffer_size)

	//loop over existing list file
	for scanner_l.Scan() {
		ip_l, err := NewIPEntryFromLine(scanner_l.Text())
		if err != nil {
			log.Errorf("Error reading IP from line: %s", err)
		}
		_, err = io.WriteString(fd, fmt.Sprintf("%s\n", ip_l.ToOutput(colons, withComments)))
		if err != nil {
			return err
		}
	}
	if err := scanner_l.Err(); err != nil {
		log.Errorf("Error while scanning in WriteToFD(): %s", err)
	}

	return nil
}

// Write list to zstd compressed file
func (l *IPList) WriteRunList(path string, withColons bool, withComments bool) {
	l.AquireRead()
	defer l.DoneRead()

	log.Debugf("Writing run file to %s", path)

	f_out, err := os.Create(path)
	if err != nil {
		log.Errorf("Error opening file: %s", err)
	}
	defer f_out.Close()

	gf, err := zstd.NewWriter(f_out)
	if err != nil {
		log.Errorf("Error opening zstd writer: %s", err)
	}
	defer gf.Close()

	w := bufio.NewWriter(gf)
	defer w.Flush()

	l.WriteToFD(w, withColons, withComments)
}

// Write header with string values to file
func writeStringMapToHeader(fd io.Writer, title string, m map[string]string) {
	var err error

	_, err = io.WriteString(fd, fmt.Sprintf("##### %s #####\n", title))
	if err != nil {
		log.Errorf("Error writing to map to header: %s", err)
	}
	for k, v := range m {
		_, err = io.WriteString(fd, fmt.Sprintf("# %s - %s\n", k, v))
		if err != nil {
			log.Errorf("Error writing to map to header: %s", err)
		}
	}
	_, err = io.WriteString(fd, "##################\n")
	if err != nil {
		log.Errorf("Error writing to map to header: %s", err)
	}
}

// Write header with int values to file
func writeIntMapToHeader(fd io.Writer, title string, m map[string]int) {
	var err error

	_, err = io.WriteString(fd, fmt.Sprintf("##### %s #####\n", title))
	if err != nil {
		log.Errorf("Error writing to map to header: %s", err)
	}
	for k, v := range m {
		_, err = io.WriteString(fd, fmt.Sprintf("# %s - %d\n", k, v))
		if err != nil {
			log.Errorf("Error writing to map to header: %s", err)
		}
	}
	_, err = io.WriteString(fd, "##################\n")
	if err != nil {
		log.Errorf("Error writing to map to header: %s", err)
	}
}

// Write final scan list to zstd file, i.e., shuffle the list before writing it to disk.
func (l *IPList) WriteFinalScanList(ppath string) {

	// Shuffle final list for later scanning
	l.Shuffle()

	l.AquireRead()
	defer l.DoneRead()

	log.Debugf("Writing final scanlist to %s", ppath)
	tmppath := fmt.Sprintf("%s.tmp", ppath)

	os.MkdirAll(path.Dir(ppath), os.ModePerm)

	// Initialize zstd process
	cpu_num := int(runtime.NumCPU() * 3 / 4)

	zstd_parameters := []string{fmt.Sprintf("-T%d", cpu_num), "-", "-o", tmppath}
	zstd_process := exec.Command("zstd", zstd_parameters...)

	zstd_stdout, err := zstd_process.StdoutPipe()
	if err != nil {
		log.Error(err)
	}
	defer zstd_stdout.Close()

	zstd_stderr, err := zstd_process.StderrPipe()
	if err != nil {
		log.Error(err)
	}
	defer zstd_stdout.Close()

	zstd_stdin, err := zstd_process.StdinPipe()
	if err != nil {
		log.Error(err)
	}
	zstd_stdin_buffer := bufio.NewWriter(zstd_stdin)

	log.Debugf("Writing final scanlist to %s", tmppath)

	// Run zstd process
	zstd_process_wg := &sync.WaitGroup{}
	zstd_process_wg.Add(1)
	go func() {
		defer zstd_process_wg.Done()
		helpers.LogPipeProcess("zstd", zstd_stdout, log.Debug)
	}()

	zstd_process_wg.Add(1)
	go func() {
		defer zstd_process_wg.Done()
		helpers.LogPipeProcess("zstd", zstd_stderr, log.Error)
	}()

	err = zstd_process.Start()
	if err != nil {
		log.Error(err)
	}

	log.Debugf("Writing header")

	writeIntMapToHeader(zstd_stdin_buffer, "KEYVAL", l.getNumberPerKey())
	log.Debugf("Writing scanlist", ppath)

	fd2, err := os.Open(l.filepath)
	if err != nil {
		log.Errorf("Error opening list file: %s", err)
	}
	defer fd2.Close()

	buffer_fd2 := bufio.NewReader(fd2)

	io.Copy(zstd_stdin_buffer, buffer_fd2)

	zstd_stdin_buffer.Flush()
	zstd_stdin.Close()

	zstd_process_wg.Wait()

	err = zstd_process.Wait()
	if err != nil {
		log.Errorf("zstd error: %s", err)
	}

	log.Debugf("Renaming final scanlist to %s", ppath)
	os.Chmod(tmppath, 0644)
	os.Rename(tmppath, ppath)

	log.Debugf("Compressed file %s to %s", l.filepath, ppath)
}

// Get hash of list, i.e., incl. all headers, IP addresses and comments.
func (l *IPList) GetHash() string {
	l.AquireRead()
	defer l.DoneRead()

	h := sha256.New()
	if !l.sorted.Load() {
		log.Warnf("Generated hash on unsorted list!")
	}
	l.WriteToFD(h, false, false)
	return hex.EncodeToString(h.Sum(nil))
}
