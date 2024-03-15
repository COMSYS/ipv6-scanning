package generators

import (
	"bufio"
	"fmt"
	"io"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/helpers"
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"
)

const max_reader_buffer_size = 500 * 1024 * 1024 // 500 MB max size of single line

// Convert hex output of generators to string
func WriteHexToIPSlice(slice *[]string, pipe io.Reader) {
	var ip string

	scanner := bufio.NewScanner(pipe)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, max_reader_buffer_size)

	for scanner.Scan() {
		l := scanner.Text()
		if len(l) == 32 {
			ip = fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s:%s", l[0:4], l[4:8], l[8:12], l[12:16], l[16:20], l[20:24], l[24:28], l[28:])
		} else {
			ip = l
		}

		*slice = append(*slice, ip)
	}
	if err := scanner.Err(); err != nil {
		log.Errorf("Error while scanning in WriteHexToIPSlice(): %s", err)
	}
}

// Write IPs from channel to a writer object, e.g., the stdin of generators.
func WriteIPChanToWriter(writer io.Writer, c chan *iplist.IPEntry, colons bool) {
	for v := range c {
		ip_str := v.ToOutput(colons, false)

		written, err := writer.Write([]byte(fmt.Sprintf("%s\n", ip_str)))
		if written < len(ip_str)+1 {
			log.Warnf("Written less bytes than expected (%d instead of %d)", written, len(ip_str)+1)
		}
		if err != nil {
			log.Error(err)
		}
	}
}

// Create IPEntry object from reader (one IP per line) and push it to channel. The entry is tagged with the generators name.
func SendHexOutputToIPChan(generator_name string, c chan *iplist.IPEntry, in io.Reader) {
	scanner := bufio.NewScanner(in)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, max_reader_buffer_size)

	for scanner.Scan() {
		ip, err := iplist.NewIPEntry(scanner.Text())
		if err != nil {
			log.Warnf("Error while parsing new IP entry from generator %s: %s", generator_name, err)
		} else {
			c <- ip
		}
	}
	if err := scanner.Err(); err != nil {
		log.Errorf("Error while scanning in SendHexOutputToIPChan() with generator %s: %s", generator_name, err)
	}
}

// Some generatores have wildcards in their output. This function inserts all IP addresses in the channel.
func GetIPAddressesFromRegions(generator_name string, c chan *iplist.IPEntry, in io.Reader, name string, num int) {
	scanner := bufio.NewScanner(in)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, max_reader_buffer_size)

	region_map := make(map[int][]string)

	// Insert regions into map
	for scanner.Scan() {
		region := scanner.Text()

		size := strings.Count(region, "*")

		region_map[size] = append(region_map[size], region)

	}
	if err := scanner.Err(); err != nil {
		log.Errorf("Error while scanning in getting GetIPAddressesFromRegions() with generator %s: %s", generator_name, err)
	}

	// Sort keys, aka sizes, of regions
	sizes := make([]int, 0, len(region_map))
	for size := range region_map {
		sizes = append(sizes, size)
	}
	sort.Ints(sizes)

	generated_ipaddresses := 0

E:
	// Get regions from region_map, starting with the smallest regions
	for _, size := range sizes {

		region_slice := region_map[size]

		// Shuffle regions of same size
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		r.Shuffle(len(region_slice), func(i, j int) { region_slice[i], region_slice[j] = region_slice[j], region_slice[i] })

		for _, region := range region_slice {

			// For each region extract IP adresses until num is reached globally (for this run)
			var increasing_nybbles = make([]int, size)

			for i := range increasing_nybbles {
				increasing_nybbles[i] = 0
			}

			// Increase increasing_nybbles slice step by step and extract according IP address each
			i := 0
			for {
				for z := 0; z < 16; z++ {
					if generated_ipaddresses < num {
						ip := GetIPAddressFromRegionAndSlice(generator_name, region, increasing_nybbles)
						if ip != nil {
							c <- ip
							generated_ipaddresses++
						}
						increasing_nybbles[i]++
					} else {
						break E
					}
				}

				finished := false
				for j := range increasing_nybbles {
					if increasing_nybbles[j] == 16 {

						if j == len(increasing_nybbles)-1 {
							finished = true
							break
						}

						if j+1 < len(increasing_nybbles) {
							increasing_nybbles[j] = 0
							increasing_nybbles[j+1]++
						}
					}
				}

				if finished {
					break
				}
			}
		}
	}
}

// Some generators have regions in their output but do use rages, e.g., [a-f], instead of wildcards
func GetIPAddressFromRegionAndSlice(generator_name string, region string, increasing_nybless []int) *iplist.IPEntry {
	var ip_string string

	i := 0
	for j := range region {
		if string(region[j]) == "*" {
			ip_string = fmt.Sprintf("%s%s", ip_string, strconv.FormatInt(int64(increasing_nybless[i]), 16))
			i++
		} else {
			ip_string = fmt.Sprintf("%s%s", ip_string, string(region[j]))
		}
	}

	ip, err := iplist.NewIPEntry(ip_string)
	if err != nil {
		log.Warnf("Error while parsing new IP entry in GetIPAddressFromRegionAndSlice() with generator %s: %s", generator_name, err)
		return nil
	} else {
		return ip
	}
}

// Function to conveniently get one of the generators.
func NewGenerator(generatortype string, folder string, name string, resourcepools []*helpers.ResourcePool, options interface{}) Generator {
	log.Debugf("New %s generator: %s", generatortype, name)

	switch generatortype {
	case "6gen":
		return NewSixGen("/third_party/generators/6gen", folder, name, resourcepools)
	case "eip":
		return NewEntropyIp("/third_party/generators/entropyip", folder, name, resourcepools)
	case "eipgen":
		return NewEipGenerator("/third_party/generators/eipgenerator", folder, name, resourcepools)
	case "6gan":
		return NewSixGan("/third_party/generators/6GAN", folder, name, resourcepools, options)
	case "6gcvae":
		return NewSixGcVae("/third_party/generators/6GCVAE", folder, name, resourcepools, options)
	case "6veclm":
		return NewSixVecLm("/third_party/generators/6VecLM", folder, name, resourcepools)
	case "6graph":
		return NewSixGraph("/third_party/generators/6Graph", folder, name, resourcepools)
	case "6forest":
		return NewSixForest("/third_party/generators/6Forest", folder, name, resourcepools)
	}

	return nil
}

// This function calls fn for every line in the in reader.
func LogPipe(prefix string, in io.Reader, fn func(...interface{})) {
	scanner := bufio.NewScanner(in)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, max_reader_buffer_size)

	for scanner.Scan() {
		fn(prefix, ": ", scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Errorf("Error while scanning output from logpipe of generator %s: %s", prefix, err)
	}
}
