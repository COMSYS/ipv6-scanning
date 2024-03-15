package main

import (
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	_ "net/http/pprof"

	"github.com/akamensky/argparse"
	log "github.com/sirupsen/logrus"

	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/annotators"
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/getter"
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/helpers"
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/iplist"
	"github.com/COMSYS/ipv6-scanning/ipv6-scanlist-generator/pkg/sequence"
)

const TITLE = "ipv6-scanlist-generator"

func main() {
	// Create new parser object
	parser := argparse.NewParser(TITLE, "Generate a single scanlist by address generation seeded from different sources.")
	// Create string flag
	t := parser.String("t", "tmpdir", &argparse.Options{Required: false, Help: "Path to tmp folder.", Default: "/tmp"})
	l := parser.String("l", "logdir", &argparse.Options{Required: false, Help: "Path to log folder.", Default: "/log"})
	i := parser.String("i", "sourcelists", &argparse.Options{Required: false, Help: "Path to sourcelist folder.", Default: "/sourcelists"})
	c := parser.String("c", "cachedir", &argparse.Options{Required: false, Help: "Path to cache folder.", Default: "/cache"})

	o := parser.String("o", "scanlists", &argparse.Options{Required: false, Help: "Path to scanlist folder.", Default: "/scanlists"})
	d := parser.Selector("d", "debug-level", []string{"INFO", "DEBUG", "WARN"}, &argparse.Options{Required: false, Help: "Log Level", Default: "DEBUG"})
	a := parser.Flag("a", "annotate", &argparse.Options{Required: false, Help: "Disable annotating IPs.", Default: false})

	p := parser.String("p", "protocols", &argparse.Options{Required: false, Help: "Protocols to filter database for (v4 only).", Default: "none"})
	g := parser.String("g", "getters", &argparse.Options{Required: false, Help: "Enabled getters.", Default: "tum"})

	gpus := parser.String("", "gpus", &argparse.Options{Required: false, Help: "GPUs to use. If set to -1, none are used.", Default: "-1"})
	// dns := parser.String("", "dns", &argparse.Options{Required: false, Help: "DNS resolver to use. Requires DNS via TCP."})

	// Parse input
	err := parser.Parse(os.Args)
	if err != nil {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Print(parser.Usage(err))
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")

	var log_writer io.Writer
	f_log, err := os.Create(path.Join(*l, fmt.Sprintf("%s-%s.log", TITLE, timestamp)))
	if err != nil {
		log.Warnf("Unable to write log to file. Unable to create logfile: %s", err)
		log_writer = os.Stdout
	} else {
		log_writer = io.MultiWriter(os.Stdout, f_log)
	}
	log.SetOutput(log_writer)

	var annotators_list []annotators.Annotator

	loglevel, err := log.ParseLevel(*d)
	if err != nil {
		log.Fatalf("Specified log level not allowed: %s", *d)
	}
	log.SetLevel(loglevel)

	if !*a {
		log.Info("Annotating enabled. Initializing annotators.")

		wg_annotator_init := &sync.WaitGroup{}

		aliasing_annotator := annotators.NewAliasingAnnotator("https://alcatraz.net.in.tum.de/ipv6-hitlist-service/registered/apd/", "TUM_USERNAME", "TUM_PASSWORD", path.Join(*i, "tum"))
		annotators_list = append(annotators_list, aliasing_annotator)

		for _, a := range annotators_list {
			wg_annotator_init.Add(1)
			go func(a annotators.Annotator) {
				a.Init()
				iplist.AddAnnotator(a.Annotate)
				wg_annotator_init.Done()
			}(a)
		}
		wg_annotator_init.Wait()
		log.Info("Annotating enabled. Initialized annotators.")
	}

	// Create our root sequence to generate IPs to scan
	seq := sequence.NewSequence("rootsequence")

	// Create GPU resource pools
	pools := make([]*helpers.ResourcePool, 0)
	if *gpus != "-1" {
		var gpus_int []interface{}
		for _, gpu_id := range strings.Split(*gpus, ",") {
			gpus_int = append(gpus_int, gpu_id)
		}
		pools = append(pools, helpers.NewResourcePool("gpu", gpus_int))
	}

	// Create protocol list from Input
	protocol_list := strings.Split(*p, ",")

	// Convert input of getters from string to pointer to slice of strings
	g_split := strings.Split(*g, ",")
	g_sl := &g_split

	// Add a new step to the list generation. In this example, we download the openly available TUM hitlist and add Entropy/IP and EIP as generators.
	if slices.Contains(*g_sl, "tum") {
		opentum_getter := getter.NewTum("opentum", "https://alcatraz.net.in.tum.de/ipv6-hitlist-service/open/responsive-addresses.txt.xz", "", "", "")
		seq.AddNextStep("opentum", "getter", &sequence.GetterOption{Getter: opentum_getter})

		// ### Entropy/IP ###
		seq.AddNextStep("eip-random", "selection", &sequence.SelectionOption{Innertype: "random", Num: 100000, Runs: 3, CachePath: *c}).
			AddNextStep("geneip", "generator", &sequence.GeneratorOption{Innertype: "eip", Num: 10000000, TmpPath: *t, ResourcePools: pools, CachePath: *c}).
			AddNextStep("geneipgen", "generator", &sequence.GeneratorOption{Innertype: "eipgen", Num: 10000000, CachePath: *c})
	}

	// This is the final merge step, i.e., it merges the list of the several branches of our build sequence together.
	seq.AddLastJoinStep("final", "merge", nil)

	log.Info("Constructed sequence:")
	seq.PrintSequence()

	log.Info("Starting sequence.")
	seq.Start()
	log.Info("Started. Waiting for completion..")
	seq.Wait()
	log.Info("Sequence done.")

	scanlist := seq.GetLastIPList()
	log.Infof("Starting to write final scanlist from file %s...", scanlist.GetFilepath())
	scanlist.WriteFinalScanList(path.Join(*o, fmt.Sprintf("%s_scan_%s.txt.zst", timestamp, strings.Join(protocol_list, "-"))))

	log.Info("Done. Goodbye.")
}
