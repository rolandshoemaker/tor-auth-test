package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/letsencrypt/net/publicsuffix"
	"github.com/miekg/dns"
	ct "github.com/rolandshoemaker/certificatetransparency"
	ctCommon "github.com/rolandshoemaker/ctat/common"
)

type result struct {
	TorError    string
	NormalError string

	Started    time.Time
	TorTook    time.Duration
	NormalTook time.Duration
}

type tester struct {
	workers int
	results chan *result
	names   chan string

	torResolver    string
	normalResolver string
	client         *dns.Client
}

func (t *tester) processName(name string) {
	r := &result{}
	msg := new(dns.Msg)
	msg.SetEdns0(4096, true)
	msg.SetQuestion(dns.Fqdn(name), dns.TypeA)

	wg := new(sync.WaitGroup)
	r.Started = time.Now()
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { r.NormalTook = time.Since(r.Started) }()
		resp, _, err := t.client.Exchange(msg, t.normalResolver)
		if err != nil {
			r.NormalError = err.Error()
		} else if resp.Rcode == dns.RcodeServerFailure {
			r.NormalError = fmt.Sprintf("%s", dns.RcodeToString[resp.Rcode])
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { r.TorTook = time.Since(r.Started) }()
		resp, _, err := t.client.Exchange(msg, t.torResolver)
		if err != nil {
			r.TorError = err.Error()
		} else if resp.Rcode == dns.RcodeServerFailure {
			r.TorError = fmt.Sprintf("%s", dns.RcodeToString[resp.Rcode])
		}
	}()
	wg.Wait()

	if r.NormalError != "" && r.NormalError == r.TorError {
		return
	}
	t.results <- r
}

func (t *tester) run() {
	t.results = make(chan *result, len(t.names))
	wg := new(sync.WaitGroup)
	stopProg := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-stopProg:
				return
			default:
				fmt.Printf("\x1b[80D\x1b[2K%d remaining", len(t.names))
				time.Sleep(250 * time.Millisecond)
			}
		}
	}()
	for i := 0; i < t.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range t.names {
				t.processName(name)
			}
		}()
	}
	wg.Wait()
	stopProg <- struct{}{}
	fmt.Println("")
}

func (t *tester) dump() error {
	close(t.results)
	results := []*result{}
	for r := range t.results {
		results = append(results, r)
	}
	data, err := json.Marshal(results)
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

var dnsTimeout = time.Second * 10

func main() {
	cacheFile := flag.String("ctFile", "", "")
	nameFile := flag.String("nameFile", "", "")
	normalResolver := flag.String("normalResolver", "127.0.0.1:53", "")
	torResolver := flag.String("torResolver", "127.0.0.1:9053", "")
	workers := flag.Int("workers", 1, "")
	flag.Parse()

	if *cacheFile == "" && *nameFile == "" {
		fmt.Println("Either --ctFile or --nameFile is required")
		os.Exit(1)
	}

	t := tester{
		workers:        *workers,
		client:         &dns.Client{DialTimeout: dnsTimeout, ReadTimeout: dnsTimeout, Net: "tcp"},
		normalResolver: *normalResolver,
		torResolver:    *torResolver,
	}

	if *cacheFile != "" {
		ctEntries, err := ctCommon.LoadCacheFile(*cacheFile)
		if err != nil {
			fmt.Printf("Failed to load CT cache file: %s\n", err)
			os.Exit(1)
		}

		names := make(map[string]struct{})
		mu := new(sync.Mutex)
		ctEntries.Map(func(ent *ct.EntryAndPosition, err error) {
			if err != nil || ent.Entry.Type != ct.X509Entry {
				return
			}
			cert, _, err := ctCommon.ParseAndFilter(ent.Entry.X509Cert, nil)
			if err != nil {
				return
			}
			for _, name := range cert.DNSNames {
				eTLD, err := publicsuffix.EffectiveTLDPlusOne(name)
				if err != nil {
					continue
				}
				mu.Lock()
				if _, present := names[eTLD]; !present {
					names[eTLD] = struct{}{}
				}
				mu.Unlock()
			}
		})

		numNames := len(names)
		t.names = make(chan string, numNames)
		t.results = make(chan *result, numNames)
		for name := range names {
			t.names <- name
		}
	}
	if *nameFile != "" {
		data, err := ioutil.ReadFile(*nameFile)
		if err != nil {
			fmt.Printf("Failed to read name file: %s\n", err)
			os.Exit(1)
		}
		names := strings.Split(string(data), "\n")
		numNames := len(names)
		t.names = make(chan string, numNames)
		t.results = make(chan *result, numNames)
		for _, name := range names {
			t.names <- name
		}
	}
	close(t.names)

	t.run()
	t.dump()
}
