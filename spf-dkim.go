package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strings"

	"github.com/mileusna/spf"
	"github.com/toorop/go-dkim"
)

const (
	recievedRegExp = `(?i)^Received:\s+from\s+`
	fromRegExp     = `(?i)^From:.+@.+$` // From: Quora Digest <english-personalized-digest@quora.com>
)

var (
	recievedCheck *regexp.Regexp
	fromCheck     *regexp.Regexp
)

func init() {
	var err error
	recievedCheck, err = regexp.Compile(recievedRegExp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cann't compile recievedRegExp. Exiting... %s\n", err.Error())
		os.Exit(500)
	}

	fromCheck, err = regexp.Compile(fromRegExp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cann't compile fromRegExp. Exiting... %s\n", err.Error())
		os.Exit(501)
	}
}

func chkParams() string {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "ERROR: Expect email file like a prarmeter\n")
		os.Exit(1)
	}

	if _, err := os.Stat(os.Args[1]); err == nil {
		fmt.Printf("Processing email %s ...\n", os.Args[1])
	} else {
		fmt.Fprintf(os.Stderr, "ERROR %s: Cann't find email file %s for parsing.\n", err.Error(), os.Args[1])
		os.Exit(2)
	}

	return os.Args[1]
}

func parseEmail(emailFile string) (recievedFromIp net.IP, sender, senderDomain string) {
	f, err := os.Open(emailFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't open file %s\n", err.Error())
		os.Exit(100)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		l := scanner.Text()
		if recievedCheck.Match([]byte(l)) {
			// fmt.Fprintf(os.Stdout, "Parsing line [%s]\n", scanner.Text())
			parts := strings.Fields(l)
			ip, err := net.LookupIP(parts[2])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Lookup of the %s FAILED. Error %s\n", parts[2], err.Error())
				os.Exit(300)
			}
			recievedFromIp = ip[0]
		} else if fromCheck.Match([]byte(l)) {
			parts := strings.Fields(l)
			sender = strings.Replace(parts[len(parts)-1], "<", "", -1)
			sender = strings.Replace(sender, ">", "", -1)
			parts = strings.SplitAfter(sender, "@")
			if len(parts) == 2 {
				senderDomain = parts[1]
			} else {
				senderDomain = sender
			}
		}
	}

	return recievedFromIp, sender, senderDomain
}

func main() {
	emailFile := chkParams()
	rxIp, sndr, sndrFQDN := parseEmail(emailFile)
	fmt.Printf("Recieved From: %s; Sender: %s; Domain: %s\n", rxIp.String(), sndr, sndrFQDN)
	fmt.Printf("\nSPF: %s\n\n", spf.CheckHost(rxIp, sndrFQDN, sndr, ""))

	// DKIM package does all for me...
	// Except result for human beings
	dkimResHR := map[int]string{
		int(dkim.SUCCESS):   "SUCCESS",
		int(dkim.PERMFAIL):  "PERMFAIL",
		int(dkim.TEMPFAIL):  "TEMPFAIL",
		int(dkim.NOTSIGNED): "NOTSIGNED",
	}

	data, err := ioutil.ReadFile(emailFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR. Can't read email file %s: %s\n", emailFile, err.Error())
		os.Exit(1)
	}
	dkimRes, err := dkim.Verify(&data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR. DKIM verification failed %s\n", err.Error())
		os.Exit(2)
	}

	fmt.Printf("\nDKIM %s (%d)\n", dkimResHR[int(dkimRes)], dkimRes)
}
