package sasspf

import (
	"fmt"
	"net"
	"os"
	"strings"
)

type filterFunc func(string) bool

func getTxtRecs(domain string, filter filterFunc) ([]string, error) {
	txtrecords, err := net.LookupTXT(domain)
	if err != nil {
		return nil, err
	}

	txtres := make([]string, 1)
	for i, txt := range txtrecords {
		fmt.Printf("(%d) %s\n", i, txt)
		if filter(txt) {
			txtres = append(txtres, txt)
		}
	}

	return txtres, nil
}

func isDomainGood(domain string) bool {
	res := true

	labels := strings.Split(domain, ".")
	lastIdx := len(labels) - 1

	// domain name is not multi label
	if lastIdx == 0 {
		return false
	}

	for i, l := range labels {
		l = strings.TrimSpace(l)
		// Zero domain is not last or label len > 63
		if len(l) > 63 || (l == "" && i != lastIdx) {
			return false
		}
	}

	// DNS lookup
	_, err := net.LookupIP(domain)
	if err != nil {
		// Assume that if error it is RCODE 3 for now
		//
		// TODO: DNS lookup RCODE 3 NXDOMAIN
		//       error is not covered here
		//       4.3. from RFC-7208
		fmt.Fprintf(os.Stderr, "DNS Lookup error %+v\n", err)
		return false
	}
	return res
}
