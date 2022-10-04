package sasspf

import (
	"fmt"
	"net"
	"strings"
)

/**
 * spf.go
 *
 * Based on the https://www.rfc-editor.org/rfc/rfc7208#section-4
 */

// Section 2.6 from RFC-7208
type ChkResult string

const (
	None      = ChkResult("None")
	Neutral   = ChkResult("Neutral")
	Pass      = ChkResult("Pass")
	Fail      = ChkResult("Fail")
	Softfail  = ChkResult("Softfail")
	Temperror = ChkResult("Temperror")
	Permerror = ChkResult("Permerror")
)

// 4.6.1
type Qualifier string

const (
	plus     = Qualifier("+")
	minus    = Qualifier("-")
	question = Qualifier("?")
	tilda    = Qualifier("~")
)

type Mechanism string

const (
	all     = Mechanism("all")
	include = Mechanism("include")
	a       = Mechanism("a")
	mx      = Mechanism("mx")
	ptr     = Mechanism("ptr")
	ip4     = Mechanism("ip4")
	ip6     = Mechanism("ip6")
	exists  = Mechanism("exists")
)

type Modifier string

const (
	redirect    = Modifier("redirect")
	explanation = Modifier("explanation")
	unknown     = Modifier("unknown-modifier")
)

// Section 4 from RFC-7208
func CheckHost(ip net.IP, domain string, sender string) (res ChkResult) {
	res = None

	if !isDomainGood(domain) {
		// TODO: Make sure that DNS Lookup NXDOMAIN
		//       is handled in isDomainGood
		return None
	}

	recs, err := getTxtRecs(domain, func(r string) bool {
		return strings.HasPrefix(r, "v=spf1")
	})
	if err != nil || len(recs) == 0 {
		return Temperror
	}
	fmt.Printf("filtered recs %+v\n", recs)

	parseSPF(recs[0])

	return res
}

func parseSPF(spfstr string) {

}
