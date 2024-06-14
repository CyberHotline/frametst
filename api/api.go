package api

var VTBASE string = "https://www.virustotal.com/api/v3/"
var MBBASE string = "https://mb-api.abuse.ch/api/v1/"
var HABASE string = "https://www.hybrid-analysis.com/api/v2/"

type Query struct {
	q       string
	qtype   string // 0 = Hash, 1 = File, 2 = Domain, 3 = IP
	verdict string
}

var VTENDPOINTS = map[string]string{
	"domain": "domains/",
	"ip":     "ip_addresses/",
	"file":   "files/",
}

var q Query
