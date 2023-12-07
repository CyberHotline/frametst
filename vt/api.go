package vt

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	mng "github.com/mohabgabber/frametst/shellmng"
)

var BASEURL string = "https://www.virustotal.com/api/v3/"

type File struct {
	Info      FileInfo
	Behaviour Filebehaviour
}

type FileInfo struct {
	Data struct {
		Attributes struct {
			Name            []string `json:"names"`
			Magic           string   `json:"magic"`
			Sha256          string   `json:"sha256"`
			Md5             string   `json:"md5"`
			Sha1            string   `json:"sha1"`
			CreationDate    int      `json:"creation_date"`
			FirstSubmission int      `json:"first_submission_date"`
			Size            int      `json:"size"`
			Tags            []string `json:"tags"`
			SignatureInfo   struct {
				Product      string `json:"product"`
				Description  string `json:"description"`
				Copyright    string `json:"copyright"`
				OriginalName string `json:"original name"`
				FileVersion  string `json:"file version"`
				InternalName string `json:"internal name"`
			} `json:"signature_info"`
			LastAnalysisStats struct {
				Harmless         int `json:"harmless"`
				TypeUnsupported  int `json:"type-unsupported"`
				Suspicious       int `json:"suspicious"`
				ConfirmedTimeout int `json:"confirmed-timeout"`
				Timeout          int `json:"timeout"`
				Failure          int `json:"failure"`
				Malicious        int `json:"malicious"`
				Undetected       int `json:"undetected"`
			}
			Reputation int `json:"reputation"`
		} `json:"attributes"`
	} `json:"data"`
}

type Filebehaviour struct {
	Data struct {
		CallsHighlighted    []string `json:"calls_highlighted"`
		MutexesCreated      []string `json:"mutexes_created"`
		MutexesOpened       []string `json:"mutexes_opened"`
		ProcessesTerminated []string `json:"processes_terminated"`
		ProcessTree         []struct {
			Name     string `json:"name"`
			PID      string `json:"process_id"`
			Children []struct {
				Name     string `json:"name"`
				PID      string `json:"process_id"`
				Children []struct {
					Name string `json:"name"`
					PID  string `json:"process_id"`
				} `json:"children"`
			} `json:"children"`
		} `json:"processes_tree"`
		RegistryKeysOpened  []string `json:"registry_keys_opened"`
		RegistryKeysDeleted []string `json:"registry_keys_deleted"`
		RegistryKeysSet     []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"registry_keys_set"`
		MitreAttackTechniques []struct {
			SignatureDescription string `json:"signature_description"`
			ID                   string `json:"id"`
		} `json:"mitre_attack_techniques"`
		Verdicts              []string `json:"verdicts"`
		FilesOpened           []string `json:"files_opened"`
		FilesDeleted          []string `json:"files_deleted"`
		FilesWritten          []string `json:"files_written"`
		FileAttributesChanged []string `json:"files_attribute_changed"`
		ModulesLoaded         []string `json:"modules_loaded"`
		TextHighlighted       []string `json:"text_highlighted"`
		MemoryPatternIps      []string `json:"memory_pattern_ips"`
		MemoryPatternDomains  []string `json:"memory_pattern_domains"`
		HTTPConversations     []struct {
			URL            string `json:"url"`
			Method         string `json:"request_method"`
			ResonseHeaders struct {
				ContentLength string `json:"Content-Length"`
				SetCookie     string `json:"Set-Cookie"`
				StatusLine    string `json:"Status-Line"`
				Server        string `json:"Server"`
				Date          string `json:"Date"`
				ContentType   string `json:"Content-Type"`
			}
		} `json:"http_conversations"`
		IPTraffic []struct {
			TransportLayerProtocol string `json:"transport_layer_protocol"`
			DestinationIP          string `json:"destination_ip"`
			DestinationPort        int    `json:"destination_port"`
		} `json:"ip_traffic"`
		DNSLookup []struct {
			ResolvedIPs []string `json:"resolved_ips"`
			Hostname    string   `json:"hostname"`
		} `json:"dns_lookups"`
		CommandExecutions []string `json:"command_executions"`
		MemoryDumps       []struct {
			Process     string `json:"process"`
			FileName    string `json:"file_name"`
			Size        string `json:"size"`
			BaseAddress string `json:"base_address"`
			Stage       string `json:"stage"`
		} `json:"memory_dumps"`
	} `json:"data"`
}

func (f File) guiurl() string {
	return "https://www.virustotal.com/gui/file/" + f.Info.Data.Attributes.Sha256
}

type IP struct {
	Address string
	Data    struct {
		Attributes struct {
			Whois             string   `json:"whois"`
			WhoisDate         int      `json:"whois_date"`
			Tags              []string `json:"tags"`
			LastAnalysisDate  int      `json:"last_analysis_date"`
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			Reputation int    `json:"reputation"`
			Network    string `json:"network"`
			TotalVotes struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
		} `json:"attributes"`
	} `json:"data"`
}

func (add IP) guiurl() string {
	return "https://www.virustotal.com/gui/ip-address/" + add.Address
}

type Domain struct {
	Domain string
	Data   struct {
		Attributes struct {
			LatestDnsRecords []struct {
				Tag   string `json:"tag"`
				Value string `json:"value"`
				Type  string `json:"type"`
				Ttl   int    `json:"ttl"`
			} `json:"latest_dns_records"`
			LastDnsRecordsDate       int      `json:"last_dns_records_date"`
			Whois                    string   `json:"whois"`
			WhoisDate                int      `json:"whois_date"`
			CreationDate             int      `json:"creation_date"`
			LastHTTPSCertificateDate int      `json:"last_https_certificate_date"`
			Tags                     []string `json:"tags"`
			CrowdSourcedContext      []struct {
				Source    string `json:"source"`
				Title     string `json:"title"`
				Details   string `json:"details"`
				Severity  string `json:"severity"`
				Timestamp int    `json:"timestamp"`
			} `json:"crowdsourced_context"`
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicous   int `json:"malicous"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			LastAnalysisDate int    `json:"last_analysis_date"`
			Registrar        string `json:"registrar"`
			Reputation       int    `json:"reputation"`
			TotalVotes       struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
		} `json:"attributes"`
	} `json:"data"`
}

func (d Domain) guiurl() string {
	return "https://www.virustotal.com/gui/domain/" + d.Domain
}

func Fretriever(key, id string, l int) (File, int) {
	infourl := BASEURL + "files/" + id
	behavioururl := BASEURL + "files/" + id + "/behaviour_summary"

	inforeq, _ := http.NewRequest("GET", infourl, nil)
	behaviourreq, _ := http.NewRequest("GET", behavioururl, nil)
	inforeq.Header.Add("accept", "application/json")
	inforeq.Header.Add("x-apikey", key)
	behaviourreq.Header.Add("accept", "application/json")
	behaviourreq.Header.Add("x-apikey", key)

	infores, _ := http.DefaultClient.Do(inforeq)
	behaviourres, _ := http.DefaultClient.Do(behaviourreq)

	defer infores.Body.Close()
	defer behaviourres.Body.Close()

	infobody, _ := io.ReadAll(infores.Body)
	behaviourbody, _ := io.ReadAll(behaviourres.Body)

	// Retrieving File Data
	var file File
	var b Filebehaviour
	var i FileInfo
	ierr := json.Unmarshal([]byte(infobody), &i)
	berr := json.Unmarshal([]byte(behaviourbody), &b)
	if ierr != nil {
		fmt.Println("Info Error:")
		log.Fatal(ierr)
	}
	if berr != nil {
		fmt.Println("Behaviour Error:")
		log.Fatal(berr)
	}
	file.Info = i
	file.Behaviour = b
	return file, l
}

func IPRetriever(key, ip string) IP {
	infourl := BASEURL + "ip_addresses/" + ip

	inforeq, _ := http.NewRequest("GET", infourl, nil)
	inforeq.Header.Add("accept", "application/json")
	inforeq.Header.Add("x-apikey", key)

	infores, err := http.DefaultClient.Do(inforeq)
	if err != nil {
		log.Fatal(err)
	}
	defer infores.Body.Close()

	infobody, _ := io.ReadAll(infores.Body)

	// Retrieving IP Data
	var ADD IP
	ierr := json.Unmarshal([]byte(infobody), &ADD)
	if ierr != nil {
		fmt.Println("Info Error:")
		log.Fatal(ierr)
	}
	ADD.Address = ip
	return ADD
}

func DomainRetriever(key, domain string) Domain {
	infourl := BASEURL + "domains/" + domain

	inforeq, _ := http.NewRequest("GET", infourl, nil)
	inforeq.Header.Add("accept", "application/json")
	inforeq.Header.Add("x-apikey", key)

	infores, err := http.DefaultClient.Do(inforeq)
	if err != nil {
		log.Fatal(err)
	}
	defer infores.Body.Close()

	infobody, _ := io.ReadAll(infores.Body)

	// Retrieving IP Data
	var D Domain
	ierr := json.Unmarshal([]byte(infobody), &D)
	if ierr != nil {
		fmt.Println("Info Error:")
		log.Fatal(ierr)
	}
	D.Domain = domain
	return D
}

func Mng(order string) {
	sliced := strings.Split(order, " ")
	if sliced[0] == "help" {
		fmt.Println("USAGE of the virustotal module:")
		fmt.Println("\thelp\tPrint The Help Menu")
		fmt.Println("\tfile [LEVEL 1-3] [HASH]\tScan a file")
		fmt.Println("\tip [IP ADDRESS]\tReport on IP address")
	} else if sliced[0] == "file" {
		level, _ := strconv.Atoi(sliced[1])
		FtableView(Fretriever(mng.Q.VirusTotal, sliced[2], level))
	} else if sliced[0] == "ip" {
		IPtableView(IPRetriever(mng.Q.VirusTotal, sliced[1]))
	} else if sliced[0] == "domain" {
		DomaintableView(DomainRetriever(mng.Q.VirusTotal, sliced[1]))
	}
}
