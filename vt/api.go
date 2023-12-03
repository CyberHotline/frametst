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

type File struct {
	Info      FileInfo
	Behaviour Filebehaviour
}

type FileInfo struct {
	Data struct {
		Attributes struct {
			Name            []string `json:"names"`                 //D
			Magic           string   `json:"magic"`                 //D
			Sha256          string   `json:"sha256"`                //D
			Md5             string   `json:"md5"`                   //D
			Sha1            string   `json:"sha1"`                  //D
			CreationDate    int      `json:"creation_date"`         //D
			FirstSubmission int      `json:"first_submission_date"` //D
			Size            int      `json:"size"`                  //D
			Tags            []string `json:"tags"`                  //D
			SignatureInfo   struct { //D
				Product      string `json:"product"`       //D
				Description  string `json:"description"`   //D
				Copyright    string `json:"copyright"`     //D
				OriginalName string `json:"original name"` //D
				FileVersion  string `json:"file version"`  //D
				InternalName string `json:"internal name"` //D
			} `json:"signature_info"`
			LastAnalysisStats struct { //D
				Harmless         int `json:"harmless"`          //D
				TypeUnsupported  int `json:"type-unsupported"`  //D
				Suspicious       int `json:"suspicious"`        //D
				ConfirmedTimeout int `json:"confirmed-timeout"` //D
				Timeout          int `json:"timeout"`           //D
				Failure          int `json:"failure"`           //D
				Malicious        int `json:"malicious"`         //D
				Undetected       int `json:"undetected"`        //D
			}
			Reputation int `json:"reputation"` //D
		} `json:"attributes"`
	} `json:"data"`
}

type Filebehaviour struct {
	Data struct {
		CallsHighlighted    []string   `json:"calls_highlighted"` //D
		MutexesCreated      []string   `json:"mutexes_created"`
		MutexesOpened       []string   `json:"mutexes_opened"`
		ProcessesTerminated []string   `json:"processes_terminated"` //D
		ProcessTree         []struct { //D
			Name     string     `json:"name"`       //D
			PID      string     `json:"process_id"` //D
			Children []struct { //D
				Name     string     `json:"name"`       //D
				PID      string     `json:"process_id"` //D
				Children []struct { //D
					Name string `json:"name"`       //D
					PID  string `json:"process_id"` //D
				} `json:"children"`
			} `json:"children"`
		} `json:"processes_tree"`
		RegistryKeysOpened  []string `json:"registry_keys_opened"`
		RegistryKeysDeleted []string `json:"registry_keys_deleted"`
		RegistryKeysSet     []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"registry_keys_set"`
		MitreAttackTechniques []struct { //D
			SignatureDescription string `json:"signature_description"` //D
			ID                   string `json:"id"`                    //D
		} `json:"mitre_attack_techniques"`
		Verdicts              []string   `json:"verdicts"` //D
		FilesOpened           []string   `json:"files_opened"`
		FilesDeleted          []string   `json:"files_deleted"`
		FilesWritten          []string   `json:"files_written"`
		FileAttributesChanged []string   `json:"files_attribute_changed"`
		ModulesLoaded         []string   `json:"modules_loaded"`
		TextHighlighted       []string   `json:"text_highlighted"` //D
		MemoryPatternIps      []string   `json:"memory_pattern_ips"`
		MemoryPatternDomains  []string   `json:"memory_pattern_domains"`
		HTTPConversations     []struct { //D
			URL            string   `json:"url"`            //D
			Method         string   `json:"request_method"` //D
			ResonseHeaders struct { //D
				ContentLength string `json:"Content-Length"` //D
				SetCookie     string `json:"Set-Cookie"`     //D
				StatusLine    string `json:"Status-Line"`    //D
				Server        string `json:"Server"`         //D
				Date          string `json:"Date"`           //D
				ContentType   string `json:"Content-Type"`   //D
			}
		} `json:"http_conversations"`
		IPTraffic []struct { //D
			TransportLayerProtocol string `json:"transport_layer_protocol"` //D
			DestinationIP          string `json:"destination_ip"`           //D
			DestinationPort        int    `json:"destination_port"`         //D
		} `json:"ip_traffic"`
		DNSLookup []struct { //D
			ResolvedIPs []string `json:"resolved_ips"` //D
			Hostname    string   `json:"hostname"`     //D
		} `json:"dns_lookups"`
		CommandExecutions []string `json:"command_executions"` //D
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

func Fretriever(key, id string, l int) (File, int) {
	infourl := "https://www.virustotal.com/api/v3/files/" + id
	behavioururl := "https://www.virustotal.com/api/v3/files/" + id + "/behaviour_summary"

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

func Mng(order string) {
	sliced := strings.Split(order, " ")
	if sliced[0] == "help" {
		fmt.Println("USAGE of the virustotal module:")
		fmt.Println("\thelp\tPrint The Help Menu")
		fmt.Println("\tfile [LEVEL 1-3] [HASH]\tScan a file")
	} else if sliced[0] == "file" {
		level, _ := strconv.Atoi(sliced[1])
		FtableView(Fretriever(mng.Q.VirusTotal, sliced[2], level))
	}
}
