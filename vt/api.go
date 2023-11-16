package vt

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

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
			Name string `json:"name"`
			PID  string `json:"process_id"`
		}
		RegistryKeysOpened []string `json:"registry_keys_opened"`
		RegistryKeysSet    []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"registry_keys_set"`
		MitreAttackTechniques []struct {
			SignatureDescription string `json:"signature_description"`
			ID                   string `json:"id"`
			Severity             string `json:"severity"`
		} `json:"mitre_attack_techniques"`
		Verdicts              []string `json:"verdicts"`
		FilesOpened           []string `json:"files_opened"`
		FileAttributesChanged []string `json:"files_attribute_changed"`
		ModulesLoaded         []string `json:"modules_loaded"`
		TextHighlighted       []string `json:"text_highlighted"`
		MemoryPatternIps      []string `json:"memory_pattern_ips"`
		MemoryPatternDomains  []string `json:"memory_pattern_domains"`
	} `json:"data"`
}

func (f File) guiurl() string {
	return "https://www.virustotal.com/gui/file/" + f.Info.Data.Attributes.Sha256
}

func Fretriever(key, id string, l int) {
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
	FtableView(file, l)
}

// func Fileinfo(key, h *string, l *int) {
// 	f := Fretriever(*key, *h)

// }
