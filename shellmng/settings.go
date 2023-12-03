package settings

import (
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
)

var services = []string{"virustotal", "hybrudanalysis", "anyrun", "malwarebazaar", "all"}
var q Keys
var rf, _ = os.ReadFile("frametst_config.xml")
var _ = xml.Unmarshal(rf, &q)

type Keys struct {
	XMLName        xml.Name `xml:"APIKEYS"`
	VirusTotal     string   `xml:"virustotal"`
	HybridAnalysis string   `xml:"hybridanalysis"`
	AnyRun         string   `xml:"anyrun"`
	MalwareBazaar  string   `xml:"malwarebazaar"`
}

func (k *Keys) Reset(service string) {
	if service == "virustotal" {
		k.VirusTotal = ""
	} else if service == "hybridanalysis" {
		k.HybridAnalysis = ""
	} else if service == "malwarebazaar" {
		k.MalwareBazaar = ""
	} else if service == "anyrun" {
		k.AnyRun = ""
	} else if service == "all" {
		k.HybridAnalysis = ""
		k.VirusTotal = ""
		k.AnyRun = ""
		k.MalwareBazaar = ""
	}
}

func (k *Keys) Set(service, data string) {
	if service == "virustotal" {
		k.VirusTotal = data
	} else if service == "anyrun" {
		k.AnyRun = data
	} else if service == "malwarebazaar" {
		k.MalwareBazaar = data
	} else if service == "hybridanalysis" {
		k.HybridAnalysis = data
	}
}

func HelpMenu() {
	fmt.Println("List Of Available Commands")
	fmt.Printf("\thelp\tPrint Help Menu\n")
	fmt.Printf("\texit\tClose The Prompt\n")
	fmt.Printf("\tconfig\tManage Your Config File\n")
}

func Configmng(order string) {
	sliced := strings.Split(order, " ")
	if sliced[0] == "help" {
		fmt.Println("USAGE of the config module:")
		fmt.Println("\thelp\tPrint Help Menu")
		fmt.Println("\tManaging Saved Creds:")
		fmt.Println("\t Example: creds set virustotal 12341234123412341234123412341234")
		fmt.Println("\t Options:")
		fmt.Println("\t\tdelete [virustotal/anyrun/malwarebazaar/hybridanalysis/all] \t Delete Saved API Keys")
		fmt.Println("\t\tset [virustotal/anyrun/malwarebazaar/hybridanalysis] [API KEY] \t Set API Key")
	} else if sliced[0] == "creds" {
		if sliced[1] == "delete" {
			if slices.Contains(services, sliced[2]) {
				q.Reset(sliced[2])
				q.Configwrite()
			}
		} else if sliced[1] == "set" {
			if slices.Contains(services, sliced[2]) {
				q.Set(sliced[2], sliced[3])
				q.Configwrite()
			}
		}
	}
}

func (k *Keys) Configwrite() {
	s, _ := xml.MarshalIndent(k, "", "  ")
	os.WriteFile("frametst_config.xml", s, fs.FileMode(os.O_WRONLY))
}
