package main

import (
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
)

var services = []string{"virustotal", "hybridanalysis", "malwarebazaar", "all"}
var Q Keys
var homedir, _ = os.UserHomeDir()
var cfgpath = homedir + "/.frametst_config.xml"
var rf, _ = os.ReadFile(cfgpath)
var _ = xml.Unmarshal(rf, &Q)

type Keys struct {
	XMLName        xml.Name `xml:"APIKEYS"`
	VirusTotal     string   `xml:"virustotal"`
	HybridAnalysis string   `xml:"hybridanalysis"`
	MalwareBazaar  string   `xml:"malwarebazaar"`
}

func (k *Keys) Reset(service string) {
	if service == services[0] {
		k.VirusTotal = ""
	} else if service == services[1] {
		k.HybridAnalysis = ""
	} else if service == services[2] {
		k.MalwareBazaar = ""
	} else if service == services[3] {
		k.HybridAnalysis = ""
		k.VirusTotal = ""
		k.MalwareBazaar = ""
	}
}

func (k *Keys) Set(service, data string) {
	if service == services[0] {
		k.VirusTotal = data
	} else if service == services[1] {
		k.HybridAnalysis = data
	} else if service == services[2] {
		k.MalwareBazaar = data
	}
}

func (k *Keys) Show(service string) {
	if service == services[0] {
		fmt.Println("VirusTotal: " + k.VirusTotal)
	} else if service == services[2] {
		fmt.Println("Malware Bazaar: " + k.MalwareBazaar)
	} else if service == services[1] {
		fmt.Println("Hybrid Analysis: " + k.HybridAnalysis)
	} else if service == services[3] {
		fmt.Println("VirusTotal: " + k.VirusTotal)
		fmt.Println("Malware Bazaar: " + k.MalwareBazaar)
		fmt.Println("Hybrid Analysis: " + k.HybridAnalysis)
	}
}

func (k *Keys) Configwrite() {
	s, _ := xml.MarshalIndent(k, "", "  ")
	os.WriteFile(cfgpath, s, fs.FileMode(os.O_WRONLY))
}

func HelpMenu() {
	fmt.Println("List Of Available Commands")
	fmt.Println("\tGeneral:")
	fmt.Println("\t help\tPrint Help Menu")
	fmt.Println("\t exit\tClose The Prompt")
	fmt.Println("\tModules:")
	fmt.Println("\t config\tManage Your Config File")
	fmt.Println("\t vt\tVirustotal Operations")
	fmt.Println("\t ha\tHybrid Analysis Operations")
}

func Configmng(order string) {
	sliced := strings.Split(order, " ")
	if sliced[0] == "help" {
		fmt.Println("USAGE of the config module:")
		fmt.Println("\thelp\tPrint Help Menu")
		fmt.Println("\tManaging Saved Creds:")
		fmt.Println("\t Example: set virustotal 123412341234123412341234")
		fmt.Println("\t Options:")
		fmt.Println("\t\tdelete [MODULE] \t Delete Saved API Keys")
		fmt.Println("\t\tset [MODULE] [API KEY] \t Set API Key")
		fmt.Println("\t\tshow [MODULE] \t Print Saved Data")
		fmt.Println("\tAvailable Modules: [virustotal/malwarebazaar/hybridanalysis]")
		fmt.Println("\tYou can also use 'all' to delete or show all modules at once")
	} else if sliced[0] == "delete" {
		if slices.Contains(services, sliced[1]) {
			Q.Reset(sliced[1])
			Q.Configwrite()
		}
	} else if sliced[0] == "set" {
		if slices.Contains(services, sliced[1]) {
			Q.Set(sliced[1], sliced[2])
			Q.Configwrite()
		}
	} else if sliced[0] == "show" {
		if slices.Contains(services, sliced[1]) {
			Q.Show(sliced[1])
		}
	}
}
