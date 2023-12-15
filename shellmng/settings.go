package settings

import (
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
)

var services = []string{"virustotal", "hybridanalysis", "anyrun", "malwarebazaar", "all"}
var Q Keys
var homedir, _ = os.UserHomeDir()
var cfgpath = homedir + "/.frametst_config.xml"
var rf, _ = os.ReadFile(cfgpath)
var _ = xml.Unmarshal(rf, &Q)

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

func (k *Keys) Show(service string) {
	if service == "virustotal" {
		fmt.Println("VirusTotal: " + k.VirusTotal)
	} else if service == "anyrun" {
		fmt.Println("Any.Run: " + k.AnyRun)
	} else if service == "malwarebazaar" {
		fmt.Println("Malware Bazaar: " + k.MalwareBazaar)
	} else if service == "hybridanalysis" {
		fmt.Println("Hybrid Analysis: " + k.HybridAnalysis)
	} else if service == "all" {
		fmt.Println("VirusTotal: " + k.VirusTotal)
		fmt.Println("Any.Run: " + k.AnyRun)
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
		fmt.Println("\t Example: creds set virustotal 12341234123412341234123412341234")
		fmt.Println("\t Options:")
		fmt.Println("\t\tdelete [MODULE] \t Delete Saved API Keys")
		fmt.Println("\t\tset [MODULE] [API KEY] \t Set API Key")
		fmt.Println("\t\tshow [MODULE] \t Print Saved Data")
		fmt.Println("\tAvailable Modules: [virustotal/anyrun/malwarebazaar/hybridanalysis]")
		fmt.Println("\tYou can also use 'all' to delete or show all modules at once")
	} else if sliced[0] == "creds" {
		if sliced[1] == "delete" {
			if slices.Contains(services, sliced[2]) {
				Q.Reset(sliced[2])
				Q.Configwrite()
			}
		} else if sliced[1] == "set" {
			if slices.Contains(services, sliced[2]) {
				Q.Set(sliced[2], sliced[3])
				Q.Configwrite()
			}
		} else if sliced[1] == "show" {
			if slices.Contains(services, sliced[2]) {
				Q.Show(sliced[2])
			}
		}
	}
}
