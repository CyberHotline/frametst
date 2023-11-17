package settings

import (
	"encoding/xml"
	"fmt"
	"log"
	"os"
)

type Keys struct {
	XMLName        xml.Name `xml:"APIKEYS"`
	VirusTotal     string   `xml:"virustotal"`
	HybridAnalysis string   `xml:"hybridanalysis"`
	AnyRun         string   `xml:"anyrun"`
	MalwareBazaar  string   `xml:"malwarebazaar"`
}

func HelpMenu() {
	fmt.Println("List Of Available Commands")
	fmt.Printf("\thelp\tPrint Help Menu\n")
	fmt.Printf("\texit\tClose The Prompt\n")
	fmt.Printf("\tconfig\tManage Your Config File\n")
}

func Printsettings(vt, ha, ar, mb string) {
	q := Keys{VirusTotal: vt, HybridAnalysis: ha, AnyRun: ar, MalwareBazaar: mb}
	data, err := xml.MarshalIndent(q, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	err1 := os.WriteFile("frametst_config.xml", data, 0600)
	if err1 != nil {
		log.Fatal(err1)
	}
}
