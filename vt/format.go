package vt

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	list "github.com/jedib0t/go-pretty/v6/list"
	table "github.com/jedib0t/go-pretty/v6/table"
)

func Listprint(content string) {
	for _, line := range strings.Split(content, "\n") {
		fmt.Printf("%s%s\n", "", line)
	}
	fmt.Println()
}

func FtableView(f File, l int) {
	//* L1

	// Making The Table
	fmt.Println("General Info")
	g := table.NewWriter()
	g.SetOutputMirror(os.Stdout)
	g.AppendHeader(table.Row{"Attribute", "Value"})
	g.AppendRow(table.Row{"Name", f.Info.Data.Attributes.Name[0]})
	g.AppendRow(table.Row{"SHA256", f.Info.Data.Attributes.Sha256})
	g.AppendRow(table.Row{"Magic", f.Info.Data.Attributes.Magic})
	g.AppendRow(table.Row{"First Submission On VT", time.Unix(int64(f.Info.Data.Attributes.FirstSubmission), 0)})
	g.SetStyle(table.StyleLight)
	g.Style().Options.SeparateRows = true
	g.Render()

	fmt.Println("Fingerprint")
	fin := list.NewWriter()
	fin.AppendItem("Hashes")
	fin.Indent()
	fin.AppendItem("SHA256: \t" + f.Info.Data.Attributes.Sha256)
	fin.AppendItem("SHA1: \t" + f.Info.Data.Attributes.Sha1)
	fin.AppendItem("MD5: \t" + f.Info.Data.Attributes.Md5)
	fin.UnIndent()
	fin.AppendItem("MISC")
	fin.Indent()
	fin.AppendItem("Size (bytes): \t" + strconv.Itoa(f.Info.Data.Attributes.Size))
	fin.AppendItem("Reputation: \t" + strconv.Itoa(f.Info.Data.Attributes.Reputation))
	fin.AppendItem("Creation Time: \t" + time.Unix(int64(f.Info.Data.Attributes.CreationDate), 0).String())
	fin.SetStyle(list.StyleBulletCircle)
	Listprint(fin.Render())

	if l >= 2 {
		fmt.Println("Signature Info")
		s := table.NewWriter()
		s.SetOutputMirror(os.Stdout)
		s.AppendHeader(table.Row{"Attribute", "Value"})
		s.AppendRow(table.Row{"Product", f.Info.Data.Attributes.SignatureInfo.Product})
		s.AppendRow(table.Row{"Description", f.Info.Data.Attributes.SignatureInfo.Description})
		s.AppendRow(table.Row{"Copyright", f.Info.Data.Attributes.SignatureInfo.Copyright})
		s.AppendRow(table.Row{"Original Name", f.Info.Data.Attributes.SignatureInfo.OriginalName})
		s.AppendRow(table.Row{"File Version", f.Info.Data.Attributes.SignatureInfo.FileVersion})
		s.AppendRow(table.Row{"Internal Name", f.Info.Data.Attributes.SignatureInfo.InternalName})
		s.SetStyle(table.StyleLight)
		s.Style().Options.SeparateRows = true
		s.Render()

		fmt.Println("Last Analysis Stats")
		a := table.NewWriter()
		a.SetOutputMirror(os.Stdout)
		a.AppendHeader(table.Row{"Attribute", "Value"})
		a.AppendRow(table.Row{"Harmless", f.Info.Data.Attributes.LastAnalysisStats.Harmless})
		a.AppendRow(table.Row{"Type Unsupported", f.Info.Data.Attributes.LastAnalysisStats.TypeUnsupported})
		a.AppendRow(table.Row{"Suspicious", f.Info.Data.Attributes.LastAnalysisStats.Suspicious})
		a.AppendRow(table.Row{"Confirmed Timeout", f.Info.Data.Attributes.LastAnalysisStats.ConfirmedTimeout})
		a.AppendRow(table.Row{"Timeout", f.Info.Data.Attributes.LastAnalysisStats.Timeout})
		a.AppendRow(table.Row{"Failure", f.Info.Data.Attributes.LastAnalysisStats.Failure})
		a.AppendRow(table.Row{"Malicious", f.Info.Data.Attributes.LastAnalysisStats.Malicious})
		a.AppendRow(table.Row{"Undetected", f.Info.Data.Attributes.LastAnalysisStats.Undetected})
		a.SetStyle(table.StyleLight)
		a.Style().Options.SeparateRows = true
		a.Render()
	}
	fmt.Printf("\nView The GUI Report: \t %v", f.guiurl())

}
