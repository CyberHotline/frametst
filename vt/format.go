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

	fmt.Println()

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
	fmt.Println()

	if len(f.Info.Data.Attributes.Tags) > 0 {
		fmt.Println("Tags")
		tag := list.NewWriter()
		for _, c := range f.Info.Data.Attributes.Tags {
			tag.AppendItem(c)
		}
		tag.SetStyle(list.StyleBulletCircle)
		Listprint(tag.Render())
		fmt.Println()
	}

	if len(f.Behaviour.Data.Verdicts) > 0 {
		fmt.Println("Verdicts")
		ver := list.NewWriter()
		for _, c := range f.Behaviour.Data.Verdicts {
			ver.AppendItem(c)
		}
		ver.SetStyle(list.StyleBulletTriangle)
		Listprint(ver.Render())
		fmt.Println()
	}
	if len(f.Behaviour.Data.CommandExecutions) > 0 {
		fmt.Println("Command Executions")
		com := list.NewWriter()
		for _, c := range f.Behaviour.Data.CommandExecutions {
			com.AppendItem(c)
		}
		com.SetStyle(list.StyleBulletStar)
		Listprint(com.Render())
		fmt.Println()
	}
	fmt.Println("---------------------------------------------------------------------------------")
	fmt.Println()
	// L2
	if l >= 2 {
		if f.Info.Data.Attributes.SignatureInfo.Product != "" && f.Info.Data.Attributes.SignatureInfo.Copyright != "" && f.Info.Data.Attributes.SignatureInfo.Description != "" {
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
			s.SetStyle(table.StyleColoredDark)
			s.Style().Options.SeparateRows = true
			s.Render()
			fmt.Println()
		}

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
		a.SetStyle(table.StyleColoredRedWhiteOnBlack)
		a.Style().Options.SeparateRows = true
		a.Render()
		fmt.Println()

		if len(f.Behaviour.Data.CallsHighlighted) > 0 {
			fmt.Println("Calls Highlighted")
			cal := list.NewWriter()
			for _, c := range f.Behaviour.Data.CallsHighlighted {
				cal.AppendItem(c)
			}
			cal.SetStyle(list.StyleBulletFlower)
			Listprint(cal.Render())
			fmt.Println()
		}

		if len(f.Behaviour.Data.TextHighlighted) > 0 {
			fmt.Println("Text Highlighted")
			text := list.NewWriter()
			for _, c := range f.Behaviour.Data.TextHighlighted {
				text.AppendItem(c)
			}
			text.SetStyle(list.StyleBulletSquare)
			Listprint(text.Render())
			fmt.Println()
		}

		if len(f.Behaviour.Data.MitreAttackTechniques) > 0 {
			fmt.Println("MITRE Attack Techniques")
			mitre := table.NewWriter()
			mitre.SetOutputMirror(os.Stdout)
			mitre.AppendHeader(table.Row{"Attack ID", "Signature Description"})
			for _, c := range f.Behaviour.Data.MitreAttackTechniques {
				mitre.AppendRow(table.Row{c.ID, c.SignatureDescription})
			}
			mitre.SetStyle(table.StyleRounded)
			mitre.Style().Options.SeparateRows = true
			mitre.Render()
			fmt.Println()
		}

		if len(f.Behaviour.Data.ProcessTree) > 0 {
			fmt.Println("Process Tree")
			prt := list.NewWriter()
			for _, c := range f.Behaviour.Data.ProcessTree {
				prt.AppendItem("Name: " + c.Name + " PID: " + c.PID)
				if len(c.Children) > 0 {
					prt.Indent()
					for _, k := range c.Children {
						prt.AppendItem("Name: " + k.Name + " PID: " + k.PID)
						if len(k.Children) > 0 {
							prt.Indent()
							for _, i := range k.Children {
								prt.AppendItem("Name: " + i.Name + " PID: " + i.PID)
							}
							prt.UnIndent()
						}
					}
					prt.UnIndent()
				}
			}
			prt.SetStyle(list.StyleConnectedRounded)
			Listprint(prt.Render())
			fmt.Println()

		}

		if len(f.Behaviour.Data.ProcessesTerminated) > 0 {
			fmt.Println("Processes Terminated")
			prterm := list.NewWriter()
			for _, c := range f.Behaviour.Data.ProcessesTerminated {
				prterm.AppendItem(c)
			}
			prterm.SetStyle(list.StyleConnectedBold)
			Listprint(prterm.Render())
			fmt.Println()
		}
		fmt.Println("---------------------------------------------------------------------------------")
		fmt.Println()
	}

	if l >= 3 {
		if len(f.Behaviour.Data.DNSLookup) > 0 {
			fmt.Println("DNS Lookup")
			dns := list.NewWriter()
			for _, d := range f.Behaviour.Data.DNSLookup {
				dns.AppendItem("Hostname: " + d.Hostname)
				if len(d.ResolvedIPs) > 0 {
					dns.Indent()
					dns.AppendItem("Resolved IPs:")
					for _, i := range d.ResolvedIPs {
						dns.AppendItem(i)
					}
					dns.UnIndent()
				}
			}
			dns.SetStyle(list.StyleConnectedLight)
			Listprint(dns.Render())
			fmt.Println()
		}

		if len(f.Behaviour.Data.IPTraffic) > 0 {
			fmt.Println("IP Traffic")
			ipt := list.NewWriter()
			for _, t := range f.Behaviour.Data.IPTraffic {
				ipt.AppendItem(t.DestinationIP)
				ipt.Indent()
				ipt.AppendItem("Port: " + strconv.Itoa(t.DestinationPort))
				ipt.AppendItem("Transport Layer Protocol: " + t.TransportLayerProtocol)
				ipt.UnIndent()
			}
			ipt.SetStyle(list.StyleConnectedLight)
			Listprint(ipt.Render())
			fmt.Println()
		}

		if len(f.Behaviour.Data.HTTPConversations) > 0 {
			fmt.Println("HTTP Conversations")
			http := list.NewWriter()
			for _, h := range f.Behaviour.Data.HTTPConversations {
				http.AppendItem(h.Method + " " + h.URL)
				if h.ResonseHeaders.Server != "" && h.ResonseHeaders.ContentType != "" && h.ResonseHeaders.Date != "" {
					http.Indent()
					http.AppendItem("Content Type: " + h.ResonseHeaders.ContentType)
					http.AppendItem("Server: " + h.ResonseHeaders.Server)
					http.AppendItem("Date: " + h.ResonseHeaders.Date)
					http.AppendItem("Content Length: " + h.ResonseHeaders.ContentLength)
					http.AppendItem("Set Cookie: " + h.ResonseHeaders.SetCookie)
					http.AppendItem("Status Line: " + h.ResonseHeaders.StatusLine)
					http.UnIndent()
				}
			}
			http.SetStyle(list.StyleBulletStar)
			Listprint(http.Render())
		}

		fmt.Println("---------------------------------------------------------------------------------")
		fmt.Println()
	}
	fmt.Printf("\nView The GUI Report: \t %v", f.guiurl())
	fmt.Println()
}

func IPtableView(ip IP) {

	fmt.Println("Last Analysis Stats:")
	l := list.NewWriter()
	l.AppendItem("Harmless: " + fmt.Sprint(ip.Data.Attributes.LastAnalysisStats.Harmless))
	l.AppendItem("Malicious: " + fmt.Sprint(ip.Data.Attributes.LastAnalysisStats.Malicious))
	l.AppendItem("Suspicious: " + fmt.Sprint(ip.Data.Attributes.LastAnalysisStats.Suspicious))
	l.AppendItem("Undetected: " + fmt.Sprint(ip.Data.Attributes.LastAnalysisStats.Undetected))
	l.AppendItem("Timeout: " + fmt.Sprint(ip.Data.Attributes.LastAnalysisStats.Timeout))
	l.SetStyle(list.StyleBulletStar)
	Listprint(l.Render())
	fmt.Println("Last Analysis Date: " + time.Unix(int64(ip.Data.Attributes.LastAnalysisDate), 0).String())
	fmt.Println()

	fmt.Println("Community Votes:")
	v := list.NewWriter()
	v.AppendItem("Reputation: " + fmt.Sprint(ip.Data.Attributes.Reputation))
	v.AppendItem("Harmless: " + fmt.Sprint(ip.Data.Attributes.TotalVotes.Harmless))
	v.AppendItem("Malicious: " + fmt.Sprint(ip.Data.Attributes.TotalVotes.Malicious))
	Listprint(v.Render())
	fmt.Println()

	fmt.Println("IP Report:")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Attribute", "Value"})
	t.AppendRow(table.Row{"Whois", ip.Data.Attributes.Whois})
	t.AppendRow(table.Row{"Whois Date", time.Unix(int64(ip.Data.Attributes.WhoisDate), 0)})
	t.AppendRow(table.Row{"Tags", ip.Data.Attributes.Tags})
	t.AppendRow(table.Row{"Network", ip.Data.Attributes.Network})
	t.SetStyle(table.StyleColoredDark)
	t.Render()
	fmt.Println()

}
