package vt

import (
	"fmt"
	"os"
	"strconv"
	"time"

	table "github.com/jedib0t/go-pretty/v6/table"
)

func Fmtfileinfo(lastanalysisstats interface{}, name, description, s256, magic, threatlabel string, typetags, captags []string, size, harmlessv, maliciousv, reputation, uniquesource int64, creationdate, lastanalysisdate time.Time) {

	// Fixing type issues
	las := lastanalysisstats.(map[string]interface{})

	// Creating Tables
	//* General Info
	fmt.Println("General Info")
	g := table.NewWriter()
	g.SetOutputMirror(os.Stdout)
	g.AppendHeader(table.Row{"Attribute", "Value"})
	g.AppendRow(table.Row{"Name", name})
	g.AppendRow(table.Row{"Description", description + ", " + strconv.Itoa(int(size)) + " Bytes"})
	g.AppendRow(table.Row{"Creation Date", creationdate})
	g.AppendRow(table.Row{"Type Tags", typetags})
	g.AppendRow(table.Row{"Capabilities Tags", captags})
	g.AppendRow(table.Row{"Votes", "Harmless: " + strconv.Itoa(int(harmlessv)) + "\nMalicious: " + strconv.Itoa(int(maliciousv)) + "\nReputation: " + strconv.Itoa(int(reputation))})
	g.SetStyle(table.StyleLight)
	g.Style().Options.SeparateRows = true
	g.Render()

	//* Threat Details
	fmt.Println("Threat Details")
	f := table.NewWriter()
	f.SetOutputMirror(os.Stdout)
	f.AppendHeader(table.Row{"Attribute", "Value"})
	f.AppendRow(table.Row{"SHA-256", s256})
	f.AppendRow(table.Row{"Magic", magic})
	f.AppendRow(table.Row{"Suggested Threat Label", threatlabel})
	f.AppendRow(table.Row{"Unique Sources", uniquesource})

	f.SetStyle(table.StyleLight)
	f.Style().Options.SeparateRows = true
	f.Render()
	//* Last Analysis Stats
	fmt.Println("Last Analysis Stats")
	a := table.NewWriter()
	a.SetOutputMirror(os.Stdout)
	a.AppendHeader(table.Row{"Attribute", "Value"})
	a.AppendRow(table.Row{"Last Analysis Date", lastanalysisdate})
	a.AppendRow(table.Row{"confirmed-timeout", las["confirmed-timeout"]})
	a.AppendRow(table.Row{"failure", las["failure"]})
	a.AppendRow(table.Row{"harmless", las["harmless"]})
	a.AppendRow(table.Row{"malicious", las["malicious"]})
	a.AppendRow(table.Row{"suspicious", las["suspicious"]})
	a.AppendRow(table.Row{"timeout", las["timeout"]})
	a.AppendRow(table.Row{"type-unsupported", las["type-unsupported"]})
	a.AppendRow(table.Row{"undetected", las["undetected"]})
	a.SetStyle(table.StyleLight)
	a.Style().Options.SeparateRows = true
	a.Render()
}
