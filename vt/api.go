package vt

import (
	vi "github.com/VirusTotal/vt-go"
)

func Fileinfo(key, h *string) {
	cli := vi.NewClient(*key)
	file, _ := cli.GetObject(vi.URL("files/%s", *h))

	name, _ := file.GetString("meaningful_name")
	description, _ := file.GetString("type_description")
	typetags, _ := file.GetStringSlice("type_tags")
	s256, _ := file.GetString("sha256")
	magic, _ := file.GetString("magic")
	threatlabel, _ := file.GetString("popular_threat_classification.suggested_threat_label")
	size, _ := file.GetInt64("size")
	harmlessv, _ := file.GetInt64("total_votes.harmless")
	maliciousv, _ := file.GetInt64("total_votes.malicious")
	reputation, _ := file.GetInt64("reputation")
	captags, _ := file.GetStringSlice("capabilities_tags")
	creationdate, _ := file.GetTime("creation_date")
	lastanalysisstats, _ := file.Get("last_analysis_stats")
	lastanalysisdate, _ := file.GetTime("last_analysis_date")
	uniquesource, _ := file.GetInt64("unique_sources")
	Fmtfileinfo(lastanalysisstats, name, description, s256, magic, threatlabel, typetags, captags, size, harmlessv, maliciousv, reputation, uniquesource, creationdate, lastanalysisdate)
}
