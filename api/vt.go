package api

type VTFile struct {
	Info     FileInfo
	Behavior FileBehavior
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

type FileBehavior struct {
	Data struct {
		CallsHighlighted    []string `json:"calls_highlighted"`
		MutexesCreated      []string `json:"mutexes_created"`
		MutexesOpened       []string `json:"mutexes_opened"`
		ProcessesTerminated []string `json:"processes_terminated"`
		ProcessTree         []struct {
			Name     string `json:"name"`
			PID      string `json:"process_id"`
			Children []struct {
				Name     string `json:"name"`
				PID      string `json:"process_id"`
				Children []struct {
					Name string `json:"name"`
					PID  string `json:"process_id"`
				} `json:"children"`
			} `json:"children"`
		} `json:"processes_tree"`
		RegistryKeysOpened  []string `json:"registry_keys_opened"`
		RegistryKeysDeleted []string `json:"registry_keys_deleted"`
		RegistryKeysSet     []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"registry_keys_set"`
		MitreAttackTechniques []struct {
			SignatureDescription string `json:"signature_description"`
			ID                   string `json:"id"`
		} `json:"mitre_attack_techniques"`
		Verdicts              []string `json:"verdicts"`
		FilesOpened           []string `json:"files_opened"`
		FilesDeleted          []string `json:"files_deleted"`
		FilesWritten          []string `json:"files_written"`
		FileAttributesChanged []string `json:"files_attribute_changed"`
		ModulesLoaded         []string `json:"modules_loaded"`
		TextHighlighted       []string `json:"text_highlighted"`
		MemoryPatternIps      []string `json:"memory_pattern_ips"`
		MemoryPatternDomains  []string `json:"memory_pattern_domains"`
		HTTPConversations     []struct {
			URL             string `json:"url"`
			Method          string `json:"request_method"`
			ResponseHeaders struct {
				ContentLength string `json:"Content-Length"`
				SetCookie     string `json:"Set-Cookie"`
				StatusLine    string `json:"Status-Line"`
				Server        string `json:"Server"`
				Date          string `json:"Date"`
				ContentType   string `json:"Content-Type"`
			}
		} `json:"http_conversations"`
		IPTraffic []struct {
			TransportLayerProtocol string `json:"transport_layer_protocol"`
			DestinationIP          string `json:"destination_ip"`
			DestinationPort        int    `json:"destination_port"`
		} `json:"ip_traffic"`
		DNSLookup []struct {
			ResolvedIPs []string `json:"resolved_ips"`
			Hostname    string   `json:"hostname"`
		} `json:"dns_lookups"`
		CommandExecutions []string `json:"command_executions"`
		MemoryDumps       []struct {
			Process     string `json:"process"`
			FileName    string `json:"file_name"`
			Size        string `json:"size"`
			BaseAddress string `json:"base_address"`
			Stage       string `json:"stage"`
		} `json:"memory_dumps"`
	} `json:"data"`
}

type IP struct {
	Address string
	Data    struct {
		Attributes struct {
			Whois             string   `json:"whois"`
			WhoisDate         int      `json:"whois_date"`
			Tags              []string `json:"tags"`
			LastAnalysisDate  int      `json:"last_analysis_date"`
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			Reputation int    `json:"reputation"`
			Network    string `json:"network"`
			TotalVotes struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
		} `json:"attributes"`
	} `json:"data"`
}

type Domain struct {
	Domain string
	Data   struct {
		Attributes struct {
			LatestDnsRecords []struct {
				Tag   string `json:"tag"`
				Value string `json:"value"`
				Type  string `json:"type"`
				Ttl   int    `json:"ttl"`
			} `json:"latest_dns_records"`
			LastDnsRecordsDate       int      `json:"last_dns_records_date"`
			Whois                    string   `json:"whois"`
			WhoisDate                int      `json:"whois_date"`
			CreationDate             int      `json:"creation_date"`
			LastHTTPSCertificateDate int      `json:"last_https_certificate_date"`
			Tags                     []string `json:"tags"`
			CrowdSourcedContext      []struct {
				Source    string `json:"source"`
				Title     string `json:"title"`
				Details   string `json:"details"`
				Severity  string `json:"severity"`
				Timestamp int    `json:"timestamp"`
			} `json:"crowdsourced_context"`
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicous   int `json:"malicous"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			LastAnalysisDate int    `json:"last_analysis_date"`
			Registrar        string `json:"registrar"`
			Reputation       int    `json:"reputation"`
			TotalVotes       struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
		} `json:"attributes"`
	} `json:"data"`
}
