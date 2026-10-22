"""English UI strings."""
from __future__ import annotations

STRINGS: dict[str, str] = {
    # --- app ---
    "app.title": "Paradox v{version}",

    # --- tabs ---
    "tab.run": "Run",
    "tab.history": "History",
    "tab.enrich": "Enrichment",
    "tab.settings": "Settings",
    "tab.ipv6": "IPv6",
    "tab.timeline": "Timeline",
    "tab.export": "Export",
    "tab.diff": "Diff",

    # --- menu ---
    "menu.file": "File",
    "menu.file.open_pcap": "Open pcap…",
    "menu.file.open_report": "Open report…",
    "menu.file.export": "Export",
    "menu.file.export.json": "JSON report…",
    "menu.file.export.markdown": "Markdown report…",
    "menu.file.export.conn_log": "Flow report (conn.log)…",
    "menu.file.quit": "Quit",
    "menu.tools": "Tools",
    "menu.tools.quick_check": "Quick IOC check…",
    "menu.help": "Help",
    "menu.help.reference": "Reference",
    "menu.help.about": "About",
    "menu.help.hotkeys": "Keyboard shortcuts",
    "menu.settings": "Open settings…",
    "menu.run.analyze": "Analyze",
    "menu.run.analyze_with_config": "Analyze with settings…",
    "menu.run.stop": "Stop",
    "menu.view.fullscreen": "Fullscreen",

    # --- status bar ---
    "status.ready": "Ready",
    "status.file": "File:",
    "status.analyzing": "Analyzing…",
    "status.done": "Done · {findings} findings · {contradictions} contradictions",
    "status.cancelled": "Cancelled by user",
    "status.saved": "Saved: {path}",
    "status.report_loaded": "Report loaded: {path}",

    # --- buttons ---
    "btn.close": "Close",

    # --- file dialogs ---
    "dialog.file.open_pcap.title": "Open pcap",
    "dialog.file.open_pcap.filter": "Packet captures (*.pcap *.pcapng *.cap);;All files (*)",
    "dialog.file.open_report.title": "Open report",
    "dialog.file.open_report.filter": "JSON (*.json);;All files (*)",
    "dialog.file.save_json.title": "Save JSON report",
    "dialog.file.save_json.filter": "JSON (*.json);;All files (*)",
    "dialog.file.save_md.title": "Save Markdown report",
    "dialog.file.save_md.filter": "Markdown (*.md);;All files (*)",
    "dialog.file.save_conn.title": "Save flow report",
    "dialog.file.save_conn.filter": "Log (*.log);;All files (*)",

    # --- errors ---
    "error.title": "Error",
    "error.read.title": "Read error",
    "error.read.body": "{type}: {message}",
    "error.wrong_file.title": "Wrong file",
    "error.wrong_file.body": "Not a Paradox JSON report: missing 'findings'.",
    "error.save.title": "Save error",
    "error.config.title": "Invalid settings",
    "error.import.body": "Failed to load: {message}",

    # --- About ---
    "dialog.about.title": "About",
    "dialog.about.app_title": "Paradox v{version}",
    "dialog.about.subtitle": "Offline pcap triage",
    "dialog.about.modules_html": (
        "<div style='text-align:center; line-height:1.6;'>"
        "<span style='color:#e0e0e0;'>"
        "20 detectors · 12 rules<br>"
        "4 extractors · 4 analyzers<br>"
        "</span>"
        "<span style='color:#a0a0b0; font-size:11px;'>"
        "Attack Graph · Multi-pcap · Threat Intel<br>"
        "Shodan · AbuseIPDB · VirusTotal · OTX · URLScan"
        "</span></div>"
    ),
    "dialog.about.copyright": "© 2026 Andrey Grigoryev (v314xm)",

    # --- Help ---
    "dialog.help.title": "Tool reference",
    "dialog.help.body_html": (
        "<b>What Paradox does</b><br>"
        "Extracts network facts from a pcap and looks for inconsistencies "
        "between data layers: DNS vs SNI, JA3 vs UA, MAC vs IP, "
        "roles vs behavior.<br><br>"
        "<b>Extractors (9):</b><br>"
        "flow, dns, host_identity, arp_history, nbns, "
        "kerberos, tls, http, <b>ndp (IPv6)</b>.<br><br>"
        "<b>Detectors (18):</b><br>"
        "dga, cloud_tunnel, ip_check_service, typosquatting, "
        "sni_mismatch, suspicious_port, port_scan, web_scanner, "
        "brute_force, ftp_brute_force, beaconing, dns_tunneling, "
        "lateral_movement, large_transfer, vulnerable_path, "
        "command_injection, ja3_malware, nxdomain_burst, <b>yara</b>.<br><br>"
        "<b>Analyzers:</b><br>"
        "Confidence Explainer, What-If (Counterfactual), "
        "Absence (broken sessions), Host Story.<br><br>"
        "<b>Contradiction rules (12):</b><br>"
        "victim_makes_attack, mac_ip_conflict, "
        "sni_host_mismatch, ja3_ua_mismatch, reverse_asymmetry, "
        "port_service_mismatch, direct_ip_no_dns, "
        "sni_without_dns, dns_answer_mismatch, "
        "sni_cert_mismatch, self_signed_cert, "
        "expired_cert.<br><br>"
        "<i>Detailed description of each module — in a separate "
        "release.</i>"
    ),

    # --- Hotkeys ---
    "dialog.hotkeys.title": "Keyboard shortcuts",
    "dialog.hotkeys.body": (
        "Ctrl+O — open pcap\n"
        "F5 — analyze\n"
        "F11 — fullscreen"
    ),

    # --- language ---
    "dialog.lang_changed.title": "Language",
    "dialog.lang_changed.body": (
        "Language changed. Restart the app to apply fully."
    ),
    # --- SettingsView (этап 1) ---
    "settings.section.general": "General",
    "settings.section.thresholds": "Thresholds",
    "settings.section.detectors": "Detectors",
    "settings.section.contradictions": "Contradictions",
    "settings.section.allowlist": "Allowlist",
    "settings.section.dga": "DGA",
    "settings.section.brute": "Brute force",
    "settings.section.network": "Network",
    "settings.section.reports": "Reports",
    "settings.section.yara": "YARA",
    "settings.section.threatintel": "Threat Intel",
    "settings.section.perf": "Performance",
    "settings.general.title": "General settings",
    "settings.general.subtitle": "Basic interface parameters.",
    "settings.thresholds.title": "Thresholds",
    "settings.thresholds.subtitle": "Detector thresholds from the core Config. Changes apply to the next run. Profile — a ready-made set of values.",
    "settings.detectors.title": "Detectors",
    "settings.detectors.subtitle": "Unchecking disables the detector on the next run. Order matches the core.",
    "settings.contradictions.title": "ContradictionDetector",
    "settings.contradictions.subtitle": "Rules check consistency across data layers. Disabling a rule removes it from the next run.",
    "settings.allowlist.title": "Allowlist",
    "settings.allowlist.subtitle": "Whitelists. A match removes a candidate from findings. One item per line, # — comment.",
    "settings.dga.title": "DGA",
    "settings.dga.subtitle": "Final DGA detector allowlist. Cloud tunnel and IP-check domains from Config are merged here. Removing an item means DGA will flag it.",
    "settings.brute.title": "Brute force",
    "settings.brute.subtitle": "How the detector distinguishes password guessing from normal traffic. Flow thresholds are in the Thresholds section.",
    "settings.network.title": "Network",
    "settings.network.subtitle": "Port and prefix lists. Enter comma- or newline-separated. Invalid values are highlighted and not saved.",
    "settings.reports.title": "Reports",
    "settings.reports.subtitle": "Where the core stores artifacts (enrichment cache, carved files if enabled). Path is created on apply.",
    "settings.yara.title": "YARA",
    "settings.yara.subtitle": "Custom YARA rules for payload signatures. If no file is selected, default core rules are used.",
    "settings.threatintel.title": "Threat Intel",
    "settings.threatintel.subtitle": "IOC enrichment from findings. Runs separately (--enrich flag). API keys live until GUI restart — the core reads them from env at request time.",
    "settings.perf.title": "Performance",
    "settings.perf.subtitle": "Trade-off between analysis depth and speed. Technical limits (memory, sizes) are hidden and use defaults.",
    "settings.search.placeholder": "Search settings (Ctrl+F)…",
    "settings.btn.reset": "Reset to default",
    "settings.btn.apply": "Apply",
    "settings.btn.enable_all": "Enable all",
    "settings.btn.disable_all": "Disable all",
    "settings.profile.label": "Profile:",
    "settings.profile.apply": "Apply profile",
    "settings.general.language": "Interface language:",

    # --- SettingsView fields (stage 2) ---
    "settings.field.dga_min_label_length": "DGA: min label length",
    "settings.field.dga_entropy_threshold": "DGA: entropy threshold",
    "settings.field.nxdomain_burst_threshold": "NXDOMAIN burst: threshold",
    "settings.field.nxdomain_burst_window_sec": "NXDOMAIN burst: window (sec)",
    "settings.field.nxdomain_burst_min_ratio": "NXDOMAIN burst: min NXDOMAIN ratio",
    "settings.field.dns_tunneling_min_qname_length": "DNS tunneling: min qname length",
    "settings.field.dns_tunneling_min_queries": "DNS tunneling: min queries",
    "settings.field.brute_force_min_flows": "Brute force: min flows",
    "settings.field.brute_force_max_avg_packets": "Brute force: max avg packets",
    "settings.field.ftp_brute_force_min_flows": "FTP brute force: min flows",
    "settings.field.beaconing_min_connections": "Beaconing: min connections",
    "settings.field.beaconing_min_duration_sec": "Beaconing: min duration (sec)",
    "settings.field.beaconing_max_jitter_ratio": "Beaconing: max jitter",
    "settings.field.large_transfer_min_bytes": "Large transfer: min bytes",
    "settings.field.port_scan_min_distinct_dsts": "Port scan: min dsts",
    "settings.field.port_scan_max_flows_per_dst": "Port scan: max flows/dst",
    "settings.field.reverse_asymmetry_min_ratio": "Reverse asymmetry: min ratio",
    "settings.field.reverse_asymmetry_min_total_bytes": "Reverse asymmetry: min bytes",
    "settings.field.brute_force_min_unique_src_ports": "HTTP: min unique src ports",
    "settings.field.brute_force_uri_ratio_threshold": "HTTP: login-endpoint request ratio",
    "settings.field.brute_force_min_rate_flows_per_sec": "HTTP: min rate (flows/sec)",
    "settings.field.ftp_brute_force_min_unique_src_ports": "FTP: min unique src ports",
    "settings.help.dga_min_label_length": "Minimum label length (part before the first dot). Shorter — not DGA, too many legitimate domains.",
    "settings.help.dga_entropy_threshold": "Shannon entropy threshold for label. Higher — looks random (xg7f2k9vbn).",
    "settings.help.nxdomain_burst_threshold": "Number of NXDOMAIN responses in window to count as a burst.",
    "settings.help.nxdomain_burst_window_sec": "Window size in seconds. Checks the maximum across all W-second windows from one src.",
    "settings.help.nxdomain_burst_min_ratio": "Minimum NXDOMAIN share among all DNS queries from src. Below — noise (browser with rare typos).",
    "settings.help.dns_tunneling_min_qname_length": "Minimum qname length for DNS tunnel. Shorter — DGA zone, not tunnel.",
    "settings.help.dns_tunneling_min_queries": "Min DNS queries to one base domain to count as a tunnel.",
    "settings.help.brute_force_min_flows": "Min flows for HTTP brute force.",
    "settings.help.brute_force_max_avg_packets": "Max average packets per flow. Higher — not brute force (browser loading a site).",
    "settings.help.ftp_brute_force_min_flows": "Min flows for FTP brute force. FTP session is longer, so threshold is higher.",
    "settings.help.beaconing_min_connections": "Min connections to one (src, dst, port) pair for beaconing.",
    "settings.help.beaconing_min_duration_sec": "Minimum observation duration. Short burst — not a C2 heartbeat.",
    "settings.help.beaconing_max_jitter_ratio": "Max jitter = stddev / mean of intervals. Lower — smoother timing, stronger C2 signal.",
    "settings.help.large_transfer_min_bytes": "'Large transfer' threshold in bytes.",
    "settings.help.port_scan_min_distinct_dsts": "Min unique dst addresses from one src for port scan.",
    "settings.help.port_scan_max_flows_per_dst": "Max flows to one dst. Higher — this is service interaction, not a scan.",
    "settings.help.reverse_asymmetry_min_ratio": "How many times larger the bigger side must be. 10:1 — anomaly, 25:1 — nearly one-way channel.",
    "settings.help.reverse_asymmetry_min_total_bytes": "Minimum total session volume. Below — not analyzed.",
    "settings.help.brute_force_min_unique_src_ports": "Min unique src ports. Strong password-guessing signal.",
    "settings.help.brute_force_uri_ratio_threshold": "Share of requests to login-endpoint. Below — not brute force.",
    "settings.help.brute_force_min_rate_flows_per_sec": "Minimum rate flows/sec. Cuts slow legitimate retries.",
    "settings.help.ftp_brute_force_min_unique_src_ports": "Min unique src ports for FTP brute force.",
    "settings.help.brute_force_skip_tls_ports": "TLS ports where brute force isn't detected: User-Agent unreadable, signal doesn't work.",
    "settings.help.login_endpoint_hints": "URI substrings identifying login-endpoint: /login, /admin, /wp-login, …",
    "settings.help.suspicious_ports": "Ports considered suspicious: 4444, 31337, 1337…",
    "settings.help.port_scan_excluded_ports": "Ports excluded from port scan — typical web traffic.",
    "settings.help.dc_service_ports": "Domain controller ports: Kerberos, LDAP, SMB. Presence + many flows distinguishes a DC from a regular server.",
    "settings.help.lateral_movement_ports": "Lateral movement ports: SMB, RDP, WinRM, MSRPC.",
    "settings.help.beaconing_mail_polling_ports": "POP3/IMAP ports. Mail client polls on a timer — not C2 beaconing.",
    "settings.help.private_networks": "Private network prefixes. Used to classify dst as internal or external.",
    "settings.help.tcp_reassembly_enabled": "Reassemble TCP segments into streams. Gives full ClientHello and HTTP body, uses memory.",
    "settings.help.tcp_reassembly_max_bytes_per_flow": "Memory limit per flow during reassembly.",
    "settings.help.tcp_reassembly_max_total_bytes": "Total memory limit for reassembly. Protection from GB-sized pcaps.",
    "settings.help.file_carve_enabled": "Extract payload metadata (sha256, type, size). Without writing content to disk.",
    "settings.help.file_carve_write_body": "Write file bodies to disk as <sha256>.bin. Caution: takes a lot of space.",
    "settings.help.file_carve_min_size": "Minimum payload size for file carve.",
    "settings.help.file_carve_max_size": "Maximum payload size for file carve.",
    "settings.help.entities_top_n": "How many top entities (by activity) to show in the report.",
    "settings.help.flow_report_top_n": "How many top flows by bytes to include in flow report.",
    "settings.help.beaconing_allowlist_suffixes": "SNI/Host suffixes where beaconing is skipped: analytics, CDN, cloud.",
    "settings.help.beaconing_allowlist_ips": "Exact IPs (no SNI) where beaconing is skipped.",
    "settings.help.dns_tunneling_allowlist": "DoH domains: dns.google, cloudflare-dns.com. Not counted as tunnel.",
    "settings.help.sni_mismatch_allowlist": "Known validation domains (OCSP, CRL, DoH) where SNI ≠ Host by design.",
    "settings.help.large_transfer_excluded_hosts": "Hosts where large transfers are normal: Windows and Apple updates.",
    "settings.help.large_transfer_excluded_user_agents": "User-Agents where large transfers are normal: BITS, CryptoAPI, Delivery Optimization.",
    "settings.help.dga_allowlist": "Final DGA allowlist = extra + cloud tunnel + ip-check services. Removing an item means DGA will flag it.",
    "settings.help.output_dir": "Directory for reports and artifacts. Created on apply.",
    "settings.help.enrichment_enabled_providers": "Which providers to use. No key: shodan_internetdb, greynoise, alienvault_otx, urlscan. With key: abuseipdb, virustotal. With ABUSECH_AUTH_KEY: urlhaus, malwarebazaar, threatfox.",
    "settings.help.enrichment_cache_ttl_days": "Enrichment cache TTL in days.",
    "settings.help.enrichment_cache_path": "Path to SQLite enrichment cache file.",
    "settings.help.enrichment_max_iocs": "How many IOCs to enrich per run.",
    "settings.placeholder.general": "<b>What's coming.</b> General settings: <b>UI language</b> (Russian / English), default reports path, startup behavior (open last pcap or empty tab), theme (currently dark-only).<br><br><b>Why empty.</b> Currently these values are either hardcoded in GUI or not critical. Will appear with the second locale or multiple work profiles.",
    "settings.placeholder.fallback": "Section in development.",
    "settings.help.fallback": "Config field '{field}'. See paradox/config.py.",

    # --- New keys for UI (v1.2) ---
    "settings.yara.browse": "Browse…",
    "settings.yara.validate": "Validate rules",
    "settings.yara.path": "Rules file path (.yar):",
    "settings.brute.skip_tls_label": "HTTP: ports to skip for brute force (TLS)",
    "settings.brute.login_hints_label": "HTTP: login-endpoint hints",
    "settings.network.suspicious_ports": "Suspicious ports",
    "settings.network.scan_excluded": "Port scan exclusions",
    "settings.network.dc_ports": "Domain controller ports",
    "settings.network.lateral_ports": "Lateral movement ports",
    "settings.network.mail_ports": "Mail polling ports (POP3/IMAP)",
    "settings.network.private_nets": "Private network prefixes",
    "settings.perf.reassembly": "Reassemble TCP segments (TCP Reassembly)",
    "settings.perf.carve": "Extract file metadata (File Carve)",
    "settings.perf.write_body": "Write file bodies to disk (DANGEROUS)",
    "settings.allowlist.beaconing_suffixes": "Beaconing: SNI/Host suffixes (analytics, CDN)",
    "settings.allowlist.beaconing_ips": "Beaconing: exact IPs (no SNI)",
    "settings.allowlist.dns_tunneling": "DNS tunneling: DoH domains, not a tunnel",
    "settings.allowlist.sni_mismatch": "SNI mismatch: known validation domains",
    "settings.allowlist.large_transfer_hosts": "Large transfer: hosts where this is normal",
    "settings.allowlist.large_transfer_uas": "Large transfer: UAs where this is normal",
    "settings.dga.allowlist_label": "DGA allowlist (domains)",
    "settings.threatintel.providers": "Active providers",
    "settings.threatintel.abuseipdb_key": "AbuseIPDB API key",
    "settings.threatintel.vt_key": "VirusTotal API key",
    "settings.threatintel.abusech_key": "abuse.ch Auth-Key",
    "settings.threatintel.otx_key": "AlienVault OTX API key",
    "settings.threatintel.greynoise_key": "GreyNoise API key",
    "settings.threatintel.urlscan_key": "URLScan API key",
    "settings.threatintel.show_keys": "Show keys",
    "settings.threatintel.cache_ttl": "Cache: TTL (days)",
    "settings.threatintel.cache_path": "Cache: SQLite file path",
    "settings.threatintel.max_iocs": "Max IOCs per run",

    # --- Timeline ---
    "timeline.title": "Incident Timeline by Kill-Chain Phase",
    "timeline.no_events": "Incident Timeline (no events found)",
    "timeline.events_count": "Incident Timeline (Events: {count})",
    "timeline.search_placeholder": "Search by IP, type or MITRE...",
    "timeline.expand_all": "Expand all",
    "timeline.collapse_all": "Collapse all",
    "timeline.no_selection": "Click on an event to see details.",
    "timeline.phase_selected": "Phase selected. Click on a specific event.",
    "timeline.phase_label": "Phase:",
    "timeline.confidence_label": "Confidence:",
    "timeline.reasons_label": "Why the detector decided this:",
    "timeline.evidence_label": "Additional data (Evidence):",
    "timeline.description_label": "Full description:",

    # --- History ---
    "history.title": "History",
    "history.subtitle": "Runs in this session. Click an entry to see details. History is not saved between launches.",
    "history.empty": "No runs yet. Open a pcap in the Run tab.",
    "history.cleared": "History cleared.",
    "history.clear_button": "Clear history",
    "history.ctx_compare": "Compare with current run…",

    # --- QuickCheck ---
    "quick_check.title": "Check IOC",
    "quick_check.subtitle": "Enter an IP, domain, URL or SHA256. Type will be detected automatically. All enabled providers will be queried.",
    "quick_check.input_placeholder": "8.8.8.8 · evil.com · https://evil.com/x · <sha256>",
    "quick_check.check_button": "Check",
    "quick_check.from_last_run": "From last run:",
    "quick_check.no_data": "— no data —",
    "quick_check.no_run": "— no data (run analysis first) —",
    "quick_check.no_iocs": "— no IOCs in the last run —",
    "quick_check.select_ioc": "— select an IOC —",
    "quick_check.type_detected": "Detected type: {type}",
    "quick_check.type_unknown": "Type not detected — select manually",
    "quick_check.warning_type": "Type not detected",
    "quick_check.warning_type_body": "Could not detect IOC type automatically. Select a type from the dropdown.",
    "quick_check.no_providers": "No providers",
    "quick_check.no_providers_body": "No provider supports type «{type}». Check Settings → Threat Intel.",
    "quick_check.querying": "Querying {count} providers for {ioc} ({type})…",
    "quick_check.done": "Done: {count} providers responded for {ioc}.",
    "quick_check.no_results": "No provider responded.",
    "quick_check.error": "Error: {msg}",
    "quick_check.auto": "Auto",

    # --- Export ---
    "export.title": "Data Export (SIEM / Threat Intelligence)",
    "export.subtitle": "You can export Findings and IOCs as CSV (for Excel) or STIX 2.1 (for SIEM/EDR).",
    "export.fmt_csv": "CSV (Findings)",
    "export.fmt_stix": "STIX 2.1 (IOC Bundle)",
    "export.copy": "Copy to clipboard",
    "export.save": "Save to file...",
    "export.empty": "No data. Run pcap analysis first.",
    "export.copied": "Full data copied to clipboard.\nCan be pasted into SIEM or a text editor.",
    "export.csv_saved": "CSV successfully saved.",
    "export.stix_saved": "STIX Bundle successfully saved.",
    "export.err_save": "Save error",

    # --- Diff ---
    "diff.title": "Run Comparison",
    "diff.subtitle": "Load two JSON reports (old and new) to see what was added, removed, or changed. Useful for re-triaging the same pcap days/weeks later.",
    "diff.load_old": "Load old…",
    "diff.load_new": "Load new…",
    "diff.placeholder": "Load both reports to see the comparison.",
    "diff.export_md": "Export to Markdown…",
    "diff.err_file": "Read error",
    "diff.wrong_file": "Wrong file",
    "diff.wrong_file_body": "Not a Paradox JSON report: missing 'findings'.",
    "diff.expected_json": "Expected a JSON report.",
    "diff.not_paradox": "This is not a Paradox JSON report.",
    "diff.no_changes": "No changes",

    # --- Finding Dialog ---
    "finding.title": "Finding: {type}",
    "finding.value": "Value",
    "finding.mitre": "MITRE",
    "finding.reasons": "Confidence reasons",
    "finding.evidence": "Evidence",
    "finding.no_reasons": "No detailed breakdown (old detector or no reasons).",
    "finding.evidence_empty": "Evidence is empty.",
    "finding.close": "Close",

    # --- Contradiction Dialog ---
    "contra.title": "{rule} — {subject}",
    "contra.resolution": "Resolution",
    "contra.facts": "Facts",
    "contra.causes": "Likely causes",
    "contra.not_specified": "Not specified.",
    "contra.no_facts": "No facts.",
    "contra.close": "Close",

    # --- Carved Files ---
    "carved.title": "Carved Files",
    "carved.warning": "<b>⚠️ WARNING!</b> These files were extracted from captured network traffic. They may contain malware.<br>Do not open them on a production machine without checking in an isolated environment (Sandbox / VM).",
    "carved.empty": "No files were extracted in this run.",
    "carved.col_sha": "SHA256",
    "carved.col_ext": "Type",
    "carved.col_size": "Size",
    "carved.col_uri": "URI",
    "carved.col_status": "Status",
    "carved.status_saved": "Saved to disk",
    "carved.status_meta": "Metadata only",
    "carved.open_dir": "Open files folder",
    "carved.close": "Close",
    "carved.not_saved_title": "File not saved",
    "carved.not_saved_body": "File body was not saved to disk. Enable 'Write file bodies to disk' in Settings → Performance and re-run analysis.",

}
