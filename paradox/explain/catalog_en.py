"""Английские шаблоны объяснений для типов находок.

Двойник `catalog.py`: тот же набор ключей и те же подстановки `{key}`,
перевод смысловой, а не пословный. Экраны названы как в i18n GUI
(Injected code, HTTP objects, Carved files, Enrichment, Timeline,
Finding details). Паритет ключей и подстановок держит тест.
"""
from __future__ import annotations

from paradox.explain.model import TypeSpec

FINDING_SPECS_EN: dict[str, TypeSpec] = {
    "ad_recon": TypeSpec(
        headline=(
            "{src} was enumerating domain accounts and services: {value}."
        ),
        why=(
            "Enumeration is not an attack but a map of the terrain: which "
            "accounts exist, which services are registered, who is delegated "
            "to whom. That map decides who gets attacked: the account with an "
            "SPN goes to offline cracking, the machine with rights goes to "
            "lateral movement."
        ),
        next_steps=(
            "Check who in the company normally reads these attributes: "
            "inventory, audit, an application.",
            "Check what {src} did next: service ticket requests, replication, "
            "SMB.",
            "Compare the time with administrative tasks and scanner runs.",
        ),
        alternatives=(
            "AD inventory: BloodHound, ADRecon, a contractor audit.",
            "An application with broad directory search: mail, ERP, an SSO "
            "connector.",
            "A vulnerability scanner with an AD check module.",
        ),
        beginner=(
            "A program was asking the domain about its layout: which accounts, "
            "services and rights exist. Administrators do this, and so do "
            "those preparing an attack."
        ),
    ),
    "beaconing": TypeSpec(
        headline=(
            "{src} contacted {dst}:{port} on a schedule: {count} connections "
            "in {duration_sec} s, mean interval {mean_interval_sec} s, "
            "spread {jitter_ratio}."
        ),
        why=(
            "Identical requests at equal intervals are a check-in: an infected "
            "machine reports that it is alive and asks for commands. Almost no "
            "data moves, so the channel is easy to miss against normal "
            "traffic."
        ),
        next_steps=(
            "Check {dst} against services: domain, certificate, ASN, "
            "registration date.",
            "Compare response sizes: identical ones point to a hand-rolled "
            "protocol.",
            "With SSLKEYLOGFILE, decrypt the stream and read the request "
            "body.",
        ),
        alternatives=(
            "OS, antivirus or update-agent telemetry.",
            "A cloud keepalive or health check with a fixed interval.",
            "An application with a poll loop: messenger, monitoring, licence "
            "client.",
        ),
        beginner=(
            "The computer calls the same address at equal intervals - that is "
            "how a malicious program checks whether it has commands."
        ),
    ),
    "brute_force": TypeSpec(
        headline=(
            "{src} was guessing credentials for {dst}:{port}: {flow_count} "
            "short connections in {duration_sec} s, each from a new source "
            "port."
        ),
        why=(
            "Guessing is the cheapest initial access: one weak account opens "
            "everything else. Success is recorded as a separate finding on the "
            "same pair, so that is where to look."
        ),
        next_steps=(
            "Check whether a successful-login finding exists for this pair: "
            "it changes the verdict.",
            "Check the service logs on {dst}: how many failures and whether "
            "any succeeded.",
            "Look at Timeline: what the host did right afterwards.",
        ),
        alternatives=(
            "A client with a wrong password in its config and aggressive "
            "retries.",
            "Monitoring that reconnects often in short sessions.",
            "NAT: several people behind one address.",
        ),
        beginner=(
            "From one address someone tried to log in to a server many times "
            "in a row, starting over each time. That is what password guessing "
            "looks like."
        ),
    ),
    "carved_file": TypeSpec(
        headline="A file was carved from the traffic: {value}.",
        why=(
            "The file is the only evidence that can be checked independently "
            "of heuristics: hash in VirusTotal, YARA, a disassembler. "
            "Detectors say 'looks like'; the file says 'here it is'."
        ),
        next_steps=(
            "Check the sha256 in Enrichment and in MalwareBazaar.",
            "Open Carved files and run the project YARA rules over it.",
            "Check Timeline: what happened on the host after the download.",
        ),
        alternatives=(
            "A normal user download - settled by the request context.",
            "The body was cut by the size limit, the hash will not match the "
            "original.",
        ),
        beginner=(
            "The file itself was recovered from the captured traffic - it can "
            "be handed to an antivirus and opened to see what is inside."
        ),
    ),
    "cloud_tunnel": TypeSpec(
        headline=(
            "{value} is a service domain that forwards connections from the "
            "internet into the network ({matched_suffix})."
        ),
        why=(
            "Such services give access to an internal host without open ports "
            "and without a domain of its own: from outside only someone "
            "else's CDN is visible. For an attacker this is a convenient and "
            "often unblocked path."
        ),
        next_steps=(
            "Check who initiated the connection and what went inward.",
            "Check the domain against approved services and development "
            "tasks.",
        ),
        alternatives=(
            "A developer set up a temporary tunnel for debugging.",
            "A SaaS service that legitimately lives on this domain.",
        ),
        beginner=(
            "Someone used a service that forwards a connection from outside "
            "into the network. Developers do that, and attackers hide the "
            "same way."
        ),
    ),
    "cloud_tunnel_domain": TypeSpec(
        headline=(
            "{src} contacted {value}, a tunnelling service domain "
            "({matched_suffix}), {queries} queries."
        ),
        why=(
            "A public tunnel domain means the traffic left the network through "
            "someone else's service, and the real server is hidden. Often it "
            "is a control channel that nobody wants to expose under their own "
            "domain."
        ),
        next_steps=(
            "Check HTTP objects: what was transferred through the tunnel.",
            "Check the domain against approved services and the list of "
            "development tasks.",
            "See whether other hosts contacted this domain.",
        ),
        alternatives=(
            "A legitimate dev tunnel (ngrok, localtunnel) on a developer "
            "machine.",
            "An embedded widget or an ad on a page.",
            "A SaaS on the same domain.",
        ),
        beginner=(
            "The traffic contains a service domain that can forward "
            "connections from the internet into the network - only that "
            "domain is visible from outside."
        ),
    ),
    "command_injection": TypeSpec(
        headline=(
            "{src} sent strings typical of command injection to {uri}: "
            "{count} requests, {matched_patterns} matched"
        ),
        why=(
            "If the server puts this parameter into a shell, the command runs "
            "with its privileges. After that the usual step is to download a "
            "second stage or open a reverse channel right away."
        ),
        next_steps=(
            "Open Injected code for this finding - the request bodies are "
            "there.",
            "Check the responses to these requests: the command may have run "
            "blindly, without output.",
            "Look on {dst} for later file downloads and requests to new URIs.",
        ),
        alternatives=(
            "A pentest or a scanner probing the same parameter.",
            "An application where such characters are part of legitimate "
            "data.",
            "A parsing error: multipart or compression distorted the content.",
        ),
        beginner=(
            "Text that a server could take for a command was placed into a "
            "request parameter - an attempt to make the server run foreign "
            "code."
        ),
    ),
    "dcsync": TypeSpec(
        headline=(
            "{src} asked the domain controller for directory replication "
            "(DsGetNCChanges), {calls} calls: {value}."
        ),
        why=(
            "The built-in replication protocol can pull the hashes of every "
            "domain account without logging on to the controller. With them an "
            "attacker can issue tickets for any user."
        ),
        next_steps=(
            "Check that {src} really is a domain controller: replication "
            "between DCs looks the same.",
            "See which account made the calls and what rights it has.",
            "If confirmed, rotate krbtgt and review all sessions.",
        ),
        alternatives=(
            "Legitimate replication between domain controllers.",
            "A third-party sync tool: Azure AD Connect, an AD backup.",
            "A parsing error: opnum 3 read from a different call.",
        ),
        beginner=(
            "A machine asked the domain controller for a copy of the account "
            "database. Controllers do that themselves - and so does anyone who "
            "has obtained the needed rights to steal passwords."
        ),
    ),
    "dga_domain": TypeSpec(
        headline=(
            "{src} asked for {value} - a name with entropy {entropy} and "
            "label '{label}'."
        ),
        why=(
            "Algorithmically generated domains change every day: blocking a "
            "list is useless, and guessing which of them is 'real' today is "
            "almost impossible. The lookup is the only moment when the C2 "
            "address is visible."
        ),
        next_steps=(
            "Check Timeline: did the name resolve and what happened next.",
            "Look for a series of similar names from {src}: a DGA generates "
            "them in batches.",
            "Check the label against known families and their dictionaries.",
        ),
        alternatives=(
            "A random identifier in a subdomain of a legitimate service.",
            "A broken IDN or a typo in a config.",
            "A CDN label with high entropy.",
        ),
        beginner=(
            "The domain name looks like a random set of letters. That is how "
            "malware changes its server address every day so that it cannot "
            "be blocked."
        ),
    ),
    "dns_tunneling": TypeSpec(
        headline=(
            "Under {base_domain}, {src} sent {total_queries} queries, "
            "{long_qnames_count} of them with long labels (from "
            "{min_qname_length} characters)."
        ),
        why=(
            "A piece of data fits into a subdomain: DNS still leaves the "
            "network even when HTTP is closed. Files are taken out and "
            "commands received this way, and in the logs it looks like "
            "ordinary lookups."
        ),
        next_steps=(
            "Look at the samples: do the labels look like base64 or hex?",
            "Check Timeline: were there answers for these names and which "
            "addresses were returned.",
            "Compare this host's DNS volume with the norm for the network.",
        ),
        alternatives=(
            "Antivirus or corporate DNS with long check labels.",
            "Telemetry that puts hashes into subdomains.",
            "A DGA rather than a tunnel: many short names instead of long "
            "ones.",
        ),
        beginner=(
            "The computer asked DNS for very long names - it looks like data "
            "is carried in them, because DNS is usually not blocked."
        ),
    ),
    "encoded_payload": TypeSpec(
        headline=(
            "{method} {uri_path}: parameter {param} held a {encoding} string "
            "that decodes to {decoded}."
        ),
        why=(
            "An encoded address hides the real server from filters and "
            "signatures: from outside it looks like an ordinary parameter. "
            "After decoding you usually see a C2 domain or a link to a second "
            "stage."
        ),
        next_steps=(
            "Decode the value in full in Injected code - it also shows where "
            "the address came from.",
            "Check whether connections to the decoded address exist in this "
            "capture.",
            "Check what the server answered the request with.",
        ),
        alternatives=(
            "A legitimate base64 parameter: token, return URL, signature.",
            "Double encoding by the framework.",
            "A random regex match on a short string.",
        ),
        beginner=(
            "The request address held encoded text, and after decoding it "
            "turned out to be a site address - that is one way the real "
            "server is hidden."
        ),
    ),
    "ftp_brute_force": TypeSpec(
        headline=(
            "{src} was guessing FTP access on {dst}:21 - {flow_count} "
            "connections, each from a new port."
        ),
        why=(
            "FTP almost always goes in cleartext, and its passwords are often "
            "simple. Breaking in gives files and a foothold inside the "
            "network, while the traffic is indistinguishable from ordinary "
            "work with the server."
        ),
        next_steps=(
            "Check the FTP logs: were there successful logins and from which "
            "address.",
            "Look at Timeline: what was done on {src} right afterwards.",
            "Check which files sit on the server and who accessed them.",
        ),
        alternatives=(
            "A client with a saved wrong password.",
            "Backup with retries.",
            "NAT: several users behind the address.",
        ),
        beginner=(
            "From one address someone tried to log in to an FTP server many "
            "times - it looks like password guessing."
        ),
    ),
    "http_binary_upload": TypeSpec(
        headline=(
            "{src} sent {post_count} POSTs with a non-text body to {host}, "
            "{total_body_bytes} bytes in total."
        ),
        why=(
            "Data leaves in pieces to someone else's service: documents and "
            "archives are taken out this way, or a second stage is uploaded. A "
            "non-text body going to an external host has almost no legitimate "
            "reason in a corporate network."
        ),
        next_steps=(
            "Open HTTP objects and look at the bodies of these POSTs.",
            "Check {host} against approved storage and services.",
            "Check the content for compression or encryption - a sign of a "
            "prepared upload.",
        ),
        alternatives=(
            "A legitimate user upload of a file to a web service.",
            "Backup or telemetry to the cloud.",
            "Binariness misjudged: compressed or encoded text.",
        ),
        beginner=(
            "Several files of unclear content were sent from the machine to an "
            "external site - that may be a normal document upload, or it may "
            "be data theft."
        ),
    ),
    "host_behavior_anomaly": TypeSpec(
        headline=(
            "Host {src} behaves unlike the others: {unique_dst_ips} distinct "
            "destinations, {total_flows} connections, {total_bytes} bytes "
            "outbound in {duration_sec} s."
        ),
        why=(
            "This host's behaviour profile - the number of distinct "
            "destinations, the volume and pace of outbound traffic - stands "
            "out from the overall distribution of the capture. This is a "
            "statistical hint, not proof: servers, backups and scanners look "
            "the same."
        ),
        next_steps=(
            "Open Timeline and see what this host was doing.",
            "Compare with other findings for the host: beaconing or "
            "large_transfer nearby makes the signal stronger.",
            "Check the list of destinations in the flows: are they familiar "
            "services.",
        ),
        alternatives=(
            "A server or workstation with scheduled sync.",
            "A host running several users or roles.",
            "A scanner or monitoring agent with broad destination coverage.",
        ),
        beginner=(
            "One machine on the network stands out from the others by how many "
            "different addresses it visits and how much data it gives away. "
            "That is a reason to look closer, but not necessarily an attack."
        ),
    ),
    "ip_check_service": TypeSpec(
        headline=(
            "{src} contacted an external IP check service: {value} "
            "({sources})."
        ),
        why=(
            "'What is my address' is a typical first step after launch: the "
            "program learns that it reached the internet and picks a route to "
            "C2. On its own it is harmless; the value is in what happens next."
        ),
        next_steps=(
            "Look at Timeline: where the host went in the following minutes.",
            "Check whether such a request is expected for this host.",
        ),
        alternatives=(
            "A VPN or proxy client checking the exit.",
            "A browser extension, a game, an anti-cheat.",
            "An administrator looking up the NAT address of the network.",
        ),
        beginner=(
            "A program asked the internet what its external address is - "
            "ordinary applications do that, and so does malware before going "
            "out to its server."
        ),
    ),
    "ja3_malware": TypeSpec(
        headline=(
            "{src} -> {dst}: a TLS client with the fingerprint of tool "
            "{tool_name} (ja3 {ja3}), {flow_count} flows."
        ),
        why=(
            "The fingerprint shows how the client assembles the TLS handshake. "
            "A match with a known tool means this is not the user's browser "
            "but a program that someone launched."
        ),
        next_steps=(
            "Check {src} against the inventory: whose host it is and what "
            "should run there.",
            "Check the certificate and SNI of these flows.",
            "Compare with the rest of the host's traffic: the tool usually "
            "talks to one or two addresses.",
        ),
        alternatives=(
            "The fingerprint matched a legitimate client on the same library.",
            "The database is stale: the tool was updated.",
            "A corporate agent built on the same TLS stack.",
        ),
        beginner=(
            "The program says hello on connect the same way a known hacking "
            "tool does - indirect evidence, but weighty."
        ),
    ),
    "ja3s_malware": TypeSpec(
        headline=(
            "{src} -> {dst}: the server answered with the fingerprint of tool "
            "{tool_name} (ja3s {ja3s}), {flow_count} flows."
        ),
        why=(
            "The server fingerprint matched a known C2 or malware stack. Such "
            "an answer usually comes from a hand-rolled handler, not from a "
            "normal web server behind a load balancer."
        ),
        next_steps=(
            "Check {dst} in Enrichment: reputation, ASN, who else talks to "
            "it.",
            "Look at the certificate: self-signed, fresh, no SAN.",
            "Find other hosts in the capture that contacted this address.",
        ),
        alternatives=(
            "A legitimate service on the same TLS stack.",
            "A test bench or an internal load balancer.",
            "An outdated fingerprint database.",
        ),
        beginner=(
            "The server answers the same way known malicious control servers "
            "do."
        ),
    ),
    "kerberoasting": TypeSpec(
        headline=(
            "{src} requested tickets for {distinct_spns} different services, "
            "{rc4_requests} of them RC4."
        ),
        why=(
            "A service ticket is encrypted with the password of its account and "
            "can be carried away. The password is then cracked offline, with no "
            "lockouts and no limits on the domain controller."
        ),
        next_steps=(
            "Check which accounts have SPNs and how long their passwords are.",
            "Check application activity: who legitimately requests these "
            "services.",
            "See what {src} did afterwards: replication, SMB, RDP.",
        ),
        alternatives=(
            "An application requests a service ticket when a user logs in.",
            "An AD vulnerability scanner or a contractor audit.",
            "An administrator checking SPN settings.",
        ),
        beginner=(
            "The machine asked the domain for passes to various services - such "
            "passes can be carried away and their password guessed without a "
            "limit on attempts."
        ),
    ),
    "large_transfer": TypeSpec(
        headline=(
            "{src} -> {dst}:{port} - {total_bytes} bytes in one session, "
            "direction {direction}."
        ),
        why=(
            "A volume of this order is rarely accidental: either a legitimate "
            "file transfer or data exfiltration. Direction and time of day "
            "decide which one you are looking at."
        ),
        next_steps=(
            "Check {dst}:{port} against the service: cloud, backup, updates.",
            "Compare the volume with the host's normal daily profile.",
            "Check whether the data is compressed: high entropy before sending "
            "is a sign of packing.",
        ),
        alternatives=(
            "Backup to the cloud.",
            "An update or a disk image download.",
            "Streaming, a video call, a large file transfer.",
        ),
        beginner=(
            "A lot of data left in a single session - usually that is normal, "
            "but sometimes that is how data that must not leave the network is "
            "taken out."
        ),
    ),
    "lateral_movement": TypeSpec(
        headline=(
            "{src} connected to {dst}:{port} the way it is done when moving "
            "inside a network: {flow_count} flows."
        ),
        why=(
            "After the first access the attacker looks for a way further: "
            "administrative ports and remote control. These connections are "
            "what links the compromise of one machine to the rest."
        ),
        next_steps=(
            "Check whether an administrative task from {src} was scheduled at "
            "that time.",
            "Look at Timeline for {dst}: new accounts, copying, service "
            "starts.",
            "Open Finding details: the user agent and URI show which tool was "
            "used.",
        ),
        alternatives=(
            "A management system (SCCM, Ansible, Zabbix) with a service "
            "account.",
            "An administrator working by hand.",
            "Inventory from CMDB.",
        ),
        beginner=(
            "One machine connected to another the way administrators usually "
            "do. If it was not an administrator, that is a sign the attack is "
            "moving on."
        ),
    ),
    "long_connection": TypeSpec(
        headline=(
            "{src} kept a connection to {dst}:{port} for {duration_min} min, "
            "{packets_total} packets."
        ),
        why=(
            "A long session with sparse packets is a convenient channel: "
            "commands come in drops, the connection lives for hours and does "
            "not look like a file transfer. Interactive C2 and tunnels work "
            "this way."
        ),
        next_steps=(
            "Check what service runs on {dst}:{port}.",
            "Look at the packet distribution over time: even sparse bursts are "
            "a sign of a control channel.",
            "Check against VPN and remote-access tasks.",
        ),
        alternatives=(
            "A VPN or SSH session of an administrator.",
            "A long stream, a video call, a terminal.",
            "A session with a wrong duration at the capture boundary.",
        ),
        beginner=(
            "The connection did not close for hours - legitimate service "
            "channels work that way, and so does remote control of an infected "
            "machine."
        ),
    ),
    "nxdomain_burst": TypeSpec(
        headline=(
            "{src} received {nxdomain_count} NXDOMAIN answers, up to "
            "{max_in_window} in {window_sec} s."
        ),
        why=(
            "A burst of non-existent names is either an algorithm trying "
            "addresses or broken resolution. The look of the names and what "
            "happens afterwards help tell them apart."
        ),
        next_steps=(
            "Look at the names in Timeline: random means DGA, long means a "
            "tunnel.",
            "Check whether any of them resolved successfully.",
            "Check the DNS suffix settings on the host.",
        ),
        alternatives=(
            "A broken DNS cache or a wrong search suffix.",
            "Antivirus or EDR checking a list of domains.",
            "User typos in addresses.",
        ),
        beginner=(
            "The computer asked many times for names that do not exist. "
            "Sometimes that is a virus, sometimes it is broken settings."
        ),
    ),
    "php_download": TypeSpec(
        headline=(
            "{host} returned a body that starts with PHP code: {value}."
        ),
        why=(
            "Server code from an external host is either shell delivery or a "
            "source leak. In the first case the file is later placed into a web "
            "directory and called."
        ),
        next_steps=(
            "Open Injected code and Carved files: the body is kept for "
            "inspection.",
            "Check Timeline: was this URI requested after the download.",
            "Check who did the download: {src}.",
        ),
        alternatives=(
            "A developer downloading sources.",
            "A CDN serving PHP as text because of a configuration error.",
        ),
        beginner=(
            "A file was downloaded from a server with server code inside - such "
            "a file can become a back door into the site."
        ),
    ),
    "port_scan": TypeSpec(
        headline=(
            "{src} was sweeping addresses on port {port}: {distinct_dsts} "
            "destinations, most with one or two connections."
        ),
        why=(
            "Sweeping shows which services are reachable and what can be worked "
            "with next. It is preparation, not an attack: exploitation of "
            "whatever was found usually follows at once."
        ),
        next_steps=(
            "Identify whose address {src} is: inventory, ARP, DHCP.",
            "Look at Timeline: what happened to the discovered nodes "
            "afterwards.",
            "Check against the schedule of legitimate scans.",
        ),
        alternatives=(
            "A scheduled vulnerability scan (Nessus, OpenVAS, Xray).",
            "Monitoring or inventory walking the subnet.",
            "NAT: several hosts behind one address.",
        ),
        beginner=(
            "From one address someone knocked on the same port of different "
            "machines one after another - that is how open services are found."
        ),
    ),
    "rare_external_ip": TypeSpec(
        headline=(
            "{src} connected to {value}, which is absent from DNS answers: "
            "{flow_count} flows."
        ),
        why=(
            "Contacting a bare address means the name was never resolved and "
            "the address was known in advance. That is what a C2 hard-coded "
            "into a program looks like, and it bypasses DNS filtering."
        ),
        next_steps=(
            "Check the address in Enrichment: reputation, ASN, who else "
            "contacted it.",
            "Look at what went out in the flow and whether there was an "
            "answer.",
            "Check whether there is DoH or VPN from this host.",
        ),
        alternatives=(
            "A CDN or Anycast whose name is not in the capture.",
            "An address in an application config: licence server, NTP.",
            "The DNS answer arrived before recording started.",
        ),
        beginner=(
            "The computer connected to an address without asking DNS for its "
            "name - malware sometimes reaches its server that way."
        ),
    ),
    "script_download": TypeSpec(
        headline=(
            "{src} downloaded from {hosts} a file with a dangerous extension "
            "{extension}: {value}."
        ),
        why=(
            "Executable and script files are what is run to take control of a "
            "machine. They are either executed at once or placed into "
            "autostart."
        ),
        next_steps=(
            "Open Carved files: check YARA and the hash.",
            "Look at Injected code if the body made it into an excerpt.",
            "Check Timeline for {src}: what happened after the download.",
        ),
        alternatives=(
            "A legitimate distribution of updates or installers.",
            "A user downloading a driver, an installer or an archive.",
            "The extension is in the URI while the body is an HTML error "
            "page.",
        ),
        beginner=(
            "A file that is normally run on a computer was downloaded: usually "
            "an installer, but sometimes a virus."
        ),
    ),
    "smtp_spam": TypeSpec(
        headline=(
            "{src} sent mail to {recipients_count} addresses in one session, "
            "HELO {helo}."
        ),
        why=(
            "Bulk mail from a single machine is either a spam botnet or an open "
            "relay used to send phishing. Both are equally bad for the "
            "network."
        ),
        next_steps=(
            "Open Finding details: MAIL FROM, X-Mailer, the recipient list.",
            "Check whether {src} is authorised on the relay and whether it "
            "should send mail at all.",
            "Check the recipients against company domains.",
        ),
        alternatives=(
            "A legitimate mailing: marketing, notifications.",
            "Mail monitoring or a test environment.",
            "A recipient count error while parsing the session.",
        ),
        beginner=(
            "Mail was sent from one machine to dozens of recipients - that is "
            "how a spam run usually works."
        ),
    ),
    "sni_mismatch": TypeSpec(
        headline=(
            "{src} -> {dst}: the TLS name (SNI) and the HTTP request name "
            "(Host) disagree ({value})."
        ),
        why=(
            "The client presents itself as one domain and asks another one for "
            "data. This is a mechanism for bypassing filtering and a C2 "
            "technique through someone else's CDN."
        ),
        next_steps=(
            "Check the recipient ASN in Enrichment: whose CDN it is and "
            "whether it is allowed.",
            "Look at HTTP objects: what was requested inside the connection.",
            "Check the SNI against the server certificate.",
        ),
        alternatives=(
            "A legitimate multi-tenant CDN (CloudFront, Fastly).",
            "A corporate MITM proxy.",
            "The Host was taken from another flow - a parsing error.",
        ),
        beginner=(
            "The program said 'I am going to one site' and then asked for data "
            "from another - that is how blocks are bypassed."
        ),
    ),
    "sni_without_dns": TypeSpec(
        headline=(
            "{src} named {sni} in TLS, but there is no DNS answer for it in "
            "the capture: {flow_count} flows."
        ),
        why=(
            "A name the client never resolved is usually hard-coded into the "
            "program. That is typical for C2: the address is in the binary so "
            "that it does not show up in DNS. The second explanation is DNS "
            "that went outside the capture."
        ),
        next_steps=(
            "Check whether there is DoH, DoT or VPN from this host.",
            "Resolve the name separately and compare with the address of the "
            "connection.",
            "Look at the certificate: does it match the SNI.",
        ),
        alternatives=(
            "DoH/DoT: DNS is simply not visible in the capture.",
            "The DNS answer arrived before recording started.",
            "The name came from a built-in CDN list.",
        ),
        beginner=(
            "The program named a site, but we never saw it ask DNS for that "
            "name - so the name is stored inside it."
        ),
    ),
    "ssh_brute_force": TypeSpec(
        headline="{src} opened {attempts} SSH connections to {dst}:{port}.",
        why=(
            "SSH is the most common door into a server, and its passwords are "
            "often weak. A successful guess gives a full account rather than "
            "access to a single service."
        ),
        next_steps=(
            "Check the sshd logs on {dst}: were there successful logins.",
            "Look at Timeline: what was done after the login.",
            "Check whether password login is allowed for this service.",
        ),
        alternatives=(
            "A client with a wrong key and retries.",
            "A configuration manager with frequent checks.",
            "NAT: several users behind the address.",
        ),
        beginner=(
            "From one address someone tried to connect over SSH many times - "
            "it looks like password guessing."
        ),
    ),
    "successful_bruteforce": TypeSpec(
        headline=(
            "After a series of attempts from {src} the login succeeded: "
            "{success_uris}."
        ),
        why=(
            "This is already a compromise, not an attempt: the account was "
            "guessed. Next the attacker establishes a foothold and looks for a "
            "way on, often under the same account."
        ),
        next_steps=(
            "Check the account and all its sessions in Timeline.",
            "Check the service logs: is the login confirmed.",
            "Look at what was done from {src} after the login.",
        ),
        alternatives=(
            "A user forgot the password and got in on the tenth try.",
            "A captcha or a redirect gave a false sign of success.",
            "The response status is not visible in the capture: the only sign "
            "is the URI.",
        ),
        beginner=(
            "After many attempts the login finally worked - most likely the "
            "password was guessed."
        ),
    ),
    "suspicious_port": TypeSpec(
        headline=(
            "{src} connected to {value} - an address on a port from the "
            "suspicious list, {flow_count} flows."
        ),
        why=(
            "A non-standard port facing outward is a common way to move a "
            "control channel away from filters that watch 443 and 80. The port "
            "itself proves nothing; the protocol and the address matter."
        ),
        next_steps=(
            "Check which program on {src} opened the connection.",
            "Look at the first bytes of the session: the protocol may be "
            "hand-rolled.",
            "Check the address in Enrichment.",
        ),
        alternatives=(
            "A legitimate service on a non-standard port: a game, P2P, an "
            "internal system.",
            "A tunnel of an administrator.",
            "The port came from settings rather than from traffic.",
        ),
        beginner=(
            "A connection went to a non-standard port - ordinary programs "
            "sometimes work that way, but malicious ones hide there too."
        ),
    ),
    "typosquatting": TypeSpec(
        headline=(
            "{value} is a domain resembling '{brand}' ({kind}), {queries} "
            "queries."
        ),
        why=(
            "Look-alike domains are bought for phishing and delivery: a person "
            "sees a familiar name and does not check the address. The "
            "difference is of two kinds: the brand is written inside the name, "
            "or one or two letters are replaced."
        ),
        next_steps=(
            "Check the registration date and the owner of the domain.",
            "Look at Timeline: what was downloaded or entered on it.",
            "Check whether the domain appeared in mail, if there is mail "
            "traffic.",
        ),
        alternatives=(
            "A legitimate domain whose name contains the brand word.",
            "A partner, a franchise or a regional subdomain.",
            "A user typo in the address.",
        ),
        beginner=(
            "The address looks very much like the name of a well-known "
            "company, but it is not its domain - that is how fake sites are "
            "made."
        ),
    ),
    "vulnerable_path": TypeSpec(
        headline=(
            "A known vulnerable path was requested: {value}, {count} "
            "requests."
        ),
        why=(
            "Backups, .git, configs and admin panels are probed to find what "
            "was left open. A file that is found is a data leak with no "
            "exploitation at all."
        ),
        next_steps=(
            "Check HTTP objects: what the server answered and whether the body "
            "is not empty.",
            "Make sure the path is really closed or absent.",
            "See who requested it: {src}.",
        ),
        alternatives=(
            "A vulnerability scanner or a bot.",
            "A manual check by an administrator.",
            "An old bookmark or a client with a hard-coded path.",
        ),
        beginner=(
            "Someone requested an address where backups or settings usually "
            "sit - if such a file exists, it can be downloaded."
        ),
    ),
    "web_scanner": TypeSpec(
        headline=(
            "{src} walked {distinct_paths} different paths on {dst} - a "
            "scanner profile."
        ),
        why=(
            "A scanner looks for vulnerable pages from a list. This is not an "
            "attack yet, but exploitation of whatever was found usually follows "
            "right behind it."
        ),
        next_steps=(
            "Check whether an exploit request followed the scan: command "
            "injection, shell upload.",
            "Check against the schedule of legitimate scans.",
            "Look at Timeline: which paths answered 200.",
        ),
        alternatives=(
            "A scheduled scan (Acunetix, Burp, Nikto).",
            "A CDN or WAF health check over a list of paths.",
            "A search crawler.",
        ),
        beginner=(
            "Many addresses on a site were walked from one address - that is "
            "how vulnerable pages are found."
        ),
    ),
    "webshell_signature": TypeSpec(
        headline=(
            "{value}: the body matched the signature of family {family} "
            "({marker})."
        ),
        why=(
            "A signature match means the shell is already on the server or is "
            "served from it. From this moment foreign code may be running on "
            "the machine."
        ),
        next_steps=(
            "Open Injected code and read the excerpt - read only, do not "
            "execute.",
            "Check Timeline: was this URI requested after the upload.",
            "Check the file hash in Enrichment.",
        ),
        alternatives=(
            "An antivirus test sample in the traffic.",
            "A legitimate admin script with the same functions.",
            "A false match on a set of markers.",
        ),
        beginner=(
            "Code that looks like a back door for a site was found in the "
            "traffic: such a file lets commands run on the server."
        ),
    ),
    "webshell_upload": TypeSpec(
        headline=(
            "{value}: PHP code was found in the request body - it looks like a "
            "web shell upload."
        ),
        why=(
            "Uploading server code gives command execution on the site. Such a "
            "file is usually used to pull tools and steal data, and in the logs "
            "it looks like an ordinary request."
        ),
        next_steps=(
            "Open Injected code: the request body and a safe preview are "
            "there.",
            "Check Timeline: was this URI requested after the upload.",
            "Look at the server answer: 200 means the file was accepted.",
        ),
        alternatives=(
            "A routine deploy: a developer uploads a PHP file.",
            "The body turned out to be a code sample rather than an executable "
            "file.",
            "A test bench or a training exercise.",
        ),
        beginner=(
            "Someone sent a file with server code to the server - if the server "
            "stored it, the site can be controlled through that file."
        ),
    ),
    "yara_match": TypeSpec(
        headline=(
            "Rule {rule} matched file {filename}, sha256 {sha256}."
        ),
        why=(
            "YARA looks for characteristic strings of known families - the most "
            "concrete evidence of all heuristics. The file can then be checked "
            "independently: by hash and in a sandbox."
        ),
        next_steps=(
            "Check the sha256 in Enrichment and in MalwareBazaar.",
            "Open Carved files and look at the body.",
            "Check Timeline: where the file was downloaded from and whether it "
            "was run.",
        ),
        alternatives=(
            "The rule is too broad: a common marker matched.",
            "A legitimate file contains the same string: a library, an "
            "installer.",
            "The body was cut by the size limit, the match may be accidental.",
        ),
        beginner=(
            "The file contains strings characteristic of known viruses - strong "
            "evidence, but it has to be confirmed."
        ),
    ),
}
