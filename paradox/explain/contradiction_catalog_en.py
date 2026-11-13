"""Английские шаблоны объяснений для правил contradictions.

Двойник `contradiction_catalog.py`: то, чего у правила нет, - зачем это
аналитику, куда смотреть дальше и как объяснить новичку. Тексты обязаны
быть верны при любом направлении и порядке фактов. Паритет ключей и
подстановок держит тест.
"""
from __future__ import annotations

from paradox.explain.model import TypeSpec

RULE_SPECS_EN: dict[str, TypeSpec] = {
    "direct_ip_no_dns": TypeSpec(
        headline="{subject} works over IP without making DNS queries: {facts}.",
        why=(
            "A program that knows addresses in advance and does not ask DNS "
            "usually carries them inside: that is how C2 works, and clients "
            "that bypass DNS filtering. There is a legitimate explanation too: "
            "an address in a config."
        ),
        next_steps=(
            "List the addresses in Timeline and check them in Enrichment.",
            "Check whether the host has DoH/DoT: then DNS is simply not "
            "visible.",
            "Check the addresses against configs of known applications.",
        ),
        alternatives=(
            "An application with a hard-coded server address: licensing, "
            "updates.",
            "DNS went outside the capture: DoH, VPN, another interface.",
        ),
        beginner=(
            "The machine connects to addresses without ever asking DNS for "
            "their names - malware sometimes reaches its server that way."
        ),
    ),
    "dns_answer_mismatch": TypeSpec(
        headline=(
            "DNS answered with a different address than the connection went to "
            "({subject}): {facts}."
        ),
        why=(
            "The client resolved the name to one address and connected to "
            "another. This is either an answer substitution, or a proxy "
            "changing the route, or an answer that arrived for a different "
            "query."
        ),
        next_steps=(
            "Compare the answer time and the connection time in Timeline.",
            "Compare the answer with an external resolver: substitution shows "
            "as a difference.",
            "Check whether there is a proxy or a load balancer on the path.",
        ),
        alternatives=(
            "CDN/Anycast: DNS returns one node, the connection goes to "
            "another.",
            "A corporate proxy or MITM interception.",
            "The DNS answer was received after the connection.",
        ),
        beginner=(
            "The name turned into one address while the program went to "
            "another - normal for large sites, and sometimes a sign of "
            "substitution."
        ),
    ),
    "expired_cert": TypeSpec(
        headline="The server certificate has expired ({subject}): {facts}.",
        why=(
            "An expired certificate is either a forgotten bench or a server "
            "that nobody looks after. Malware often does not watch the term, "
            "but normal services are sometimes expired too."
        ),
        next_steps=(
            "Check what service runs on this address.",
            "Check the inventory: is this your service or an external one?",
        ),
        alternatives=(
            "Someone forgot to renew the certificate on a legitimate service.",
            "A test bench or an internal system.",
        ),
        beginner=(
            "The server certificate has expired - that happens to normal sites "
            "too, but almost always to malicious ones."
        ),
    ),
    "ja3_ua_mismatch": TypeSpec(
        headline=(
            "The TLS fingerprint does not match the User-Agent at {subject}: "
            "{facts}."
        ),
        why=(
            "The client presents itself as a browser, but its TLS stack belongs "
            "to a tool. That is how automation is disguised as a live user."
        ),
        next_steps=(
            "Compare the JA3 with this host's earlier traffic.",
            "Look at what the client downloaded and where it went.",
            "Check the certificate and Host in the same flows.",
        ),
        alternatives=(
            "A legitimate program on an embedded browser (Electron, WebView) "
            "with its own TLS stack.",
            "A proxy or antivirus changing the User-Agent.",
        ),
        beginner=(
            "The program says 'I am a browser' but says hello like another "
            "program - that is how bots and viruses disguise themselves."
        ),
    ),
    "mac_ip_conflict": TypeSpec(
        headline=(
            "Several MAC addresses were seen for address {subject}: {facts}."
        ),
        why=(
            "One IP on two MACs at the same time is either ARP spoofing and "
            "traffic interception, or an address conflict, or a virtual machine "
            "migration."
        ),
        next_steps=(
            "Check the MAC against inventory and DHCP leases.",
            "Check whether ARP anomalies occurred at the same time.",
            "Find the switch port where the second MAC is visible.",
        ),
        alternatives=(
            "ARP spoofing or MITM on the local network.",
            "An IP conflict: two devices configured with one address.",
            "A virtual machine migration or a network card replacement.",
        ),
        beginner=(
            "One network address turned out to have two 'passports' - that "
            "happens with spoofing or when a VM moves."
        ),
    ),
    "port_service_mismatch": TypeSpec(
        headline=(
            "The port carries a protocol other than the expected one "
            "({subject}): {facts}."
        ),
        why=(
            "A service on a foreign port bypasses port-based filtering: from "
            "outside it looks like ordinary traffic. Tunnels are hidden the "
            "same way."
        ),
        next_steps=(
            "Check which process listens on or opens this port.",
            "Look at the first bytes of the session: the protocol may be "
            "hand-rolled.",
            "Check against firewall rules and approved services.",
        ),
        alternatives=(
            "A legitimate service moved to a non-standard port.",
            "A proxy or load balancer translating the protocol.",
            "A classification error based on the first packet.",
        ),
        beginner=(
            "On a port where one service usually runs, something else is "
            "talking - that is one way a communication channel is hidden."
        ),
    ),
    "reverse_asymmetry": TypeSpec(
        headline="A sharp volume asymmetry in session {subject}: {facts}.",
        why=(
            "The volume in one direction clearly outweighs the other: either "
            "the host gives a lot away (exfiltration) or receives a lot "
            "(download). The skew alone is not a sign of attack: backup, "
            "streaming and a gateway produce it too."
        ),
        next_steps=(
            "Check direction and volume by packets, not only by counters.",
            "Check against the service profile: backup and streaming are "
            "always asymmetric.",
            "Check whether the data is compressed before sending.",
        ),
        alternatives=(
            "Exfiltration of data outward.",
            "A large file or update download.",
            "A gateway, NAT or CDN proxy: traffic of many clients aggregated.",
        ),
        beginner=(
            "One side transferred several times more than the other - a file "
            "download and data exfiltration both look like this."
        ),
    ),
    "role_deviation": TypeSpec(
        headline=(
            "{subject}: the behaviour does not match the baseline role - "
            "{facts}."
        ),
        why=(
            "The host is classified by MAC/OUI as a device of one type, while "
            "in traffic it behaves like another. A workstation answering like a "
            "web server, or a server scanning the network, is a sign of an "
            "unauthorised service or of a compromise."
        ),
        next_steps=(
            "Open Timeline and see when the host changed behaviour.",
            "Check open ports and processes on the host itself.",
            "Check the role against inventory: it may be a repurposed machine "
            "rather than an attack.",
        ),
        alternatives=(
            "The host was repurposed and the 'passport' (OUI) was not updated.",
            "A legitimate service is running on the host.",
            "The MAC changed or the host is shared (terminal/virtualisation).",
        ),
        beginner=(
            "The device behaves unlike its type: an ordinary computer suddenly "
            "answers like a server. That is a reason to check whether something "
            "extra has appeared on it."
        ),
    ),
    "self_signed_cert": TypeSpec(
        headline=(
            "A self-signed certificate on an external address ({subject}): "
            "{facts}."
        ),
        why=(
            "A browser will not accept such a certificate without an exception. "
            "For C2 that is normal: the server is set up for a while and nobody "
            "spends on a certificate authority."
        ),
        next_steps=(
            "Check the issuer and the term: a fresh self-signed certificate is "
            "a strong sign.",
            "Look at what service answers on this address.",
            "Check the address in Enrichment.",
        ),
        alternatives=(
            "A test bench or an internal service exposed to the outside.",
            "A device (camera, router, NAS) with a factory certificate.",
        ),
        beginner=(
            "The server issued an identity document to itself - a browser does "
            "not trust that, and malicious servers often do it."
        ),
    ),
    "sni_cert_mismatch": TypeSpec(
        headline=(
            "The certificate does not match the name the client requested "
            "({subject}): {facts}."
        ),
        why=(
            "The client asks for one domain while the server presents a "
            "certificate for another. This is either traffic interception, or a "
            "CDN, or certificate substitution."
        ),
        next_steps=(
            "Check the issuer and the SAN of the certificate.",
            "Compare with the expected certificate of the service.",
            "Check whether there is an intercepting proxy on the host.",
        ),
        alternatives=(
            "A corporate MITM proxy or antivirus.",
            "A CDN serving a certificate in its own name.",
            "SNI and certificate were taken from different flows.",
        ),
        beginner=(
            "The program asked for one site while the server showed a document "
            "for another name - that happens when traffic is intercepted."
        ),
    ),
    "sni_host_mismatch": TypeSpec(
        headline=(
            "The TLS name (SNI) and the HTTP request name (Host) disagree at "
            "{subject}: {facts}."
        ),
        why=(
            "The client presents itself as a legitimate CDN while asking for "
            "another domain inside - that is domain fronting: bypassing blocks "
            "and C2 through someone else's infrastructure."
        ),
        next_steps=(
            "Check the recipient ASN: whose CDN it is and whether it is allowed "
            "in the company.",
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
            "Client {subject} named a name absent from DNS answers: {facts}."
        ),
        why=(
            "A name the client never resolved is usually hard-coded into the "
            "program - typical for C2. The second option: DNS went outside the "
            "capture, through DoH."
        ),
        next_steps=(
            "Check whether there is DoH/DoT or VPN from this host.",
            "Resolve the name separately and compare with the address of the "
            "connection.",
            "Look at the certificate: does it match the SNI.",
        ),
        alternatives=(
            "DoH/DoT: DNS is not visible in the capture.",
            "The DNS answer arrived before recording started.",
        ),
        beginner=(
            "The program named a site, but we never saw it ask DNS for that "
            "name - so the name is stored inside it."
        ),
    ),
    "victim_makes_attack": TypeSpec(
        headline="{subject} is both victim and attack source: {facts}.",
        why=(
            "Either the host is compromised and used as a foothold, or one of "
            "the findings is wrong. This is the node to work through: it links "
            "two stages of the attack."
        ),
        next_steps=(
            "Determine which finding came first in time.",
            "Check accounts, processes and autostart on {subject}.",
            "Look where the host went after it became an attack source.",
        ),
        alternatives=(
            "The host is compromised and is attacking further.",
            "Attribution error: the src/dst role in one of the findings is "
            "swapped.",
        ),
        beginner=(
            "The same computer looks like a victim in some events and like the "
            "attacker in others. Usually it was broken into and is being used "
            "onwards."
        ),
    ),
}
