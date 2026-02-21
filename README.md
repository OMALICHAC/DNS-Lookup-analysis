# DNS Lookup Analysis — Network Traffic Examination with Wireshark

![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)
![Network Analysis](https://img.shields.io/badge/Network_Analysis-005571?style=for-the-badge)
![PCAP](https://img.shields.io/badge/PCAP-2C2C2C?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-CC0000?style=for-the-badge&logo=hackthebox&logoColor=white)

---

## Table of Contents

1. [What This Project Is](#what-this-project-is)
2. [Why DNS Analysis Matters](#why-dns-analysis-matters)
3. [What Is in the Capture File](#what-is-in-the-capture-file)
4. [How to Open and Analyze](#how-to-open-and-analyze)
5. [Key Wireshark Filters for DNS](#key-wireshark-filters-for-dns)
6. [What to Look For — A Security Analyst's Perspective](#what-to-look-for--a-security-analysts-perspective)
7. [Skills Demonstrated](#skills-demonstrated)
8. [Tools Used](#tools-used)
9. [Author](#author)
10. [License](#license)

---

## What This Project Is

This repository contains a hands-on network traffic analysis exercise built around a real packet capture of DNS (Domain Name System) activity. Using Wireshark, the industry-standard protocol analyzer, the capture file records live DNS queries and responses generated during normal network usage.

The goal of this project is to demonstrate the ability to:

- **Capture** network traffic in a controlled environment using Wireshark.
- **Filter** raw packet data to isolate DNS protocol activity from the broader traffic stream.
- **Examine** individual DNS queries and responses to understand how domain name resolution operates at the packet level.
- **Identify** patterns, anomalies, and indicators that a security analyst would flag during routine traffic review.

This is not a theoretical exercise. The included `.pcapng` file contains actual captured packets that can be opened, inspected, and analyzed by anyone with a copy of Wireshark.

---

## Why DNS Analysis Matters

### The Role of DNS in Network Communication

The Domain Name System is one of the most fundamental protocols on the internet. Every time a user visits a website, sends an email, or connects to a cloud service, a DNS query translates a human-readable domain name (such as `example.com`) into a machine-routable IP address (such as `93.184.216.34`). Without DNS, modern networking would be essentially unusable.

Because DNS is involved in nearly every network transaction, it is also one of the most valuable sources of intelligence for security operations.

### How Attackers Abuse DNS

Threat actors exploit DNS in several well-documented ways:

- **DNS Tunneling** — Attackers encode data within DNS queries and responses to exfiltrate information or establish command-and-control (C2) channels. Because DNS traffic is rarely blocked by firewalls, it provides a covert communication path. Tunneling often manifests as unusually long subdomain labels or high query volumes to a single domain.

- **DNS Hijacking** — An attacker redirects DNS queries to a malicious resolver, causing victims to reach fraudulent servers instead of legitimate ones. This can be used to harvest credentials, distribute malware, or intercept sensitive communications.

- **Domain Generation Algorithms (DGAs)** — Malware families use algorithmic techniques to generate large numbers of pseudo-random domain names. The malware queries these domains until it finds one that the attacker has registered, establishing a C2 link. DGA traffic is recognizable by its high volume of queries to domains that appear random or nonsensical.

- **DNS Cache Poisoning** — By injecting forged DNS responses into a resolver's cache, an attacker can redirect all users of that resolver to a malicious IP address. This attack exploits weaknesses in how DNS resolvers validate responses.

### Why SOC Analysts Must Understand DNS Traffic

Security Operations Center (SOC) analysts encounter DNS data constantly. SIEM platforms, EDR tools, and network monitoring systems all surface DNS activity. An analyst who can read raw DNS packets — who understands the structure of a query, the meaning of response codes, and the significance of TTL values — is equipped to:

- Detect data exfiltration attempts hidden in DNS queries.
- Identify compromised hosts communicating with C2 infrastructure.
- Recognize reconnaissance activity where attackers enumerate subdomains.
- Correlate DNS logs with other telemetry to build a complete picture of an incident.

---

## What Is in the Capture File

### About the File Format

The file `DNS lookup analysis.pcapng` is a **PCAPNG** (Packet Capture Next Generation) file. This is the modern successor to the original PCAP format and is the default capture format used by Wireshark. PCAPNG supports multiple interfaces, enhanced metadata, and annotations that the legacy format does not.

The file can be opened with Wireshark on any operating system (Windows, macOS, Linux) and can also be processed by command-line tools such as `tshark`, `tcpdump`, and `editcap`.

### Types of DNS Traffic You Can Examine

Within the capture, the following DNS record types and protocol behaviors may be present:

| Record Type | Purpose |
|-------------|---------|
| **A** | Maps a domain name to an IPv4 address |
| **AAAA** | Maps a domain name to an IPv6 address |
| **CNAME** | Canonical name alias — points one domain to another |
| **MX** | Mail exchange — identifies the mail server for a domain |
| **PTR** | Reverse DNS — maps an IP address back to a domain name |
| **SOA** | Start of authority — administrative information about a DNS zone |
| **TXT** | Text records — often used for SPF, DKIM, and domain verification |

Beyond record types, the capture allows examination of:

- **Query/Response pairs** — Matching a client's DNS question to the server's answer.
- **Transaction IDs** — Correlating queries and responses by their unique identifier.
- **TTL (Time to Live) values** — Understanding how long a resolver should cache a response.
- **Response codes** — Identifying successful lookups (`NOERROR`), failed lookups (`NXDOMAIN`), and server errors (`SERVFAIL`).
- **Recursive vs. iterative queries** — Observing how the Recursion Desired (RD) and Recursion Available (RA) flags behave.

---

## How to Open and Analyze

### Prerequisites

- **Wireshark** (version 3.x or later recommended) — Download free from [wireshark.org](https://www.wireshark.org/download.html).

### Step-by-Step Guide

**Step 1: Clone the Repository**

```bash
git clone https://github.com/your-username/DNS-Lookup-analysis.git
cd DNS-Lookup-analysis
```

**Step 2: Open the Capture File**

Launch Wireshark, then open the file:

```
File > Open > DNS lookup analysis.pcapng
```

Wireshark will load all captured packets and display them in the packet list pane.

**Step 3: Apply a DNS Display Filter**

In the display filter bar at the top of Wireshark, type:

```
dns
```

Press **Enter**. Wireshark will now show only DNS protocol packets, hiding all other traffic (TCP handshakes, HTTP requests, ARP, etc.).

**Step 4: Examine a DNS Query**

Click on any packet where the **Info** column shows `Standard query`. In the packet details pane (middle section), expand the following:

```
Domain Name System (query)
  > Queries
    > [domain name]: type A, class IN
```

This reveals the exact domain name the client is attempting to resolve and the record type being requested.

**Step 5: Find the Matching Response**

Look for a packet shortly after the query with the same **Transaction ID** and an Info column showing `Standard query response`. Expand the **Answers** section to see the resolved IP address, TTL, and any additional records.

**Step 6: Filter for Queries Only**

To see only outbound DNS questions (no responses), apply this filter:

```
dns.flags.response == 0
```

This isolates client-side behavior — showing exactly which domains a host attempted to resolve.

**Step 7: Filter for a Specific Domain**

To search for queries about a particular domain:

```
dns.qry.name contains "example"
```

Replace `"example"` with any domain or substring of interest.

---

## Key Wireshark Filters for DNS

The following display filters are essential for DNS traffic analysis:

| Filter | Description |
|--------|-------------|
| `dns` | Show all DNS traffic (queries and responses) |
| `dns.flags.response == 0` | Show only DNS queries (outbound questions) |
| `dns.flags.response == 1` | Show only DNS responses (inbound answers) |
| `dns.qry.name` | Filter by the queried domain name field |
| `dns.qry.name contains "keyword"` | Find queries containing a specific string |
| `dns.qry.type == 1` | Show only A record queries (IPv4) |
| `dns.qry.type == 28` | Show only AAAA record queries (IPv6) |
| `dns.qry.type == 5` | Show only CNAME record queries |
| `dns.qry.type == 15` | Show only MX record queries |
| `dns.flags.rcode == 3` | Show NXDOMAIN responses (domain does not exist) |
| `dns.flags.rcode == 2` | Show SERVFAIL responses (server failure) |
| `dns.resp.ttl < 60` | Show responses with a TTL under 60 seconds |
| `dns.count.answers > 5` | Show responses with more than 5 answer records |
| `udp.port == 53` | Show all traffic on the standard DNS port |
| `dns && ip.addr == 8.8.8.8` | Show DNS traffic to or from Google's public resolver |

These filters can be combined with logical operators (`&&`, `||`, `!`) to build more targeted queries.

---

## What to Look For — A Security Analyst's Perspective

When reviewing DNS traffic in a capture file, a security analyst should pay attention to the following indicators:

### Unusual Query Volume

A single host generating hundreds or thousands of DNS queries in a short period may indicate malware activity, particularly domain generation algorithm (DGA) behavior. Legitimate browsing produces a moderate, varied query pattern. Malware often produces rapid, repetitive, or sequential queries.

### Queries to Suspicious or Randomized Domains

Domain names that appear to be randomly generated strings (e.g., `xk4m9q2z.badactor.com`) are a strong indicator of DGA-based malware. Analysts should look for domains with high entropy in the subdomain label.

### DNS Responses with Unexpected IP Addresses

If a well-known domain resolves to an IP address outside its normal range, this could indicate DNS hijacking or cache poisoning. Cross-referencing resolved IPs against known-good records or threat intelligence feeds is standard practice.

### Abnormally Long DNS Names

The DNS protocol allows labels up to 63 characters and full names up to 253 characters. DNS tunneling tools exploit this by encoding data in subdomain labels, producing queries like:

```
dGhpcyBpcyBlbmNvZGVk.data.attacker-domain.com
```

Any query with unusually long or Base64-like subdomain components warrants investigation.

### High Volume of NXDOMAIN Responses

A large number of `NXDOMAIN` (Non-Existent Domain) responses directed at a single host may indicate that the host is running malware that is cycling through DGA domains, most of which are not yet registered by the attacker.

### Queries to Non-Standard DNS Servers

Legitimate clients typically query their configured resolver (e.g., the corporate DNS server or a public resolver like `8.8.8.8`). Queries directed to unknown or foreign DNS servers may indicate that a host has been compromised and reconfigured.

### DNS over Non-Standard Ports

Standard DNS uses UDP port 53 (and occasionally TCP port 53 for large responses or zone transfers). DNS traffic on other ports may indicate tunneling or an attempt to evade firewall rules.

---

## Skills Demonstrated

This project demonstrates the following competencies relevant to cybersecurity and network security roles:

- **Network Traffic Capture and Analysis** — Capturing live traffic and working with packet-level data in PCAPNG format.
- **Wireshark Proficiency** — Navigating the Wireshark interface, applying display filters, and interpreting the packet details pane.
- **DNS Protocol Understanding** — Knowledge of DNS query/response structure, record types, response codes, TTL behavior, and recursion flags.
- **DNS Security Concepts** — Awareness of DNS-based attack techniques including tunneling, hijacking, cache poisoning, and domain generation algorithms.
- **Threat Detection Methodology** — Ability to identify indicators of compromise (IOCs) within DNS traffic and articulate why specific patterns are suspicious.
- **Documentation and Communication** — Presenting technical findings in a clear, structured format suitable for both technical and non-technical audiences.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| [Wireshark](https://www.wireshark.org/) | Packet capture and protocol analysis |

---

## Author

**Chioma Iroka**
Computer Science Graduate | Cybersecurity Focus

This project is part of a cybersecurity portfolio demonstrating practical skills in network analysis, traffic examination, and security operations. For questions or collaboration opportunities, feel free to connect.

---

## License

This project is licensed under the [MIT License](LICENSE).

You are free to use, modify, and distribute this project for educational and professional purposes. The packet capture file contains network traffic generated in a controlled environment and does not include sensitive or personally identifiable information.
