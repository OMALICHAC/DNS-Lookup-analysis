# DNS Lookup Analysis — Network Traffic Examination with Wireshark

![Wireshark](https://img.shields.io/badge/Wireshark-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)
![Network Analysis](https://img.shields.io/badge/Network_Analysis-005571?style=for-the-badge)
![PCAP](https://img.shields.io/badge/PCAP-2C2C2C?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-CC0000?style=for-the-badge&logo=hackthebox&logoColor=white)

---

## Table of Contents

1. [What This Project Is](#what-this-project-is)
2. [How Attackers Abuse DNS](#how-attackers-abuse-dns)
3. [What Is in the Capture File](#what-is-in-the-capture-file)
4. [How to Open and Analyze](#how-to-open-and-analyze)
5. [Key Wireshark Filters for DNS](#key-wireshark-filters-for-dns)
6. [What to Look For — A Security Analyst's Perspective](#what-to-look-for--a-security-analysts-perspective)
7. [Tools Used](#tools-used)
8. [Author](#author)
9. [License](#license)

---

## What This Project Is

A packet capture of DNS traffic that I recorded and analyzed using Wireshark. The capture file (`DNS lookup analysis.pcapng`) contains real DNS queries and responses from a live network. I filtered the traffic, examined individual query/response pairs, and looked for patterns that would stand out during a security review.

---

## How Attackers Abuse DNS

- **DNS Tunneling** — Encoding data inside DNS queries to exfiltrate information or set up command-and-control channels.
- **DNS Hijacking** — Redirecting queries to a malicious resolver so victims reach fraudulent servers instead of legitimate ones.
- **Domain Generation Algorithms (DGAs)** — Malware generating pseudo-random domain names in bulk to find attacker-registered C2 domains.
- **DNS Cache Poisoning** — Injecting forged responses into a resolver's cache to redirect users to malicious IPs.

---

## What Is in the Capture File

### DNS Record Types

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
- **TTL values** — How long a resolver should cache a response.
- **Response codes** — `NOERROR`, `NXDOMAIN`, `SERVFAIL`.
- **Recursive vs. iterative queries** — Recursion Desired (RD) and Recursion Available (RA) flag behavior.

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

### Unusual Query Volume

A single host firing off hundreds of DNS queries in a short window is a red flag. Legitimate browsing produces varied, moderate query patterns — malware tends to be rapid and repetitive.

### Queries to Suspicious or Randomized Domains

Domain names like `xk4m9q2z.badactor.com` point to DGA-based malware. Look for high-entropy strings in the subdomain label.

### DNS Responses with Unexpected IP Addresses

If a well-known domain resolves to an IP outside its normal range, that could mean DNS hijacking or cache poisoning. Cross-reference resolved IPs against known-good records.

### Abnormally Long DNS Names

DNS tunneling tools encode data in subdomain labels, producing queries like:

```
dGhpcyBpcyBlbmNvZGVk.data.attacker-domain.com
```

Any query with unusually long or Base64-like subdomain components warrants investigation.

### High Volume of NXDOMAIN Responses

A flood of `NXDOMAIN` responses hitting a single host often means malware cycling through DGA domains, most of which the attacker hasn't registered yet.

### Queries to Non-Standard DNS Servers

Legitimate clients query their configured resolver. Queries going to unknown or foreign DNS servers may mean a host has been compromised and reconfigured.

### DNS over Non-Standard Ports

Standard DNS runs on UDP port 53. DNS traffic on other ports may indicate tunneling or an attempt to dodge firewall rules.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| [Wireshark](https://www.wireshark.org/) | Packet capture and protocol analysis |

---

## Author

**Chioma Iroka**
Computer Science Graduate | Cybersecurity Focus
- GitHub: [github.com/ChiomaIroka](https://github.com/ChiomaIroka)

---

## License

This project is licensed under the [MIT License](LICENSE).
