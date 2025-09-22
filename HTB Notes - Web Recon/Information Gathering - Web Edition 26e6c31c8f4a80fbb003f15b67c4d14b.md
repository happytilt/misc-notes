# Information Gathering - Web Edition

- Identify Assets
- Discover Hidden Info
- Analyzing Attack Surface
- Gather Intelligence

![image.png](Information%20Gathering%20-%20Web%20Edition%2026e6c31c8f4a80fbb003f15b67c4d14b/image.png)

**Active Recon** - Direct interaction with target system (noisy)

- Port/Vuln Scanning
- Network Mapping
- Banner Grabbing
OS Fingerprinting
- Service Enum
- Web Spidering

**Passive Recon** - No interaction with target; mainly OSINT

- Google Dorking
- WHOIS Lookups
- DNS Records
- Web Archive Analysis (Wayback Machine)
- Social Media
- Code Repos

# WHOIS

- Query and response protocol
- Access database of info on registered internet resources (primarily domain names)

**For Web Recon**

- Social engineering attacks or phishing campaigns
    - Records reveal real names, emails, and phone numbers
- Passively Maps Network
    - Records have name servers, IP addresses, etc
- `WhoisFreaks`, a historical WHOIS record service
    - Reveals changes to a record to ownership, contact info, other details over time
- Malware and Adversary analysis
    - Gain intel on an attacker’s domain through its WHOIS record
    - Often useful info on the C2 server
- Threat Intel Reports
    - Records provide insight on threat actor’s TTPs
    - IOCs can be discovered through WHOIS data

**WHOIS Records** contain:

1. Domain Name
2. Registrar - Company where domain was registered at (GoDaddy, Namecheap)
3. Registrant Contact - Person/Org that registered domain
4. Administrative Contact - Those responsible for managing domain
5. Technical Contact - Those responsible for handling domain tech issues
6. Creation and Expiration Dates
7. Name Servers - DNS serves that translate the domain into an IP address

## Using WHOIS

Linux command: `whois`

Output Example

```bash
happytilt@htb[/htb]$ whois facebook.com

   Domain Name: FACEBOOK.COM
   Registry Domain ID: 2320948_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.registrarsafe.com
   Registrar URL: http://www.registrarsafe.com
   Updated Date: 2024-04-24T19:06:12Z
   Creation Date: 1997-03-29T05:00:00Z
   Registry Expiry Date: 2033-03-30T04:00:00Z
   Registrar: RegistrarSafe, LLC
   Registrar IANA ID: 3237
   Registrar Abuse Contact Email: abusecomplaints@registrarsafe.com
   Registrar Abuse Contact Phone: +1-650-308-7004
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited
   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited
   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
   Name Server: A.NS.FACEBOOK.COM
   Name Server: B.NS.FACEBOOK.COM
   Name Server: C.NS.FACEBOOK.COM
   Name Server: D.NS.FACEBOOK.COM
   DNSSEC: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2024-06-01T11:24:10Z <<<

[...]
Registry Registrant ID:
Registrant Name: Domain Admin
Registrant Organization: Meta Platforms, Inc.
[...]
```

# DNS & Subdomains

- [DNS](https://www.notion.so/DNS-1ee6c31c8f4a80128996e9bbcaca39f3?pvs=21) - Translates domain names to IP address

## What happens you enter a URL in a browser?

1. DNS Query
    1. Browser checks local cache (like a host file) first
    2. Reaches out to a DNS Resolver (usually provided by ISP) if not found locally
2. Recursive Lookup
    1. DNS Resolver checks its cache
    2. If not found locally, go through DNS hierarchy
        1. Starting at Root Name Server
    3. Recursive = recursively querying other DNS servers in a hierarchical chain
3. Root Server points to TLD name server
    1. TLD name server responsible for domain name’s TLD
    2. TLD = `.com`, `.org`, etc.
4. TLD name server points to Authoritative name server
    1. Authoritative NS finds the specific domain
5. Authoritative Name Server returns result
    1. Recursive lookup result goes back to DNS Resolver
    2. DNS Resolver gives result to browser
6. Browser connects
    1. With an IP address, it knows where to go

## Hosts File

- Text file on your computer
- Manual and local way to map domain name → IP address
- skips the DNS lookup process

Windows File Location:

`C:\Windows\System32\drivers\etc\hosts`

Linux File Location:

`/etc/hosts`

File format:

```
#<IP Address>    <Hostname> [<Alias> ...]
#Redirect a domain to localhost for development
127.0.0.1       myapp.local

#Normal Entry
192.168.1.10    devserver.local another.one and.another

#Block website/domain
0.0.0.0       unwanted-site.com
```

- Needs admin/root privilege to edit hosts file

## DNS Zones

- A portion of the domain namespace that a specific organization or administrator manages
    - A domain can be managed as one zone with one zone file
- Can be multiple zones within the same domain namespace, created through delegation
    - Split a domain into different zones
    
    Example:
    
    - example.com (parent zone)
    - sales.example.com (child zone, delegated to another team)
    - dev.example.com (another child zone, maybe on a different server)
- **Zones define subdomains (through delegation)**
- **But not all subdomains are zones**

**Zone Splits in a DNS namespace example:**

```sql
( Root Zone )
     |
     └── com.   ← Zone for .com (managed by Verisign)
            |
            └── example.com.   ← Zone for example.com (managed by Org A)
                   |
                   ├── www.example.com.  (record in example.com zone)
                   ├── mail.example.com. (record in example.com zone)
                   └── sales.example.com.   ← Delegated → new zone (Org B)
                          |
                          └── app.sales.example.com. (record in sales.example.com zone)
```

**Zone File**

- Lives on DNS Server
- Defines resources within its zone

Example Zone File:

```
$TTL 3600 ; Default Time-To-Live (1 hour)
@       IN SOA   ns1.example.com. admin.example.com. (
                2024060401 ; Serial number (YYYYMMDDNN)
                3600       ; Refresh interval
                900        ; Retry interval
                604800     ; Expire time
                86400 )    ; Minimum TTL

@       IN NS    ns1.example.com.
@       IN NS    ns2.example.com.
@       IN MX 10 mail.example.com.
www     IN A     192.0.2.1
mail    IN A     198.51.100.1
ftp     IN CNAME www.example.com.
```

- `IN` - Internet; denotes IP protocol suite
- `NS records` - Specifies authoritative name servers for a zone (or domain)
- `MX records` - Mail server
- `A records` - DNS mappings of domain → IP in a zone
- `AAAA records` - DNS mappings of domain → IPv6 in a zone

- **All DNS Records in zone file**
    
    
    | **Record Type** | **Full Name** | **Description** | **Zone File Example** |
    | --- | --- | --- | --- |
    | `A` | Address Record | Maps a hostname to its IPv4 address. | `www.example.com.` IN A `192.0.2.1` |
    | `AAAA` | IPv6 Address Record | Maps a hostname to its IPv6 address. | `www.example.com.` IN AAAA `2001:db8:85a3::8a2e:370:7334` |
    | `CNAME` | Canonical Name Record | Creates an alias for a hostname, pointing it to another hostname. | `blog.example.com.` IN CNAME `webserver.example.net.` |
    | `MX` | Mail Exchange Record | Specifies the mail server(s) responsible for handling email for the domain. | `example.com.` IN MX 10 `mail.example.com.` |
    | `NS` | Name Server Record | Delegates a DNS zone to a specific authoritative name server. | `example.com.` IN NS `ns1.example.com.` |
    | `TXT` | Text Record | Stores arbitrary text information, often used for domain verification or security policies. | `example.com.` IN TXT `"v=spf1 mx -all"` (SPF record) |
    | `SOA` | Start of Authority Record | Specifies administrative information about a DNS zone, including the primary name server, responsible person's email, and other parameters. | `example.com.` IN SOA `ns1.example.com. admin.example.com. 2024060301 10800 3600 604800 86400` |
    | `SRV` | Service Record | Defines the hostname and port number for specific services. | `_sip._udp.example.com.` IN SRV 10 5 5060 `sipserver.example.com.` |
    | `PTR` | Pointer Record | Used for reverse DNS lookups, mapping an IP address to a hostname. | `1.2.0.192.in-addr.arpa.` IN PTR `www.example.com.` |

## Web Recon with DNS

- DNS records give lots of info during recon
    - Example - CNAME records pointing to old, vulnerable server
- Map a Network
    - Through analyzing A/AAAA records
- Monitoring Changes
    - New records might mean new vulnerable machine
- Information leak through TXT records

DNS Recon Tools (Linux)

`dig`

- Make manual DNS queries, zone transfers, and analyzing DNS records
- Common dig Commands
    
    
    | **Command** | **Description** |
    | --- | --- |
    | `dig domain.com` | Performs a default A record lookup for the domain. |
    | `dig domain.com A` | Retrieves the IPv4 address (A record) associated with the domain. |
    | `dig domain.com AAAA` | Retrieves the IPv6 address (AAAA record) associated with the domain. |
    | `dig domain.com MX` | Finds the mail servers (MX records) responsible for the domain. |
    | `dig domain.com NS` | Identifies the authoritative name servers for the domain. |
    | `dig domain.com TXT` | Retrieves any TXT records associated with the domain. |
    | `dig domain.com CNAME` | Retrieves the canonical name (CNAME) record for the domain. |
    | `dig domain.com SOA` | Retrieves the start of authority (SOA) record for the domain. |
    | `dig @1.1.1.1 domain.com` | Specifies a specific name server to query; in this case 1.1.1.1 |
    | `dig +trace domain.com` | Shows the full path of DNS resolution. |
    | `dig -x 192.168.1.1` | Performs a reverse lookup on the IP address 192.168.1.1 to find the associated host name. You may need to specify a name server. |
    | `dig +short domain.com` | Provides a short, concise answer to the query. |
    | `dig +noall +answer domain.com` | Displays only the answer section of the query output. |
    | `dig domain.com ANY` | Retrieves all available DNS records for the domain (Note: Many DNS servers ignore `ANY` queries to reduce load and prevent abuse, as per [RFC 8482](https://datatracker.ietf.org/doc/html/rfc8482)). |
    | `dig -x {IP_addr}` | Query DNS PTR (Pointer) used for reverse DNS lookup. Map an IP address back to a domain name |
- Output sections:
    - Header - Query type, status, and UID
    - Question - The DNS request; question
    - Answer - Answer to DNS query
    - Footer - Shows query delay, DNS server socket, timestamp, and message size

`nslookup`

- Simple/basic DNS queries

`host`

- Quick checks of A/AAAA/MX records

`dnsenum`

- Dns enumeration
- Discover subdomains and gather DNS info

`fierce`

- UI for DNS subdomain enumeration

`theHarvester`

- OSINT tool
- collects emails and info associated with a domain from many sources

# Subdomains

Subdomains represented by A/AAAA records

- CNAME records create aliases for subdomains

Looking for:

- Development/staging environments
- Hidden login and admin portals
- Legacy webapps
- Sensitive info leaks

## **Subdomain Enumeration**

**Passive Subdomain Enum**

- OSINT discovery and no interaction with domain
- `Certificate Transparency (CT) logs`
    - Public repo of SSL/TLS certs
    - Certs include subdomain info associated with domain in `Subject Alternative Name (SAN) field`
- Google Dorking and other search engines

**Active Subdomain Enum**

- Interacting with domain’s name server to find subdomains
- Attempting `DNS Zone Transfers`
    - Zone Transfer = Copying zone data from one Authoritative name server to another
        - Zone transfers enable redundancy between Authoritative NS
    - By default, if zone transfers are not restricted, anyone can request them
        - Can leak all DNS records
- `Brute Forcing`
    - Running a word list of subdomain names against a domain
    - tools: `dnsenum`, `ffuf`, `gobuster`

### DNS Zone Transfers

- *A DNS zone transfer is essentially a wholesale copy of all DNS records within a zone (a domain and its subdomains) from one name server to another.*

Remediation - Only allow zone transfers from trusted secondary name servers; with authentication

**Zone Transfer Process**

Primary name server = server holding zone file

Secondary name server = server request for zone transfer to it

1. Zone Transfer Request (AXFR)
    - Secondary server requests primary server
2. SOA Record Transfer
    - After receiving and authentication, primary server sends over SOA record
3. DNS Records Transmission
    - Primary server sends over all DNS records in the zone, one by one
4. Zone Transfer Complete
    - Once everything is sent, primary server sends end of zone signal
5. Acknowledgement (ACK)
    - Secondary server sends an ACK as a receipt for the zone transfer

Zone Transfer with `dig`

`dig axfr @{name server} {domain}`

### Subdomain Brute-Force Enumeration

1. Select a word list
2. Iteration and Querying
    1. example → example.com → dev.example.com
3. DNS Lookup
    1. Perform DNS query to check for existence
4. Filtering and Validation
    1. Take note of successful DNS resolutions
    2. Test for reachability via browser

Tools:

- `dnsenum` (Perl; widely-used CLI tool)
    - Attempts zone transfers
    - Brute Forcing
    - Google Scraping
    - Reverse lookups
    - WHOIS
- `fierce`
- `dnsrecon`
- `amass`
- `assetfinder`
- `puredns`

`dnsenum —enum {domain} -f /path/to/wordlist -r`

- “r” flag enables recursive subdomain brute-forcing
    - if dnsenum finds a subdomain, it will then try to enumerate subdomains of that subdomain

# **Virtual Hosts**

**Virtual Hosting**

- Web servers like Apache, Nginx, or IIS are designed to host multiple websites or applications on a single server
- HTTP `Host` header distinguishes between multiple websites or applications sharing the same IP address
- VHOSTs are mapped to a directory/app on a web server (one IP)
    - While subdomains are extensions of a domain
    - All subdomains can be vhosts
    - Not all vhosts are subdomains
- VHOSTs aren’t public and may not appear in DNS records
- Virtual hosts can also be configured to use different domains, not just subdomains

<aside>
🔍

If a virtual host does not have a DNS record, you can still access it by modifying the `hosts` file on your local machine. 

The `hosts` file allows you to map a domain name to an IP address manually, bypassing DNS resolution.

</aside>

**VHost Lookup Process**

1. Browser Requests a Website
2. Host header included in request
3. Web server checks and matches Host header with its configurations
4. Web server serves content from the VHOST specified in Host header

**Types of Virtual Hosting**

Name-Based

- Only relies on Host header
- Can have limitations with certain protocols like SSL/TLS

IP-Based

- Assigns a unique IP address to each website hosted on the server
- Doesn’t use Host header and can be used with any protocol
- Better isolation between sites but takes up IP addressing space

Port-Based

- VHosts are associated with different ports on one IP
- Not common or user-friendly; requires specifying port number in URL

## **Virtual Host Discovery Tools**

`gobuster vhost` - directory/file/vhost brute-forcing

- Automatically sends HTTP requests with different Host headers to a target IP
- `-u` = web server IP/domain
- `-w` = wordlist file
- `--append-domain` - appends base domain to each word in word list
- `-t` - thread count; go faster
- `-k` - Ignores SSL/TLS cert errors
- `-o` outputs to a file

1. Edit host file
    1. {ip} {domain name}
2. `gobuster vhost -u http://inlanefreight.htb:41714 -w subdomains-top1million-110000.txt --append-domain -t 200 -k`
    1. you need to put in domain name and not IP to skip DNS, as needed for labs

`Feroxbuster` - gobuster but in Rust; supports recursion, wildcard discovery, and various filters

`ffuf` - Web fuzzer than can be used in vhost discovery

# **Certificate Transparency Logs**

**Digital Certificates**

- in SSL/TLS, a file that verifies website’s identity
- Can be spoofed and used to impersonate

**Certificate Transparency (CT) logs**

- A global registry of certificates
- Public, append-only ledgers that records issued SSL/TLS certificates
- Certificate Authority (CA) would submit to multiple CT logs when issuing new certificates
    - Each log is operated by a different organization, ensuring redundancy and decentralization

CT enables:

1. Early Detection of Rogue Certificates
2. Accountability for Certificate Authorities
3. Strengthening the Web PKI (Public Key Infrastructure)

**How Certificate Transparency Logs Work**

1. Certificate Issuance
    1. When website owner requests a TL cert from a CA, CA verifies website owner’s identity and ownership
    2. CA issues a pre-certificate, a preliminary certificate version
2. Log Submission
    1. CA submits pre-certificate to multiple CT logs
3. Signed Certificate Timestamp (SCT)
    1. Each CT log generates a SCT
    2. Cryptographic timestamp proof of log submission
    3. SCT is included in final certificate to be issued
4. Browser Verification
    1. Browsers would verify a website’s cert’s SCT when visiting
    2. Verified against public CT logs logs
5. Monitoring and Auditing
    1. CT logs are continuously monitored by various entities, including security researchers, website owners, and browser vendors

**The Merkle Tree Structure**

- CT structured in this to organizes the certificates in a tree-like fashion, where each leaf node represents a certificate, and each non-leaf node represents a hash of its child nodes

Root Hash: Merkle root is a single hash representing entire CT log’s state

Hash 1 & Hash 2: Intermediate nodes, each a hash of two child nodes (either certificates or other hashes)

Cert 1 - Cert 4: Leaf nodes representing individual SSL/TLS certificates for different subdomains of inlanefreight.com

![image.png](Information%20Gathering%20-%20Web%20Edition%2026e6c31c8f4a80fbb003f15b67c4d14b/image%201.png)

By providing the Merkle path (a series of hashes) for a particular certificate

- Anyone can verify a cert’s existence in a CT log without downloading entire log
- The Root Hash will be different if even one bit is off from leaf node going up

## **Web Recon with CT Logs**

- CT logs reveal historical information on subdomains
    - Including hard to guess or brute force domains
- Can expose old/expired cert subdomains
- Reliable and efficient reconnaissance method over brute forcing

Searching CT  (online sites)

`crt.sh` - Free, easy to use, no registration required but limited filtering/analysis options

`search.censys.io` - Extensive data and API access but requires registration or subscriptions

crt.sh lookup with cURL

curl pipped with jq and sort

```bash
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[]
| select(.name_value | contains("dev")) | .name_value' | sort -u
```

- `curl -s "https://crt.sh/?q=facebook.com&output=json"`: This command fetches the JSON output from crt.sh for certificates matching the domain `facebook.com`.
- `jq -r '.[] | select(.name_value | contains("dev")) | .name_value'`: This part filters the JSON results, selecting only entries where the `name_value` field (which contains the domain or subdomain) includes the string "`dev`". The `r` flag tells `jq` to output raw strings.
- `sort -u`: This sorts the results alphabetically and removes duplicates.

# Fingerprinting

*Extracting technical details about the technologies powering a website or web application*

**Fingerprinting Techniques**

- Banner Grabbing
    
    ```bash
    happytilt@htb[/htb]$ curl -I https://www.inlanefreight.com
    
    HTTP/1.1 200 OK
    Date: Fri, 31 May 2024 12:12:26 GMT
    Server: Apache/2.4.41 (Ubuntu)
    Link: <https://www.inlanefreight.com/index.php/wp-json/>; rel="https://api.w.org/"
    Link: <https://www.inlanefreight.com/index.php/wp-json/wp/v2/pages/7>; rel="alternate"; type="application/json"
    Link: <https://www.inlanefreight.com/>; rel=shortlink
    Content-Type: text/html; charset=UTF-8
    ```
    
- HTTP Header Analysis
- Response Probing
- Page Content Analysis

**Fingerprinting Tools**

`Wappalyzer` - Browser extension

`BuiltWith` - Online website

`WhatWeb` - CLI tool

`Nmap` - It’s Nmap

`Netcraft` - Online website/service

`wafw00f` - CLI tool specific for fingerprinting WAFs

Installing `wafw00f`

`pip3 install git+https://github.com/EnableSecurity/wafw00f`

### **Nikto**

- open-source web server scanner
- used to fingerprint as well

Installing Nikto:

```bash
git clone https://github.com/sullo/nikto
cd nikto/program
chmod +x ./nikto.pl
```

Fingerprinting with Nikto

```bash
nikto -h site.com -Tuning b
```

- `-h` specifies host
- -`Tuning b` - only Software Identification modules

# Crawling (Spidering)

*The automated process of systematically browsing the World Wide Web*

<aside>
🧠

*It's essential to approach data analysis holistically, considering the relationships between different data points and their potential implications for your reconnaissance goals.*

</aside>

Starts at a seed URL (initial page) then crawls through each page, parsing content for links to craw down further.

What crawlers extract:

- Links
- Comments
- Metadata
- Sensitive Files

Common Crawling Strategies

- Breadth-First Crawling
    - Goes wide then deeper

![image.png](Information%20Gathering%20-%20Web%20Edition%2026e6c31c8f4a80fbb003f15b67c4d14b/image%202.png)

- Depth-First Crawling
    - Goes deep then outwards

![image.png](Information%20Gathering%20-%20Web%20Edition%2026e6c31c8f4a80fbb003f15b67c4d14b/image%203.png)

### Popular Web Crawlers

- Burp Suite Spider
- OWASP ZAP
- Scrapy (Python Framework)
- Apache Nutch (Open-Source Java Crawler)

### Scrapy & ReconSpider

Installing:

```bash
pip3 install scrapy
```

[https://github.com/bhavsec/reconspider](https://github.com/bhavsec/reconspider)

ReconSpider 

- Open-source reconnaissance tool written in Python
- Uses Scrapy for web scraping functionality

`python3 ReconSpider.py http://inlanefreight.com`

- Returns json data and outputs to `result.json` in same directory as script

## **robots.txt**

- Text file on websites directing crawlers where NOT to crawl to
- Placed in the root directory of a website
- Not strictly enforced and most legit web crawlers will respect rules

What robots.txt looks like

```
#Comments
User-agent: *
Disallow: /private/
```

- `Disallow` is a directive
- Common directives
    
    
    | **Directive** | **Description** | **Example** |
    | --- | --- | --- |
    | `Disallow` | Specifies paths or patterns that the bot should not crawl. | `Disallow: /admin/` (disallow access to the admin directory) |
    | `Allow` | Explicitly permits the bot to crawl specific paths or patterns, even if they fall under a broader `Disallow` rule. | `Allow: /public/` (allow access to the public directory) |
    | `Crawl-delay` | Sets a delay (in seconds) between successive requests from the bot to avoid overloading the server. | `Crawl-delay: 10` (10-second delay between requests) |
    | `Sitemap` | Provides the URL to an XML sitemap for more efficient crawling. | `Sitemap: https://www.example.com/sitemap.xml` |

In Web Recon, robots.txt can reveal:

- Hidden directories
- Website Structure
- Honeypot Directories

## **Well-Known URIs (RFC 8615)**

- Directory in website root; `/.well-known/change-password`
- Centralizes a website's critical metadata, including configuration files and information related to its services, protocols, and security mechanisms
    - For instance, to access a website's security policy, a client would request `https://example.com/.well-known/security.txt`

Notable `.well-known` **URIs

| **URI Suffix** | **Description** | **Status** | **Reference** |
| --- | --- | --- | --- |
| `security.txt` | Contains contact information for security researchers to report vulnerabilities. | Permanent | RFC 9116 |
| `/.well-known/change-password` | Provides a standard URL for directing users to a password change page. | Provisional | https://w3c.github.io/webappsec-change-password-url/#the-change-password-well-known-uri |
| `openid-configuration` | Defines configuration details for OpenID Connect, an identity layer on top of the OAuth 2.0 protocol. | Permanent | http://openid.net/specs/openid-connect-discovery-1_0.html |
| `assetlinks.json` | Used for verifying ownership of digital assets (e.g., apps) associated with a domain. | Permanent | https://github.com/google/digitalassetlinks/blob/master/well-known/specification.md |
| `mta-sts.txt` | Specifies the policy for SMTP MTA Strict Transport Security (MTA-STS) to enhance email security. | Permanent | RFC 8461 |

`openid-configuration`

- Part of the OpenID Connect Discovery protocol
    - identity layer built on top of the OAuth 2.0 protocol
- Client goes to `https://example.com/.well-known/openid-configuration` if they wants to use OpenID for authentication
    - Returns a JSON document containing metadata about provider’s endpoints

# **Search Engine Discovery**

- Search engines can be used for web recon and OSINT gathering
- Uncovers information about websites, organizations, and individuals
- Using search operators and techniques to find employee details, sensitive documents, hidden login pages, and exposed credentials

## **Search Operators**

| **Operator** | **Operator Description** | **Example** | **Example Description** |
| --- | --- | --- | --- |
| `site:` | Limits results to a specific website or domain. | `site:example.com` | Find all publicly accessible pages on example.com. |
| `inurl:` | Finds pages with a specific term in the URL. | `inurl:login` | Search for login pages on any website. |
| `filetype:` | Searches for files of a particular type. | `filetype:pdf` | Find downloadable PDF documents. |
| `intitle:` | Finds pages with a specific term in the title. | `intitle:"confidential report"` | Look for documents titled "confidential report" or similar variations. |
| `intext:` or `inbody:` | Searches for a term within the body text of pages. | `intext:"password reset"` | Identify webpages containing the term “password reset”. |
| `cache:` | Displays the cached version of a webpage (if available). | `cache:example.com` | View the cached version of example.com to see its previous content. |
| `link:` | Finds pages that link to a specific webpage. | `link:example.com` | Identify websites linking to example.com. |
| `related:` | Finds websites related to a specific webpage. | `related:example.com` | Discover websites similar to example.com. |
| `info:` | Provides a summary of information about a webpage. | `info:example.com` | Get basic details about example.com, such as its title and description. |
| `define:` | Provides definitions of a word or phrase. | `define:phishing` | Get a definition of "phishing" from various sources. |
| `numrange:` | Searches for numbers within a specific range. | `site:example.com numrange:1000-2000` | Find pages on example.com containing numbers between 1000 and 2000. |
| `allintext:` | Finds pages containing all specified words in the body text. | `allintext:admin password reset` | Search for pages containing both "admin" and "password reset" in the body text. |
| `allinurl:` | Finds pages containing all specified words in the URL. | `allinurl:admin panel` | Look for pages with "admin" and "panel" in the URL. |
| `allintitle:` | Finds pages containing all specified words in the title. | `allintitle:confidential report 2023` | Search for pages with "confidential," "report," and "2023" in the title. |
| `AND` | Narrows results by requiring all terms to be present. | `site:example.com AND (inurl:admin OR inurl:login)` | Find admin or login pages specifically on example.com. |
| `OR` | Broadens results by including pages with any of the terms. | `"linux" OR "ubuntu" OR "debian"` | Search for webpages mentioning Linux, Ubuntu, or Debian. |
| `NOT` | Excludes results containing the specified term. | `site:bank.com NOT inurl:login` | Find pages on bank.com excluding login pages. |
| `*` (wildcard) | Represents any character or word. | `site:socialnetwork.com filetype:pdf user* manual` | Search for user manuals (user guide, user handbook) in PDF format on socialnetwork.com. |
| `..` (range search) | Finds results within a specified numerical range. | `site:ecommerce.com "price" 100..500` | Look for products priced between 100 and 500 on an e-commerce website. |
| `" "` (quotation marks) | Searches for exact phrases. | `"information security policy"` | Find documents mentioning the exact phrase "information security policy". |
| `-` (minus sign) | Excludes terms from the search results. | `site:news.com -inurl:sports` | Search for news articles on news.com excluding sports-related content. |

### **Google Dorking or Google Hacking**

[OffSec’s Exploit Database Archive](https://www.exploit-db.com/google-hacking-database)

- Finding Login Pages:
    - `site:example.com inurl:login`
    - `site:example.com (inurl:login OR inurl:admin)`
- Identifying Exposed Files:
    - `site:example.com filetype:pdf`
    - `site:example.com (filetype:xls OR filetype:docx)`
- Uncovering Configuration Files:
    - `site:example.com inurl:config.php`
    - `site:example.com (ext:conf OR ext:cnf)` (searches for extensions commonly used for configuration files)
- Locating Database Backups:
    - `site:example.com inurl:backup`
    - `site:example.com filetype:sql`

# Internet Archive's Wayback Machine

[Wayback Machine](https://web.archive.org/)

- Uses crawlers to capture snapshots of websites at regular intervals
- Stores the entire content of the pages: HTML, CSS, JavaScript, images, and other resources

# **Automating Recon with Frameworks**

- [FinalRecon](https://github.com/thewhiteh4t/FinalRecon):
    - SSL certificate checking, Whois information gathering, header analysis, and crawling.
- [Recon-ng](https://github.com/lanmaster53/recon-ng)
    - DNS enumeration, subdomain discovery, port scanning, web crawling, exploit known vulnerabilities
- [theHarvester](https://github.com/laramies/theHarvester)
    - Specifically designed for gathering email addresses, subdomains, hosts, employee names, open ports, and banners from different public sources
    - Search engines, PGP key servers, and the SHODAN database
    - CLI tool
- [SpiderFoot](https://github.com/smicallef/spiderfoot)
    - Collect information about a target, including IP addresses, domain names, email addresses, and social media profiles
    - DNS lookups, web crawling, port scanning, and more
- [OSINT Framework](https://osintframework.com/)
- A collection of various tools and resources for open-source intelligence gathering
- Including social media, search engines, public records, and more

## FinalRecon

Installing:

```bash
git clone https://github.com/thewhiteh4t/FinalRecon.git
cd FinalRecon
pip3 install -r requirements.txt
chmod +x ./finalrecon.py
./finalrecon.py --help
```