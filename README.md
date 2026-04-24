# Arachnet

> Cybersecurity Reconnaissance & Vulnerability Scanning Toolkit  
> **Project Wing Cyber — MLSA KIIT**

![alt_text](mlsa.png)

---

## What's New?

- ✅ DNS Enumeration via DNSDumpster with structured JSON output
- ✅ Automated subdomain, IP, and NS record segregation
- ✅ XSS Scanner with WAF detection and payload ranking
- ✅ IDOR vulnerability scanner with crawling and multi-method testing
- ✅ Vulnerability scanning with Nuclei integration
- ✅ SQL Injection testing via SQLMap integration
- ✅ Multi-threaded scanning support (up to 10 threads)
- ✅ Scope management (add/remove targets from scan scope)

---

## Features

| Module | Description |
|---|---|
| **DNS Enumeration** | Enumerates subdomains, IPs, NS/MX/TXT records via DNSDumpster |
| **Vulnerability Scan** | Integrates with [Nuclei](https://github.com/projectdiscovery/nuclei) for comprehensive vuln scanning |
| **SQL Injection** | Tests for SQLi via [SQLMap](https://github.com/sqlmapproject/sqlmap) |
| **XSS Scanner** | Custom reflected XSS scanner with dangerous character fuzzing, WAF-aware payload selection (supports Cloudflare, CloudFront, Imperva, and more), Katana crawling |
| **IDOR Scanner** | Tests for Insecure Direct Object References using endpoint fuzzing, parameter brute-forcing, and multi-method HTTP requests |
| **Scope Management** | Add or remove targets from enumerated results interactively |

### External Tool Dependencies

These tools should be installed separately and available in your `$PATH`:

- [Nuclei](https://github.com/projectdiscovery/nuclei) — for vulnerability scanning
- [SQLMap](https://github.com/sqlmapproject/sqlmap) — for SQL injection testing
- [Katana](https://github.com/projectdiscovery/katana) — for URL crawling (optional, used with `--crawl`)
- [Nmap](https://nmap.org/) — for IP-based scanning

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/MLSAKIIT/Arachnet.git
cd Arachnet

# 2. Install Python dependencies
pip3 install -r requirements.txt

# 3. (Optional) Install external tools
# See https://github.com/projectdiscovery/nuclei#installation
# See https://github.com/sqlmapproject/sqlmap#installation

# 4. Make the script executable
chmod +x arachnet.sh
```

---

## Usage

### Interactive Mode (Main Menu)

```bash
./arachnet.sh
```

This launches the interactive menu where you can:
1. **Enumerate** — Run DNS enumeration on a domain
2. **Vuln Scan** — Scan with Nuclei
3. **Test for SQLi** — Run SQL injection tests
4. **Test for XSS** — Run XSS scanner
5. **Test for IDOR** — Run IDOR scanner
6. **Scope options** — Manage scan targets
7. **Exit**

### Standalone XSS Scanner

```bash
# Scan a single URL
python3 xss/main.py -u "http://example.com/page?id=1" -o results.txt

# Scan URLs from a file
python3 xss/main.py -f urls.txt -o results.txt -t 5

# Scan with WAF detection enabled
python3 xss/main.py -u "http://example.com/page?id=1" --waf

# Crawl and scan
python3 xss/main.py -u "http://example.com" --crawl -o results.txt

# Pipe URLs from another tool
cat urls.txt | python3 xss/main.py --pipe -o results.txt
```

### Standalone IDOR Scanner

```bash
# Scan a single URL
python3 idor/idor.py -u "http://example.com" -o results.txt

# Scan URLs from a file
python3 idor/idor.py -f urls.txt -o results.txt

# Interactive mode
python3 idor/idor.py
```

### DNS Enumeration Only

```bash
python3 DnsDumpster/main.py -u example.com
```

---

## Demonstration

```
$ ./arachnet.sh

    _                      _                 _
   / \    _ __  __ _   ___| |__  _ __   ___ | |_
  / _ \  | '__/ _` | / __| '_ \| '_ \ / _ \  __|
 / ___ \ | |  | (_| |  (__| | | | | | |  __/  |_
/_/   \_ \_|   \__,_| \___|_| |_|_| |_|\___| \__|

        Arachnet - Cybersecurity Toolkit
          Project Wing Cyber | MLSA KIIT

Enter the domain: example.com

1. Enumerate
2. Vuln Scan
3. Test for SQLi
4. Test for XSS
5. Test for IDOR
6. Scope options
7. Exit

Please enter an option:
```

---

## Project Structure

```
Arachnet/
├── arachnet.sh              # Main CLI entry point (bash menu)
├── seg.py                   # DNS output segregation script
├── requirements.txt         # Python dependencies
├── DnsDumpster/
│   ├── main.py              # DNS enumeration entry point
│   └── DnsDumpsterClient.py # DNSDumpster API client
├── xss/
│   ├── main.py              # XSS scanner
│   ├── Header.py            # HTTP header parser
│   ├── Waf.py               # WAF detection module
│   ├── adder.py             # Payload management
│   ├── payloads.json        # XSS payload database
│   └── waf_list.txt         # Known WAF signatures
├── idor/
│   └── idor.py              # IDOR vulnerability scanner
├── dump/                    # (generated) Raw enumeration output
└── enum/                    # (generated) Segregated results
```

---

## License

This project is for educational and authorized security testing purposes only. Always obtain proper authorization before scanning any target.