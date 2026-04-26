# Async Recon Tool

A lightweight asynchronous reconnaissance tool for passive and active DNS enumeration, certificate transparency scraping, SSL probing, and basic banner grabbing. Built using Python with asyncio, httpx, socket, and ssl for concurrent network-based reconnaissance.

## Features

### Passive Recon (-p)
- Certificate Transparency scraping via crt.sh
- Subdomain extraction from certificates
- DNS resolution mapping (domain to IP)

### Active Recon (-a)
- SSL certificate probing (SAN and subject extraction)
- DNS resolution mapping
- Basic HTTP banner grabbing on ports 80 and 443

### Performance Design
- Fully asynchronous execution using asyncio
- Threaded handling of blocking socket operations
- Concurrent requests for faster recon workflows

## How It Works

Passive mode queries crt.sh for certificate transparency logs associated with the target domain. It extracts subdomains from Subject Alternative Names and certificate subject fields.

Active mode establishes SSL connections directly to the target domain to extract certificate metadata such as SAN entries and subject information.

All discovered domains are resolved into IP addresses using system DNS resolution. After resolution, banner grabbing is performed by connecting to common HTTP ports (80 and 443) to capture basic server response headers.

## Installation

Python 3.9 or higher is required.

Install dependencies:

pip install httpx

## Usage

Passive recon mode (certificate transparency enumeration only):

python recon.py --target example.com -p

Active recon mode (SSL probing + banner grabbing):

python recon.py --target example.com -a

## Output Example

[+] Collected Domains (PASSIVE):
['sub.example.com', 'api.example.com']

[+] IP map:
{'93.184.216.34': {'example.com', 'api.example.com'}}

========== FINAL RESULTS ==========

IP: 93.184.216.34
Domains: ['example.com', 'api.example.com']
Banners:
  Port 80: HTTP/1.1 200 OK ...
  Port 443: HTTP/1.1 200 OK ...
-----------------------------------

## Limitations

crt.sh may rate limit or block repeated requests. Banner grabbing is minimal and limited to HTTP-based responses. DNS resolution depends on the local system resolver and may vary. No full port scanning, deep service fingerprinting, or advanced protocol analysis is implemented.

## Future Improvements

Add multiple certificate transparency sources for redundancy. Implement async port scanning for broader network coverage. Improve service fingerprinting accuracy. Add JSON and CSV export functionality for results. Introduce retry logic and rate-limit handling. Allow configurable port scanning ranges.

## Disclaimer

This tool is intended strictly for educational purposes and authorized security testing only. Do not use it against systems you do not own or do not have explicit permission to test.

## Author

A reconnaissance utility built for learning asynchronous programming, OSINT techniques, SSL analysis, and active network probing workflows.
