# Day 03 — Simple DNS Lookup CLI

## What I Built

A DNS lookup tool that queries all major DNS record types for any domain and supports reverse DNS lookups (IP → hostname). Built with Python and the `dnspython` library.

---

## How It Works

```
python dns_lookup.py
```

Pick domain lookup or reverse lookup, enter your target, and get the results.

Example output:
```
DNS Lookup for google.com
  A Record: 142.251.142.142
  AAAA Record: 2a00:1450:4003:812::200e
  MX Record: 10 smtp.google.com.
  NS Record: ns1.google.com.
  NS Record: ns2.google.com.
  TXT Record: "v=spf1 include:_spf.google.com ~all"
  CNAME Record: No records found
```

---

## What is DNS?

DNS (Domain Name System) is the internet's phone book. Computers communicate using IP addresses, but humans use domain names. DNS translates one to the other. Every time you type a URL, a DNS lookup happens behind the scenes.

---

## DNS Record Types

| Record | Purpose | Cybersecurity Use |
|--------|---------|-------------------|
| **A** | Maps domain → IPv4 address | Find a target's server IPs |
| **AAAA** | Maps domain → IPv6 address | Find IPv6 infrastructure |
| **MX** | Mail servers for the domain | Phishing analysis, email spoofing recon |
| **NS** | Nameservers managing the domain | Infrastructure mapping, DNS hijack detection |
| **TXT** | Text records (SPF, DMARC, verification) | Check email security policies, find leaked info |
| **CNAME** | Alias pointing to another domain | Subdomain takeover detection |
| **PTR** | Reverse: IP → hostname | Investigate suspicious IPs |

---

## Features

### Domain Lookup
Queries A, AAAA, MX, NS, TXT, and CNAME records for any domain.

### Reverse DNS Lookup
Takes an IP address and finds the hostname associated with it using PTR records. Useful for investigating suspicious IPs found in logs.

### Custom DNS Server
Uses Google's DNS (`8.8.8.8`) instead of the local router's DNS for faster, more reliable results.

### Error Handling
Gracefully handles missing records, non-existent domains, and timeouts without crashing.

---

## Why DNS Records Are Public

DNS is public by design. Your browser needs to look up any domain to connect to it. Mail servers need to find MX records to deliver email. This makes DNS a goldmine for reconnaissance — you can map an organization's infrastructure without sending a single suspicious request.

---

## What I Learned

- How DNS resolution works (name → IP translation)
- The purpose of each DNS record type
- How to use the `dnspython` library to query records programmatically
- Reverse DNS and PTR records
- Error handling for network operations
- Why DNS is useful for security reconnaissance
- How to use a custom resolver (Google DNS vs local)

---

## Project Structure

```
dns_lookup/
├── dns_lookup.py    # The lookup tool
└── README.md        # This file
```

---

## Requirements

```
pip install dnspython
```

---

**#30DaysOfCyber**
