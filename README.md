# ResolveR - README

This project is a custom DNS server created for learning purposes. It implements the recursive DNS resolution process, handling DNS requests, checking the cache, and querying authoritative DNS servers to provide the correct IP addresses for domain names.

## Demo


## Features
- Implements DNS protocol with UDP using asyncio for handling concurrent requests.
- Supports recursive DNS resolution by querying root servers and authoritative name servers.
- Implements caching for DNS records to improve efficiency and reduce the number of external queries.
- Logs requests and responses to a rotating file for monitoring and debugging purposes.

## How It Works (Image Explanation)



The image above illustrates the DNS resolution process:
1. **Stub Resolver:** Your laptop/PC sends a DNS query for `a.example.com` to a recursive DNS server.
2. **Recursive DNS Server:** The recursive server first checks its cache. If the record is cached, it returns the IP. Otherwise, it forwards the query up the DNS hierarchy.
3. **Root Servers (TLD):** The recursive server queries the root server (e.g., `.com`) to identify the authoritative server for the second-level domain (SLD).
4. **Second-Level Domain Servers (SLD):** The root server points to the server responsible for `example.com`.
5. **Authoritative Server:** The recursive server queries the authoritative server for `example.com` to get the IP address for `a.example.com`.
6. **Response:** Once the authoritative server provides the IP, the recursive server caches the result and returns it to your laptop/PC.

## Key Files
- **`main.py`:** The entry point for the DNS server, uses asyncio for asynchronous DNS request handling.
- **`dns_header.py`:** Contains logic for parsing and creating DNS headers.
- **`dns_question.py`:** Handles the parsing and creation of DNS questions in requests.
- **`dns_resolver.py`:** Implements recursive DNS resolution and caching.
- **`cache.py`:** Manages caching of DNS responses to improve performance.
- **`logging_config.py`:** Configures logging to record DNS queries and server events.

Here's an improved version of the **Installation** and other sections for your README:

## Installation

1. **Clone the Repository**  
   First, clone the project repository to your local machine using the following command:
   ```bash
   git clone https://github.com/your-repository-url.git
   cd your-repository-folder
   ```

2. **Set Up the Environment**  
   Ensure that you have Python installed (version 3.6 or higher). You can check your Python version by running:
   ```bash
   python --version
   ```
3. **Run the DNS Server**  
   Start the DNS server by executing:
   ```bash
   python app/main.py
   ```

4. **Test the DNS Server**  
   You can use the `dig` command to test the DNS server locally. For example, to query `example.com` through your DNS server, run:
   ```bash
   dig @127.0.0.1 -p 2053 example.com
   ```

## Future Enhancements

- **Support for Additional DNS Record Types**  
  Extend the DNS server to handle more record types.
  
- **Optimized Caching Mechanisms**  
  Improve the caching strategy to support longer retention times and more efficient data retrieval.

- **Support for Advanced DNS Features**  
  Add support for more complex DNS functionality, such as DNSSEC (DNS Security Extensions), dynamic updates, and load balancing features.

## References

- **Domain Names - Implementation and Specification**  
  [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035)  
  This RFC provides the fundamental specification for the DNS protocol, detailing message formats, query processes, and server functions.

- **Blacklist Sources**  
  [Steven Black's Hosts Repository](https://github.com/StevenBlack/hosts)  
  This repository provides commonly used lists of domains associated with ads, malware, and phishing attempts, which can be used to block undesirable content.
---