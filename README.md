# automated-ioc-lookups

This repo contains a number of API integrations that can be used to interact with some open-source tools and retrieve WHOIS information, DNS records, SSL certificates, and other information for IP addresses and domains. The goal of this project is to improve the enrichment process for analysts and to provide a single program that can integrate with multiple APIs to retrieve data. 

In the future, I hope to include more analysis tools to identify trends in data - these questions are based on the assumption that anyone using these tools are using them with a purpose and to aid investigations (and, inherently, that the IPs and domains being looked up are somehow related and appear in an incident(s) or something like that), but with that in mind: 

- Are the same SSL certs seen commonly?
- Which CIDRs are seen most often?
- What is the average "risk" associated with a domain or IP? (i.e. "total votes" from VT)
- Can we link any IPs or domains via the SSL thumbprint? 

