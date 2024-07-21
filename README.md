# automated-ioc-lookups

This repo contains a number of API integrations that can be used to interact with some open-source tools and retrieve WHOIS information, DNS records, SSL certificates, and other information for IP addresses and domains. The goal of this project is to improve the enrichment process for analysts and to provide a single program that can integrate with multiple APIs to retrieve data. 

In the future, I hope to include more analysis tools to identify trends in data - these questions are based on the assumption that anyone using these tools are using them with a purpose and to aid investigations (and, inherently, that the IPs and domains being looked up are somehow related and appear in an incident(s) or something like that), but with that in mind: 

- Are the same SSL certs seen commonly?
- Which CIDRs are seen most often?
- What is the average "risk" associated with a domain or IP? (i.e. "total votes" from VT)
- Can we link any IPs or domains via the SSL thumbprint? 

# Setup & Usage

Using this program is straightforward, but there is some setup involved. 

**(Optional but recommended) Create a virtual environment**
```bash
$: python3 -m venv venv 

# Linux/Unix
$: source venv/bin/activate

# Windows 
$: .\venv\Scripts\activate
```

**Install the required python modules**
```bash
$: pip install -r requirements.txt
```

**Create config JSON file**

In the root directory, create a new folder called "config", then create a file called "config.json".
```bash
# Linux/Unix
$: mkdir config && cd config
$: touch config.json
```

In config.json, add the following (and be sure to add your actual API tokens as indicated)
```json
{
    "tokens": {
        "virustotal": "<YOUR-VT-API-TOKEN>",
        "ipinfo": "<YOUR-IPINFO-API-TOKEN>"
    }
}
```

**Using the program**

You can follow the instructions in [notebook.ipynb](./notebook.ipynb) to see how to integrate the necessary functions and classes.

The notebook is flexible and explains the general process for how the APIs are called, the results combined, and the outputs constructed. This should be sufficient for basic use cases, but if you need more information on any of the functions or want to explore how the integrations actually work, you can refer to the [objects/](./objects/) folder. This folder (and its subfolders) contains all the source code, including class and function definitions. 

If you want or need to export the program to be used in another implementation, you can simply copy and paste the entire [objects/](./objects/) folder into your project and call the functions as needed. Each class, method, and [util](./objects/utils/) has a description and typeset arguments.