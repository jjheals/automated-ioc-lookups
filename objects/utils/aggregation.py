from ..ioc_types import IPAddress, Domain, SSLCert
from ..apis import VirusTotalAPI, IPInfoAPI
from .general import list_to_dict
import datetime as dt 
import pandas as pd 


def construct_ips_from_list(los:list[str], return_format:dict | IPAddress = dict) -> list[dict | IPAddress]: 
    """Takes in a list of strings and constructs either IPAddress objects or 
       dictionaries, depending on return_format
       
        Args
            los (list[str]): a list of IPs as strings.
            return_format (dict | IPAddress, optional): specify the return format. Defaults to dict. 
        
        Returns 
            list[dict | IPAddress]: a list of dictionaries or IPAddress objects.
            
        Raises 
            ValueError: if the return format is invalid (i.e. not dict | IPAddress)
    """  
    return_list:list[return_format] = []
    
    match(return_format.__name__): 
        
        # Return format is dict
        case "dict": 
            for ip in los: 
                # Use check_ip_verison to check if not a valid IP address
                if check_ip_version(ip) < 0: continue
                
                # Add to return list as a dictionary
                return_list.append(
                    {
                        'type': 'IPAddress',
                        'value': ip
                    }
                )
               
        # Return format is IPAddress 
        case "IPAddress": 
            for ip in los: 
                # Use check_ip_verison to check if not a valid IP address
                if check_ip_version(ip) < 0: continue
                
                # Add to return list as an IPAddress obj
                return_list.append(IPAddress(ip))

        # Return format not recognized
        case _: 
            print(f'\033[91mERROR: \033[90mreturn format {return_format} is not recognized.')
            raise ValueError('construct_ips_from_list(): return format not recognized.')

    return return_list
                 
    
def check_ip_version(ip:str) -> int: 
    """Takes in an IPAddress and checks what type it is (v4 or v6).
    
        Args
            ip (str): the IP address as a string.
            
        Returns
            int: integer for the IP version (4 | 6) or -1 if the given ip is not a valid IPv4 or v6 address.
    """
    if(IPAddress.match_ipv4_regex(ip)): return 4
    elif(IPAddress.match_ipv6_regex(ip)): return 6
    else: return -1
    

def combine_vt_ipinfo_results(vt_results:dict[str, dict], ipinfo_results:dict[str, dict]) -> tuple[list[dict], list[dict], list[dict], list[dict]]: 
    """Takes in a dictionary with the results of lookups from VT, and a dict with the results of lookups from IPInfo, 
    and combines the results into a single list of dictionaries where each dict is the combined results for a 
    single IP address. 
       
    Returns a tuple containing: 
        - the first value as a list of the resulting IP details (as dicts)
        - the second value as a list of the resulting domain details (as dicts)
        - the third value as a list of the DNS records for the domains (as dicts)
        - the fourth value as a list of the SSL certs (as dicts).
    """ 

    # Construct a list of all the unique IP addresses and domains in either dict of results
    ips:list[str] = []                  # Unique IPs in either set of results
    domains:list[str] = []              # Unique domains in either set of results
    ssl_cert_results:list[dict] = []    # SSL certs in either set of results
    
    # Iterate over the VT results and add each value to the appropriate list 
    for ioc in vt_results:
        if IPAddress.match_ipv4_regex(ioc) or IPAddress.match_ipv6_regex(ioc): ips.append(ioc)
        else: domains.append(ioc)
    
    # Iterate over the IPInfo results and add each value to the appropriate list 
    for ioc in ipinfo_results: 
        if IPAddress.match_ipv4_regex(ioc) or IPAddress.match_ipv6_regex(ioc): ips.append(ioc)
        else: domains.append(ioc)
        
    # Remove duplicates from both lists
    ips = list(set(ips))
    domains = list(set(domains))
    
    # -- Iterate over the ips and construct the combined results -- #
    ip_results:list[dict] = []
    for ip in ips: 
        
        # Init an entry for this IP
        entry:dict = {} 
        entry['value'] = ip 
        
        # -- VT results -- #
        these_vt_results:dict = vt_results.get(ip, {})
        
        # Get the SSLCert thumbprint, which is nested, and append the SSL cert to ssl_cert_results if applicable
        last_https_cert:dict = these_vt_results.get('last_https_certificate', None)
        if last_https_cert: 
            ssl_thumbprint:str = last_https_cert.get('thumbprint', '')
            ssl_cert_results.append(last_https_cert)
            
        else: ssl_thumbprint:str = None
        
        entry['network'] = these_vt_results.get('network', '')
        entry['ssl_thumbprint'] = ssl_thumbprint
        
        # -- IPInfo results -- #
        these_ipinfo_results:dict = ipinfo_results.get(ip, {})
        
        # Extract the attributes from the IPInfo result
        entry['country'] = these_ipinfo_results.get('country', '') 
        entry['city'] = these_ipinfo_results.get('city', '')
        entry['state'] = these_ipinfo_results.get('state', '')
        entry['resolved_domain'] = these_ipinfo_results.get('resolved_domain', '') 
        entry['asn'] = these_ipinfo_results.get('asn', '')
        entry['as_org'] = these_ipinfo_results.get('as_org', '') 
        entry['latitude'] = these_ipinfo_results.get('latitude', '')
        entry['longitude'] = these_ipinfo_results.get('longitude', '')
        
        # Add the entry to combined_results
        ip_results.append(entry)
        
    # -- Iterate over the domains and construct the combined results -- #
    domain_results:list[dict] = []
    dns_results:list[dict] = []
    for domain in domains: 
        
        # Init an entry for this Domain
        entry:dict = {} 
        entry['value'] = domain 
        
        # -- VT results -- #
        these_vt_results:dict = vt_results.get(domain, {})
        
        # Get the SSLCert thumbprint, which is nested, and append the SSL cert to ssl_cert_results if applicable
        last_https_cert:dict = these_vt_results.get('last_https_certificate', None)
        if last_https_cert: 
            ssl_thumbprint:str = last_https_cert.get('thumbprint', '')
            ssl_cert_results.append(last_https_cert)
        else: ssl_thumbprint:str = None
        
        # Construct an entry for this domain 
        entry['tld'] = these_vt_results.get('tld', '')
        entry['ssl_thumbprint'] = ssl_thumbprint
        entry['vt_harmless_votes'] = these_vt_results.get('total_votes', {}).get('harmless', -1)
        entry['vt_malicious_votes'] = these_vt_results.get('total_votes', {}).get('malicious', -1)
        entry['registrar'] = these_vt_results.get('registrar', '')
        entry['jarm'] = these_vt_results.get('jarm', '')
        entry['creation_date'] = these_vt_results.get('creation_date', '')
        
        # Add the entry to combined_results
        domain_results.append(entry)

        # Check if there were DNS records 
        these_dns_records:list[dict] = these_vt_results.get('last_dns_records', {})
        if these_dns_records: 
            # Create a series of entries to the dns_records for these DNS records 
            for dns_record in these_dns_records: 
                dns_results.append({
                    'domain': domain, 
                    'type': dns_record.get('type', ''),
                    'value': dns_record.get('value', '')
                })
        
    # Return the final lists of dicts
    return ip_results, domain_results, dns_results, ssl_cert_results


def lookup_iocs(vt_api:VirusTotalAPI, ipinfo_api:IPInfoAPI, iocs_as_df:pd.DataFrame, ignore_supradomains:list[str]=[], 
                ignore_cidrs:list[str]=[], date_detected:str=dt.datetime.now().strftime('%Y-%m-%d'), 
                date_targeted:str=dt.datetime.now().strftime('%Y-%m-%d')) -> tuple[list[dict], list[dict], list[dict]]: 
    """Takes in the API objects, and the iocs as a single dataframe with three columns: "Value", "Type", "Count", 
    and conducts lookups on all of the IOCs; joins the IP results and SSL cert results into a single list each 
    and returns."""
    
    # Prep the IOCs for the VT API 
    prepped_iocs:list[dict[str,str]] = []
    for r in iocs_as_df.iterrows(): 
        r = r[1]
        prepped_iocs.append({
            'value': r['Value'],
            'type': r['Type']
        })
            
    # Conduct lookups with the APIs 
    vt_result = list_to_dict(vt_api.lookup_iocs(
        prepped_iocs, 
        ignore_supradomains=ignore_supradomains, 
        ignore_cidrs=ignore_cidrs, 
        print_debug=True
    ))
    
    ipinfo_result = list_to_dict(ipinfo_api.lookup_iocs(
        prepped_iocs
    ))
    
    # Combine the results 
    ip_results, domain_results, ssl_cert_results = combine_vt_ipinfo_results(
        vt_results=vt_result, 
        ipinfo_results=ipinfo_result, 
        date_detected=date_detected, 
        date_targeted=date_targeted
    )
    
    return ip_results, domain_results, ssl_cert_results