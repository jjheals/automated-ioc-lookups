import requests
import datetime as dt 

from ..ioc_types.SSLCert import SSLCert
import json 
from ..ioc_types import AbstractIOC
from ..ioc_types import IPAddress
from ..ioc_types import Domain
from .AbstractAPI import AbstractAPI

class VirusTotalAPI(AbstractAPI): 
    
    # -- Static Attributes -- #
    
    # Keys for returning an IP report from VT as a dictionary
    # NOTE: does not contain 'last_https_certificate' because that is handled as its own object (SSLCert)
    IP_REPORT_KEYS:list[str] = [
        'network',
        'last_analysis_stats',
        'reputation',
        'total_votes',
    ]
    
    # Keys for returning an IP report from VT as a dictionary
    # NOTE: does not contain 'last_https_certificate' because that is handled as its own object (SSLCert)
    DOMAIN_REPORT_KEYS:list[str] = [
        'last_dns_records',
        'tld',
        'popularity_ranks',
        'reputation',
        'total_votes',
        'jarm',
        'registrar',
        'creation_date'
    ]
    
    # Base URL for the VT API
    VT_API_URL:str = 'https://www.virustotal.com/api/v3/'
    
    
    # -- Dynamic attributes -- #
    token:str   # VT token for the API
    
    
    # Constructor 
    def __init__(self, token:str): 
        super().__init__(token)
    
    
    def lookup_iocs(self, iocs:list[dict | AbstractIOC], ignore_supradomains:list[str]=[], ignore_cidrs:list[str]=[], 
                    include_analysis_results:bool=False, print_debug:bool=False) -> list[dict]: 
        """Takes in a list of IOCs and hits the VT API for each of them using the token in self.token.
        
            Args: 
                iocs (list[dict]): a list of IOCs to search as dictionaries in the format: 
                    { 
                        "type": [ "IPAddress" | "Domain" ], 
                        "value: "some.domain-or-ip.com" 
                    } 
                
                    NOTE: iocType can be anything, but the function only tries to hit the API with "IPAddress" or "Domain" types.
                    
                ignore_supradomains (list[str], optional): give a list of supradomains to ignore. Defaults to empty list.
                ignore_cidrs (list[str], optional): give a list of CIDR ranges to ignore. Defaults to empty list.
                include_analysis_results (bool, optional): specify whether to include the "last analysis results" in the results. Defaults to False.
                print_debug (bool, optional): specify to print debug traces and info. Defaults to False.
                
            Returns: 
                list[dict]: a list of dictionaries containing the results for each IOC.
        """ 
        
        headers:dict = {'x-apikey': self.token}     # Define the headers for the request
        return_dicts:list[dict] = []                # List to return containing the results as dictionaries
        
        # Iterate over the IOCs and make API calls for each
        for ioc in iocs:
            
            # Convert to dict if not dict 
            if ioc.__class__.__name__ != 'dict': ioc = ioc.to_dict()
            
            # If this ioc doesn't have a value, then skip it
            if not ioc['value']: continue
            
            this_ioc_type:str = ioc['type']     # CGet the IOC type is the correct type for VT
            this_base_url:str = self.VT_API_URL # Construct the API URL based on the type of IOC        
            match_keys:dict = {}                # Init dict that will be used to match the keys of the API response
            
            # Match the IOC type and act accordingly
            match(this_ioc_type):
                case 'IPAddress': 
                
                    # TODO: check if this IP is in a range in "ignore_cidrs"
                    # DO SOMETHING ...
                    # ...
                    
                    # Check that this is an IPv4 since VT only takes IPv4
                    if not IPAddress.match_ipv4_regex(ioc['value']): 
                        if print_debug: print(f'\033[33mNOTICE: \033[90mIgnoring "{ioc["value"]}" because it is not a valid IPv4 address (likely IPv6).')
                        continue 
                    
                    # Update vars appropriately
                    this_base_url += 'ip_addresses/'    # Set base URL to ip addresses endpt
                    match_keys = self.IP_REPORT_KEYS    # Set match_keys to IP address
                    
                case 'Domain': 
                
                    # Get the supradomain to check if it should be skipped
                    supra_domain:str = Domain.get_supradomain(ioc['value'])
                    if supra_domain in ignore_supradomains: 
                        if print_debug: 
                            print(f'\033[33mNOTICE: \033[90mIgnoring "{ioc["value"]}" due to supradomain "{supra_domain}".')
                        continue
                    
                    # Update vars appropriately
                    this_base_url += 'domains/'             # Set base URL to domains endpt
                    match_keys = self.DOMAIN_REPORT_KEYS    # Set match_keys to Domain 
                    
                case _: 
                    # IOC is not a valid type, so skip it
                    if print_debug: 
                        print(f'\033[33mNOTICE: \033[90mskipping "{ioc["value"]}" because the type "{this_ioc_type}" is not valid for VT.')
                    continue
            
            # Make API call
            try: 
                response = requests.get(this_base_url + ioc['value'], headers=headers) 
                data:dict = response.json()['data']['attributes']
            except KeyError: 
                # KeyError means no results found
                print(f'\33[33mNOTICE: \033[90mNo results found for "{ioc["value"]}" (VirusTotal)')
                continue
            except Exception as e: 
                # NOTE: better exception handling, rotating keys, continuing for the rest of the IOCs, etc
                # Check what kind of error (invalid API key, no results, etc)
                
                # DO SOMETHING ... 
                # ... 
                raise e
        
            # Create a dictionary for this IOC to save the data
            this_ioc_as_dict:dict = {
                'type': this_ioc_type,
                'value': ioc['value']
            }
            
            # If including analysis results, add that key to match_keys
            if include_analysis_results: match_keys.append('last_analysis_results')
            
            # Extract the data for this IOC depending on the type
            for k in match_keys: this_ioc_as_dict[k] = data.get(k, None)
                    
            # NOTE: Remaining keys are for both domains and IPs
            # Check for SSL cert 
            if 'last_https_certificate' in data:
                this_ioc_as_dict['last_https_certificate'] = SSLCert(data['last_https_certificate']).to_dict()
            else: 
                this_ioc_as_dict['last_https_certificate'] = None
        
            # The VT API tends to return "reputation" as 0 - use the analysis stats to calculate the reputation
            try: 
                n_m:int = int(this_ioc_as_dict['last_analysis_stats']['malicious'])    # n_m == num malicious verdicts
                n_s:int = int(this_ioc_as_dict['last_analysis_stats']['suspicious'])   # n_s == num suspicious verdicts
        
                # Apply weights to the malicious and suspicious verdicts to calculate the reputation
                # Malicious = 2 * suspicious, i.e. a malicious verdict is weighted twice as much as a suspicious verdict
                try: this_ioc_as_dict['reputation'] = ((2*n_m) + n_s) / (n_m + n_s) 
                except ZeroDivisionError: this_ioc_as_dict['reputation'] = 0.0
            except KeyError: 
                # Key error means the 'last_analysis_stats' key doesn't exist
                this_ioc_as_dict['reputation'] = -1
            
            # If we have "created_date" in the results, convert from the Unix timestamp
            if 'creation_date' in this_ioc_as_dict: 
                unix_ts:int = this_ioc_as_dict.get('creation_date')
                created_date:dt.datetime = dt.datetime.fromtimestamp(unix_ts).strftime('%Y-%m-%d %H:%M:%S')
                this_ioc_as_dict['creation_date'] = created_date
                
            # Append this IOC to the return dict
            return_dicts.append(this_ioc_as_dict)
            
        # Return the results as a list of dictionaries 
        return return_dicts