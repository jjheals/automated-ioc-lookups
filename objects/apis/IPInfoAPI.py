from .AbstractAPI import AbstractAPI
from ..ioc_types import AbstractIOC
from ..ioc_types import IPAddress 
import requests 


class IPInfoAPI(AbstractAPI):
    
    def __init__(self, token:str): 
        super().__init__(token)
        
    
    def lookup_iocs(self, iocs:list[dict | AbstractIOC]) -> list[dict]: 
        """Takes in a list of IOCs and looks up the IOCs using the IPInfo API.
        
            Args
                iocs (list[dict | AbstractIOC]): a list of IOCs either as dictionaries or as AbstractIOC objects.
            
            Returns 
                list[dict]: the results as a list of dictionaries.
        """ 
        # Init list of dicts to return 
        return_dicts:list[dict] = []
        
        # Define the API URL and headers for the request 
        base_url = f"https://ipinfo.io/"
        headers = { 
            "Accept": "application/json"
        }
                
        # Iterate over the IOCs and lookup each 
        for ioc in iocs: 
            
            # Convert to dict if not dict 
            if ioc.__class__.__name__ != 'dict': ioc = ioc.to_dict()
            
            # If this ioc doesn't have a value, then skip it
            if not ioc.get('value', ''): continue
            
            # Check that this IOC is an IPAddress
            this_ioc_type:str = ioc.get('type', '')    
            if this_ioc_type != 'IPAddress': continue 
            
            try:
                # Make the API request for this IOC
                ip_info = requests.get(base_url + f'{ioc["value"]}?token={self.token}', headers=headers).json()   
                
                # Extract complex attributes
                loc:list[float] = ip_info.get('loc', '')
                latitude:float = None
                longitude:float = None
                
                if loc: 
                    loc = loc.split(',')
                    latitude:float = float(loc[0])
                    longitude:float = float(loc[1])

                split_as:list = ip_info.get('org', '').split(" ")
                if split_as:
                    asn:int = split_as[0][2:]
                    as_org:str = " ".join(split_as[1:])
                else: 
                    asn:int = None
                    as_org:str = None
                    
                    
                return_dicts.append({
                    'value': ioc['value'],
                    'resolved_domain': ip_info.get('hostname', ''),
                    'city': ip_info.get('city', ''),
                    'state': ip_info.get('region', ''),
                    'country': ip_info.get('country', ''),
                    'asn': int(asn),
                    'as_org': as_org,
                    'latitude': latitude,
                    'longitude': longitude
                })
            
            # Handle any exceptions
            except Exception as e:
                print(f'\033[91mERROR: \033[90mIPInfoAPI.lookup_iocs(): error looking up the IOC "{ioc}"')
                print(e)
                continue
        
        # Return the list of results
        return return_dicts