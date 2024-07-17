from .AbstractIOC import AbstractIOC

import re


class IPAddress(AbstractIOC): 
    
    ipv4_regex:str = r'^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
    ipv6_regex:str = r'^((?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?:(?::[0-9A-Fa-f]{1,4}){1,6})|:(?:(?::[0-9A-Fa-f]{1,4}){1,7}|:))$'
    
    
    def __init__(self, value): 
        super().__init__(value, 'IPAddress')
    
    
    @staticmethod
    def from_dict(d:dict) -> 'IPAddress':
        """Create an IPAddress from the given dictionary."""
        return IPAddress(d.get('value', ''))
        
        
    @staticmethod
    def match_ipv4_regex(val:str) -> bool: 
        """Matches the given value to an IPv4 regex string and returns the result as bool."""
        return re.compile(IPAddress.ipv4_regex).match(val)
    
    
    @staticmethod
    def match_ipv6_regex(val:str) -> bool: 
        """Matches the given value to an IPv6 regex string and returns the result as bool."""
        return re.compile(IPAddress.ipv6_regex).match(val)