from .AbstractIOC import AbstractIOC
import re


class Domain(AbstractIOC): 
    
    domain_regex:str = r'^(?=.{1,253}$)((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$'
    
    
    def __init__(self, value:str): 
        super().__init__(value, 'Domain')
    
    
    def from_dict(d:dict) -> 'Domain': 
        """Creates a Domain obj from the given dictionary."""
        return Domain(d.get('value', ''))
    
    
    @staticmethod
    def match_domain_regex(val:str) -> bool:
        """Matches the given value to a domain regex string and returns the result as bool."""
        return re.compile(Domain.domain_regex).match(val)        
    
    
    @staticmethod
    def get_supradomain(domain:str) -> str: 
        """Takes in a domain as a string and returns just the supradomain."""
        return '.'.join(domain.split('.')[-2:])