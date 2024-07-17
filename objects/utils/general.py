import pandas as pd 
import re 
from ..ioc_types import IPAddress, Domain


def validate_date_format(date:str) -> bool: 
    """Checks that the given date is in yyyy-mm-dd format."""
    # Split the date on hyphens 
    split_date:list[str] = date.split('-')
    
    # Check 1: if the resulting list is not 3 values long, then it is invalid
    if len(split_date) != 3: 
        print('incorrect number of values')
        return False
    
    # Check 2: Check that the length of the first value is 3, the second is 2, and the third is 2
    if(
        len(split_date[0])  != 4 or 
        len(split_date[1])  != 2 or 
        len(split_date[2]) != 2
    ): 
        return False 
    
    # Check 3: Make sure all values are integers, and that the mm is 1 <= mm <= 12, and the day is 1 <= dd <= 31
    if(
        (not split_date[0].isdigit()) or                # YYYY is an int
        (not split_date[1].isdigit()) or                # mm is an int
        (not split_date[2].isdigit()) or                # dd is an int 
        (int(split_date[1]) < 0 or int(split_date[1]) > 12) or    # 1 <= mm <= 12
        (int(split_date[2]) < 0 or int(split_date[2]) > 31)       # 1 <= dd <= 31
    ): 
        return False 
    
    # True if we make it here 
    return True 


def get_ioc_type(ioc:str) -> Domain | IPAddress | None: 
    """Takes in an IOC as a string and returns the type of that IOC, either <class 'Domain'> or <class 'IPAddress'>.
    Note that since an IPAddress can technically also be a Domain, this function checks IPAddress first and only 
    checks Domain if IPAddress is false.""" 
    # Check if the ioc is an IPAddress, either IPv4 or IPv6
    if IPAddress.match_ipv4_regex(ioc) or IPAddress.match_ipv6_regex(ioc): return IPAddress.__name__
    
    # Check if the ioc is a Domain
    elif Domain.match_domain_regex(ioc): return Domain.__name__
    
    # Type not recognized
    else: return None


def list_to_dict(lst:list[dict], pk:str='value') -> dict: 
    """Takes in a list of dictionaries and rearranges the values into a single dictionary where the given 
    [pk] is the "primary key" that becomes the key of the new dictioanry.""" 
    return { 
        v[pk] : v for v in lst
    }
    
    
def get_ioc_type(ioc:str) -> Domain | IPAddress | None: 
    """Takes in an IOC as a string and returns the type of that IOC, either <class 'Domain'> or <class 'IPAddress'>.
    Note that since an IPAddress can technically also be a Domain, this function checks IPAddress first and only 
    checks Domain if IPAddress is false.""" 
    # Check if the ioc is an IPAddress, either IPv4 or IPv6
    if IPAddress.match_ipv4_regex(ioc) or IPAddress.match_ipv6_regex(ioc): return IPAddress.__name__
    
    # Check if the ioc is a Domain
    elif Domain.match_domain_regex(ioc): return Domain.__name__
    
    # Type not recognized
    else: return None


def check_str_contains(los:list[str], target_str:str) -> str | None: 
    """Takes in a list of strings [los] and checks of any of the values are present in the
    given strings [target_str]. Returns the value from los that was found in the target_str, 
    or None if none of the strings are present in target_str. NOTE: case insensitive."""
    
    # Standardize target_str to all lowercase
    target_str = target_str.lower()
    
    # Iterate over the strings in los to find any that are in target_str
    for s in los: 
        if s.lower() in target_str:
            return s 
        
    # None found if we make it here
    return None 


def clean_string(input_str:str) -> str: 
    """Takes in a string and removes all special chars, spaces, and strips trailing and leading whitespace."""
    pattern:str = r'[^a-zA-Z0-9]'
    return re.sub(pattern, '', input_str.strip())