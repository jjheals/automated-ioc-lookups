from abc import ABC, abstractmethod
from ..ioc_types import AbstractIOC 


class AbstractAPI(ABC):
    
    def __init__(self, token:str): 
        self.token = token 
        
        
    @abstractmethod
    def lookup_iocs(self, iocs:list[dict | AbstractIOC]) -> list[dict]: 
        """Takes in a list of IOCs either as dictionaries or AbstractIOC objects and 
           looks up the IOCs using this API.""" 
        return NotImplementedError 