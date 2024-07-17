from abc import ABC, abstractmethod

class AbstractIOC(ABC):
    
    def __init__(self, value:str, type_:str): 
        self.value = value
        self.type = type_
        
    @abstractmethod
    def to_dict(self) -> dict: 
        """Returns this IOC as a dictionary."""
        raise NotImplementedError
    
    
    def to_dict(self) -> dict: 
        """Return this AbstractIOC as a dictionary."""
        return self.__dict__
    
    
    @staticmethod
    def from_dict(d:dict) -> 'AbstractIOC': 
        """Creates an AbstractIOC obj from the given dictionary."""
        raise NotImplementedError