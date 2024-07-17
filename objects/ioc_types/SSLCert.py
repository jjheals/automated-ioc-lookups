from .AbstractIOC import AbstractIOC

# NOTE: constructed to match the SSL cert in a VirusTotal API response 
class SSLCert(AbstractIOC): 
    
    '''
        NOTE: preset attributes are only included to show the format. When creating a new SSLCert 
              object, the attributes are set from the outermost key ONLY; e.g., to set the public_key, 
              the 'public_key' key from the given dictionary is checked, NOT the individual keys in 
              the value of 'public_key' (rsa, rsa['key_size], 'algorithm', etc.). See __init__() for 
              more details. 
    '''
    size:int
    public_key:dict = {
        'rsa': { 
                'key_size': 0,
                'modulus': '',
                'exponent': ''
            },
        'algorithm': ''
    }
    thumbprint_sha256:str 
    cert_signature:dict = { 
        'signature': '',
        'signature_algorithm': ''
    }
    validity:dict = { 
        'not_after': '',
        'not_before': ''                 
    }
    version:str 
    extensions:dict 
    thumbprint:str 
    serial_number:str 
    issuer:dict 
    subject:dict = { 
        'CN': ''              
    }
    
    
    def __init__(self, d:dict): 
        
        # Set all attributes based on the format returned by the VT API 
        self.size = d['size']
        self.public_key = d['public_key']
        self.thumbprint_sha256 = d['thumbprint_sha256']
        self.cert_signature = d['cert_signature']
        self.validity = d['validity']
        self.version = d['version']
        self.extensions = d['extensions']
        self.thumbprint = d['thumbprint']
        self.serial_number = d['serial_number']
        self.issuer = d['issuer']
        self.subject = d['subject']
        
    def to_dict(self) -> dict: 
        return {
            'size': self.size,
            'public_key': self.public_key,
            'thumbprint_sha256': self.thumbprint_sha256,
            'cert_signature': self.cert_signature,
            'validity': self.validity,
            'version': self.version,
            'extensions': self.extensions, 
            'thumbprint': self.thumbprint,
            'serial_number': self.serial_number,
            'issuer': self.issuer,
            'subject': self.subject
        }


    def to_table_rows(self) -> dict: 
        """Return this SSLCert as a tuple that can be inserted into a table for SSLCerts."""
        return {
            'thumbprint': self.thumbprint,                                           # thumbprint
            'size': self.size,                                                       # size
            'public_key_algorithm': self.public_key['algorithm'],                    # public_key_algorithm
            'cert_signature_algorithm': self.thumbprint_sha256,                      # thumbprint_sha256
            'cert_signature_algorithm': self.cert_signature['signature_algorithm'],  # cert_signature_algorithm
            'cert_signature': self.cert_signature['signature'],                      # cert_signature
            'valid_after': self.validity['not_before'],                              # valid_after
            'valid_before': self.validity['not_after'],                              # valid_before
            'version': self.version,                                                 # version 
            'issuer_C': self.issuer.get('C', ''),                                    # issuer_C
            'issuer_O': self.issuer.get('O', ''),                                    # issuer_O
            'issuer_CN':self.issuer.get('CN', ''),                                   # issuer_CN
            'subject_C': self.subject.get('C', ''),                                  # subject_C
            'subject_ST': self.subject.get('ST', ''),                                # subject_ST
            'subject_O': self.subject.get('O', ''),                                  # subject_O
            'subject_CN': self.subject.get('CN', '')                                 # subject_CN
        }