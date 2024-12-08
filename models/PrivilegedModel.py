import requests
from . import AuthModel

class PrivilegedAPIError(Exception):
    """
        PrivilegedAPIError exception
    """
    pass

class PrivilegedModel:
    
    def __init__(self, model: AuthModel) -> None:
        """
            Initialize PrivilegedModel
            
            Args:
                model (AuthModel): Authenticated AuthModel object
        """
        if type(model) is not AuthModel.AuthModel:
            raise PrivilegedAPIError("PrivilegedAPIError: Invalid model type")
        
        self.model = model
        
    def get_session_channel(self):
        """
            Get session channel
            
            Raises:
                PrivilegedAPIError: Failed to get session channel
        """       
        url = "https://api.freedommobile.ca/api/v1/session?channel=myaccount"
        headers = {
            "Authorization": "Bearer " + self.model.get_bearer()
        }
        
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            raise PrivilegedAPIError("Get session channel - failed, HTTP ", response.status_code)
        
        return response.json()
    
    def get_billing(self):
        """
            Get billing information
            
            Raises:
                PrivilegedAPIError: Get billing - failed, HTTP status_code
        """
        if not self.model.is_authenticated():
            raise Exception("Get billing: user not authenticated")
        
        url = "https://api.freedommobile.ca/api/v1/services/billing"
        headers = {
            "Authorization": "Bearer " + self.model.get_bearer()
        }
        
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            raise PrivilegedAPIError("Get billing - failed, HTTP ", response.status_code)
        
        return response.json()