"""
    Authentication client for Freedom Mobile API
    https://prod-auth.prod.digital.aws.freedommobile.ca/api/v1/authentication/token
"""

import requests
from models import AuthModel, PrivilegedModel

tmp = AuthModel.AuthModel("phonenumberhere", "pinhere")

try:
    tmp.authenticate()
    
    if tmp.is_authenticated():
        print(tmp._access_token())
        tmp2 = PrivilegedModel.PrivilegedModel(tmp)
        print(tmp2.get_billing())
        print(tmp2.get_session_channel())

except Exception as e:
    print(e)
    print("Error authenticating user")
    exit(1)
