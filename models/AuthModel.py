from datetime import datetime
from http.cookiejar import CookieJar
import json
import requests
import uuid
import hashlib
from urllib.parse import urlparse, parse_qs

class AuthError(Exception):
    """
        AuthError exception
    """
    pass

class AuthModel:

    def __init__(self, username, pin) -> None:
        """
            Initialize AuthModel; used for authenticating user with Freedom Mobile API and retrieving access token.

            Args:
                username (str): phone number/username
                pin (str): pin
                
            Raises:
                AuthError: Class init - Username or pin is empty
        """
        self._username = username
        self._pin = pin
        
        if len(self._username) == 0 or len(self._pin) == 0:
            raise AuthError("Class init - Username or pin is empty")
        
        self._req_sess = requests.Session()
        # state
        self._authenticated = False
        self._idt = None # id_token
        self._expiry = None # expires_in
        self._access_token = None # access bearer
        self._scope = None # scope
        # Magic
        self._code_verifier = self._generate_code_verifier()
        self._code = None

    def _generate_code_verifier(self) -> str:
        """
        
        Generate code verifier for auth

     
        """
        code_verifier = str(uuid.uuid4()) + str(uuid.uuid4()) + str(uuid.uuid4())
        code_verifier = code_verifier.replace("-", "").replace("_", "")
        return code_verifier

        
    def get_bearer(self) -> str:
        """
            Get access token

            Returns:
                str: access token
        """
        if not self._authenticated:
            raise AuthError("Get bearer: user not authenticated")
        return self._access_token

    def is_authenticated(self):
        """
            Check if user is authenticated

            Returns:
                bool: True if authenticated
        """
        return self._authenticated
        
    def authenticate(self):
        """
            Authenticate user
        """
        if self._authenticated:
            raise Exception("Authenticate: user already authenticated")
        
        self._validate_pin_and_get_auth_methods()
        self._validate_auth_method()
        self._validate_security_code(input("enter security code:"))
        self._get_openid_code()
        self._final_auth()
        
        if self._authenticated:
            print("User authenticated. Expires in: " + (self._expiry - datetime.now()) + " second(s)") 
        
            
    def _validate_pin_and_get_auth_methods(self) -> str:
        """
            Get available auth methods from Freedom Mobile API - stage 1 of 4 for authentication (MFA).

            Returns:
                dict: auth methods
            
            Raises:
                AuthError: Validate base info - failed, too many requests and authentication rate-limited; try again in 30 minutes
                AuthError: Validate base info - failed, invalid username or pin
                
        """       
        url = "https://prod-auth.prod.digital.aws.freedommobile.ca/api/v1/authentication/token"
        payload = {
            "msisdn": self._username,
            "pin": self._pin
        }
        headers = {
            "Content-Type": "application/json"
        }
        # send req
        response = self._req_sess.post(url, headers=headers, json=payload)
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 429:
            raise AuthError("Validate base info - failed, too many requests and authentication rate-limited; try again in 30 minutes")
        else:
            raise AuthError("Validate base info - failed, invalid username or pin")
        
    def _validate_auth_method(self, method=None) -> None:
        """
            Validate auth method, stage 2 of 4 for authentication (MFA).
            
            If method is None, function will attempt to use the base username from stage 1 to send the MFA code.

            Args:
                method (str): auth method
            
            Raises:
                AuthError: Validate MFA - MFA method not valid
        """
        url = "https://prod-auth.prod.digital.aws.freedommobile.ca/api/v1/authentication/security-code/send"

        if method is None:
            method = self._username
            
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "msisdnoremail": method
        }
        response = self._req_sess.post(url, headers=headers)
        
        if response.status_code != 204: # 204 no content --> successfully sent MFA code
            raise AuthError("Validate MFA - MFA method not valid")
        
    def _validate_security_code(self, code) -> None:
        """
            Validate security code, stage 3 of 4 for authentication (MFA).

            Args:
                code (str): security code

            Returns:
                True if code is valid
            
            Raises:
                AuthError: Validate security code - failed, code is empty
                AuthError: Validate security code - failed, code invalid
                
        """
        if len(code) == 0:
            raise AuthError("Validate security code - failed, code is empty")
        
        url = "https://prod-auth.prod.digital.aws.freedommobile.ca/api/v1/authentication/security-code/validate"
        
        payload = {
            "code": code
        }
        headers = {
            "Content-Type": "application/json"
        }
        response = self._req_sess.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            raise AuthError("Validate security code - failed, code invalid")
        
    def _get_openid_code(self) -> None:
        """
            Get code req. for retrieving access JWT. Used internally only.
            
            Raises:
                AuthError: Failed to get OpenID token: code verifier is null
                AuthError: Failed to get OpenID token - header 'Location' was missing
                AuthError: Failed to get OpenID token - code was not in query URL
                AuthError: Failed to get OpenID token - state did not match, possible CSRF attack?
                AuthError: Failed to get OpenID token - unknown error
                
        """

        if self._code_verifier is None:
            raise AuthError("Failed to get OpenID token: code verifier is null")
      
        challenge = hashlib.sha256(self._code_verifier.encode()).hexdigest()
        
        url = "https://prod-auth.prod.digital.aws.freedommobile.ca/connect/authorize"
        payload = {
            "client_id": "fmmyaccount",
            "redirect_uri": "https://myaccount.freedommobile.ca/callback-oidc",
            "response_type": "code",
            "scope": "openid fmapi/account fmapi/bundleread",
            "state": self._state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        
        # https://myaccount.freedommobile.ca/callback-oidc?code=[code]&state=[state]&iss=[iss]&session_state=[session_state]
        response = self._req_sess.get(url, params=payload, allow_redirects=False)
      
        if response.status_code >= 300 and response.status_code < 400: # should be some sort of redirect code
            loc = response.headers.get("Location")
            if loc is None:
                raise AuthError("Failed to get OpenID code - header 'Location' was missing")
            parsed_loc = urlparse(loc)
            query = parse_qs(parsed_loc.query)
            if query.get("code") is None:
                raise AuthError("Failed to get OpenID token - code was not in query URL")
            #if query.get("state") != self._state: # TODO: Fix this check
            #    raise AuthError("Failed to get OpenID token - state did not match, possible CSRF attack?")
            
            
            self._code = query.get("code")
            print("code: ", self._code)
            return None
        
        raise AuthError("Failed to get OpenID token - unknown error")

    def _final_auth(self):
        """
            Final authentication step, MFA complete. Grab JWT. Stage 4 of 4 for authentication (MFA).
            
            Raises:
                AuthError: Final auth failed - code or code_verifier is null
                AuthError: Final auth - invalid HTTP status code (status_code)
        """
        if self._code is None or self._code_verifier is None:
            raise AuthError("Final auth failed - code or code_verifier is null")
                
        url = "https://prod-auth.prod.digital.aws.freedommobile.ca/connect/token"
        payload = {
            "client_id": "fmmyaccount",
            "code": self._code,
            "code_verifier": self._code_verifier,
            "grant_type": "authorization_code",
            "redirect_uri": "https://myaccount.freedommobile.ca/callback-oidc"
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        response = self._req_sess.post(url, headers=headers, data=payload)
        
        if response.status_code == 200:
            data = response.json()
            self._idt = data.get("id_token")
            self._expiry = datetime.datetime.now() + datetime.timedelta(seconds=data.get("expires_in"))
            self._access_token = data.get("access_token")
            self._scope = data.get("scope")    
            self._authenticated = True
        else:
            print(response.text)
            raise AuthError("Final auth - invalid HTTP status code (" + str(response.status_code) + ")")        