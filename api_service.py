from enum import Enum
from typing import Dict, Optional, Any
import requests
from requests import Response

class HttpStatus(Enum):
    OK = 200
    CREATED = 201
    NO_CONTENT = 204

class ApiResponse:
    def __init__(self, status_code: int, headers: Dict[str, str], body: Any):
        self.status_code = status_code
        self.headers = headers
        self.body = body

class ApiService:
    def __init__(self, base_url: str, timeout: int = 30, verify_ssl: bool = True):
        self.base_url = base_url
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def _make_request(self, method: str, url: str, **kwargs) -> ApiResponse:
        """
        Make an HTTP request and return a custom ApiResponse object.

        :param method: HTTP method (get, post, patch, delete)
        :param url: URL path to be appended to base_url
        :param kwargs: Additional arguments for the request
        :return: ApiResponse object
        """
        full_url = self.base_url + url

        try:
            response: Response = getattr(requests, method)(
                full_url, 
                timeout=self.timeout, 
                verify=self.verify_ssl, 
                **kwargs
            )
            return ApiResponse(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.json() if response.content else None
            )
        except Exception as error:
            print(f"Error in {method.upper()} request to {full_url}: {error}")
            raise

    def get(self, url: str, headers: Optional[Dict[str, str]] = None, 
            expected_status: HttpStatus = HttpStatus.OK) -> ApiResponse:
        """
        Perform a GET request.

        :param url: URL path to be appended to base_url
        :param headers: Request headers
        :param expected_status: Expected HTTP status code
        :return: ApiResponse object
        """
        response = self._make_request('get', url, headers=headers)
        if response.status_code != expected_status.value:
            print(f"Unexpected status code: {response.status_code}, expected: {expected_status.value}")
        return response

    def post(self, url: str, body: Optional[Dict[str, Any]] = None, 
             headers: Optional[Dict[str, str]] = None, 
             expected_status: HttpStatus = HttpStatus.CREATED,
             files: Optional[Dict[str, Any]] = None) -> ApiResponse:
        """
        Perform a POST request.

        :param url: URL path to be appended to base_url
        :param body: Request body
        :param headers: Request headers
        :param expected_status: Expected HTTP status code
        :param files: Files to be uploaded
        :return: ApiResponse object
        """
        response = self._make_request('post', url, json=body, headers=headers, files=files)
        if response.status_code != expected_status.value:
            print(f"Unexpected status code: {response.status_code}, expected: {expected_status.value}")
        return response

    def patch(self, url: str, body: Optional[Dict[str, Any]] = None, 
              headers: Optional[Dict[str, str]] = None, 
              expected_status: HttpStatus = HttpStatus.OK,
              files: Optional[Dict[str, Any]] = None) -> ApiResponse:
        """
        Perform a PATCH request.

        :param url: URL path to be appended to base_url
        :param body: Request body
        :param headers: Request headers
        :param expected_status: Expected HTTP status code
        :param files: Files to be uploaded
        :return: ApiResponse object
        """
        response = self._make_request('patch', url, json=body, headers=headers, files=files)
        if response.status_code != expected_status.value:
            print(f"Unexpected status code: {response.status_code}")
        return response

    def delete(self, url: str, headers: Optional[Dict[str, str]] = None, 
               expected_status: HttpStatus = HttpStatus.NO_CONTENT) -> ApiResponse:
        """
        Perform a DELETE request.

        :param url: URL path to be appended to base_url
        :param headers: Request headers
        :param expected_status: Expected HTTP status code
        :return: ApiResponse object
        """
        response = self._make_request('delete', url, headers=headers)
        if response.status_code != expected_status.value:
            print(f"Unexpected status code: {response.status_code}")
        return response

    def add_auth(self, headers: Dict[str, str], auth_type: str, token: str) -> Dict[str, str]:
        """
        Add authentication to headers.

        :param headers: Existing headers
        :param auth_type: Type of authentication (e.g., 'Bearer', 'ApiKey')
        :param token: Authentication token
        :return: Updated headers
        """
        headers = headers or {}
        headers['Authorization'] = f"{auth_type} {token}"
        return headers