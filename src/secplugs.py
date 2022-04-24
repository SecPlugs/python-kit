"""
secplugs.py: The secplugs python client

Purpose: This is a python client for the secplugs REST api.
"""

# sha256
import hashlib
# Use requests for the REST calls
import requests
# json handling
import json
# Path handling
import pathlib

import os
import sys

# RFC 4122 compliant v4 uuid - generate at install time
# https://docs.python.org/3/library/uuid.html#uuid.uuid4
CLIENT_UUID = '6491f6d0-40b5-11eb-b378-0242ac130003'

# Version format is the same as https://developer.chrome.com/docs/extensions/mv2/manifest/version/
# Note: generate at build time
PLUGIN_VERSION = '2.71.82.84'

FILE_QUICKSCAN_END_POINT = "https://api.live.secplugs.com/security/file/quickscan"
FILE_UPLOAD_ENDPOINT = "https://api.live.secplugs.com/security/file/upload"
SECPLUGS_CLEAN_MID_SCORE = 70


class Secplugs(object):
    """The secplugs python client."""

    def __init__(self, api_key="GW5sb8sj8D9CtvVrjsTC22FNljxhoVuL1UoM6fFL"):
        """Initialise the secplugs client with the API key."""
        self.__apikey = api_key
        self.headers = {
            'x-api-key': api_key
        }
        self.file_name = None
        self.cksum = None

    @property
    def apikey(self):
        return self.__apikey

    @apikey.setter
    def apikey(self, key):
        self.__apikey = key

    def is_clean(self, file_name):
        """Convenience method to check if a file is clean or malicious."""
        fp = pathlib.PosixPath(file_name)
        if not fp.exists():
            raise FileNotFoundError(f"{file_name} doesn't exist")
        result = self.scan_file(file_name)
        if ("score" in result) and ("error" not in result):
            if result.get("score") < SECPLUGS_CLEAN_MID_SCORE:
                return False
            else:
                return True
        else:
            return False

    def scan_file(self, file_name):
        """Convenience method t o trigger a file scan."""
        fp = pathlib.PosixPath(file_name)
        if not fp.exists():
            raise FileNotFoundError(f"{file_name} doesn't exist")
        self.cksum = self.get_file_sha256(file_name)
        self.file_name = file_name
        response = self.quick_scan()
        # Do we need to upload the file ?
        if response.status_code == 404:
            upload_info = self.get_presigned_url(file_name)
            if "error" in upload_info:
                return "{'error': upload_info.get('msg'), 'score': -1}"
            else:
                upload_res = self.upload_file(upload_info)
                result = self.quick_scan()
                if result.ok:
                    return result.json()
                else:
                    return "{'error': str(result.text), 'score': -1}"
        else:
            return response.json()
        
    def get_file_sha256(self, file_path):
        """return the sha256 of a file at the specified path"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as file:

            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda f=file: f.read(4096), b""):
                sha256_hash.update(byte_block)

        # return file sha256
        sha256_str = str(sha256_hash.hexdigest())
        return sha256_str

    def get_presigned_url(self, file_name):
        # compute checksum
        self.cksum = self.get_file_sha256(file_name)

        self.file_name = file_name
        # get the pre signed upload info
        response = requests.get(FILE_UPLOAD_ENDPOINT,
                                {'sha256': self.cksum},
                                headers=self.headers)
        if response.ok:
            return response.json()
        else:
            return {"error": True, "msg": str(response.text)}
    
    def upload_file(self, upload_info):
        """Upload the file to be scanned to the AWS S3 buckets."""
        response_json = upload_info
        pre_signed_post = response_json['upload_post']

        # Upload the file with the pre signed post
        with open(self.file_name, 'rb') as file_to_upload:
            files = {'file': (self.cksum, file_to_upload)}
            response = requests.post(pre_signed_post['url'],
                                     data=pre_signed_post['fields'],
                                     files=files)

    def quick_scan(self):
        """Submits the file for a quick scan"""

        # Build the scan context
        scancontext = {
            "client_uuid": CLIENT_UUID,
            "plugin_version": PLUGIN_VERSION,
            "file_name" : os.path.basename(self.file_name)
        }

        # Query params are url and scancontext
        query_parameters = {
            "sha256" : self.cksum,
            "scancontext" : json.dumps(scancontext)
        }

        # submit it
        response = requests.get(url=FILE_QUICKSCAN_END_POINT,
                                params=query_parameters,
                                headers=self.headers)
        return response
