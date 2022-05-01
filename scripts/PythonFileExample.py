'''
 Title: Python Example Secplugs File Plugin
 Author: TheStig@scancloud.io

 Purpose: This example submits a file (eicar if not specified) to file/quickscan
 (uploading if neccesary), waits on the report_id, and then prints out the results.
 It uses the asynchronous mock vendor and sends context data
 containing version and client uuid

 Concepts: File End Points, API Keys, A synchronous, context data, mock vendor, file upload

'''

# Create & delete the temporary eicar file
import tempfile
import os
import time
import sys

# sha256
import hashlib

# json parsing api responses etc
import json

# Use requests for the REST calls
import requests


# RFC 4122 compliant v4 uuid - generate at install time
# https://docs.python.org/3/library/uuid.html#uuid.uuid4
CLIENT_UUID = '6491f6d0-40b5-11eb-b378-0242ac130003'

# Version format is the same as https://developer.chrome.com/docs/extensions/mv2/manifest/version/
# Note: generate at build time
PLUGIN_VERSION = '2.71.82.84'

# Api key to use, we'll use the mock asynch api key
# Note: The below keys are public domain and do not need to be kept secret.
# They are protected from abuse with usage quotas.
MOCK_ASYNC_API_KEY = "GW5sb8sj8D9CtvVrjsTC22FNljxhoVuL1UoM6fFL"

# We will poll every second
POLLING_INTERVAL = 1000

# The production api
FILE_QUICKSCAN_END_POINT = "https://api.live.secplugs.com/security/file/quickscan"
FILE_UPLOAD_ENDPOINT = "https://api.live.secplugs.com/security/file/upload"
REPORT_ENDPOINT = "https://api.live.secplugs.com/security/report"

# Request headers
HEADERS = {
    "x-api-key" : MOCK_ASYNC_API_KEY
}

def file_upload(file_path, sha256):
    ''' Upload a file to secplugs broker

    '''

    # get the pre signed upload info
    response = requests.get(FILE_UPLOAD_ENDPOINT,
                            {'sha256': sha256},
                            headers=HEADERS)
    # check ok
    assert response.ok
    response_json = json.loads(response.content)
    pre_signed_post = response_json['upload_post']

    # Upload the file with the pre signed post
    with open(file_path, 'rb') as file_to_upload:
        files = {'file': (sha256, file_to_upload)}
        response = requests.post(pre_signed_post['url'],
                                 data=pre_signed_post['fields'],
                                 files=files)

    # check ok
    assert response.ok




def create_random_eicar_file():
    ''' Create a file with eicar string in it followed by hash bust data, returns the path
    Note: caller deletes
    '''

    # https://en.wikipedia.org/wiki/EICAR_test_file
    eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    file_contents = eicar_string + str(time.time())

    # Create the file
    temp_file = tempfile.NamedTemporaryFile(prefix="eicar_", \
                                            suffix=".tmp",
                                            delete=False)
    file_data = bytearray()
    file_data.extend(map(ord, file_contents))
    temp_file.write(file_data)
    temp_file.close()

    # return file path
    return temp_file.name

def get_file_sha256(file_path):
    ''' return the sha256 of a file at the specified path '''

    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as file:

        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda f=file: f.read(4096), b""):
            sha256_hash.update(byte_block)

    # return file sha256
    sha256_str = str(sha256_hash.hexdigest())
    return sha256_str

def submit_file(file_path):
    ''' submits the file for scanning '''

    # get the hash
    sha256 = get_file_sha256(file_path)

    # Build the scan context
    scancontext = {
        "client_uuid": CLIENT_UUID,
        "plugin_version": PLUGIN_VERSION,
        "file_name" : os.path.basename(file_path)
    }

    # Query params are url and scancontext
    query_parameters = {
        "sha256" : sha256,
        "scancontext" : json.dumps(scancontext)

    }

    # submit it
    response = requests.get(
        url=FILE_QUICKSCAN_END_POINT,
        params=query_parameters,
        headers=HEADERS)

    # Do we need to upload?
    if response.status_code == 404:

        # upload it
        print(".uploading.", end='', flush=True)
        file_upload(
            file_path=file_path,
            sha256=sha256)

        # retry now its been uploaded
        response = requests.get(
            url=FILE_QUICKSCAN_END_POINT,
            params=query_parameters,
            headers=HEADERS)

    # Check ok and get report id
    assert response.ok
    json_response = response.json()
    report_id = json_response['report_id']

    # Poll until done
    max_polls = 60
    while json_response['status'] == 'pending':

        # poll
        report_request_url = REPORT_ENDPOINT + '/' + report_id
        response = requests.get(
            url=report_request_url,
            headers=HEADERS)

        # Next
        print(".", end='', flush=True)
        time.sleep(POLLING_INTERVAL / 1000)
        json_response = response.json()

    # Check ok and did not time out
    assert response.ok and max_polls > 0

    # Done, print summary
    print(".Done", end='')
    score = json_response['score']
    verdict = json_response['verdict']
    duration = json_response['duration']
    threat_object = json.dumps(json_response['threat_object'])
    vendor_config_name = json_response['meta_data']['vendor_info']['vendor_config_name']
    print("")
    print("--- Analysis Summary ---")
    print(f'Score: {score}')
    print(f'Verdict: {verdict}')
    print(f'Duration: {duration}')
    print(f'Threat Object: {threat_object}')
    print(f'Vendor Cfg. Used: {vendor_config_name}')
    print(f'Full Report: https://secplugs.com/plugin_landing/viewreport.php?report_id={report_id}')


print('Welcome to the Python Example Secplugs File Plugin')

RANDOM_EICAR_FILE = create_random_eicar_file()

# Check for file path in command line
if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
    FILE_TO_SCAN = sys.argv[1]
    print(f'using provided file {FILE_TO_SCAN}')
else:
    FILE_TO_SCAN = RANDOM_EICAR_FILE
    print(f'no file provided, will use {FILE_TO_SCAN}')

# Submit for scanning
submit_file(FILE_TO_SCAN)

# Delete the eicar file
os.remove(RANDOM_EICAR_FILE)
