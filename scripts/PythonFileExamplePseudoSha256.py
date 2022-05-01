'''
 Title: Python Example Secplugs File Plugin No SHA256
 Author: TheStig@scancloud.io

 Purpose: This example submits a file (eicar if not specified) to file/quickscan
 (uploading if neccesary), waits on the report_id, and then prints out the results.
 It uses the asynchronous mock vendor and sends context data
 containing version and client uuid. 
 It used a unique id instead of the files sha256

 Concepts: File End Points, API Keys, A synchronous, context data, mock vendor, file upload

'''

# Create & delete the temporary eicar file
import tempfile
import os
import time
import sys

# json parsing api responses etc
import json

# Import secplugs client
from secplugs import Secplugs


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

def process_result(json_response):
    # print summary
    print(".Done", end='')
    score = json_response['score']
    verdict = json_response['verdict']
    duration = json_response['duration']
    threat_object = json.dumps(json_response['threat_object'])
    vendor_config_name = json_response['meta_data']['vendor_info']['vendor_config_name']
    report_id = json_response['report_id']
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
s = Secplugs("ammzxNR0cm5HpIMwcC3rr72Ti8GWPXLo69EZAeyo")
result = s.scan_file(FILE_TO_SCAN)
process_result(result)

# Delete the eicar file
os.remove(RANDOM_EICAR_FILE)
