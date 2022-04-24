'''
 Title: Python Example Secplugs File Plugin
 Author: TheStig@secplugs.com

 Purpose: This example submits a file (eicar if not specified) to file/quickscan
 (uploading if neccesary), waits on the report_id, and then prints out the results.
 It uses the asynchronous mock vendor and sends context data
 containing version and client uuid

 Concepts: File End Points, API Keys, A synchronous, context data, mock vendor, file upload

'''

# Import the library
import secplugs

def scan_self():
    ''' Scan the current file '''
    file_scanner = secplugs.Secplugs()
    file_name = __file__
    if file_scanner.is_clean(file_name):
        print(f'{file_name} is clean')
    else:
        print(f'{file_name} is suspicous')

# Scan this source file
scan_self()
