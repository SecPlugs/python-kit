#!/bin/bash
# Runs tests

# Check return code and exit on failure 
function check_return_code_ok {

    if [ $1 -ne 0 ]; then
        echo ':-{'
        exit $1
    fi
}

# Check return code and exit if no failure 
function check_return_code_not_ok {

    if [ $1 -eq 0 ]; then
        echo ':-{'
        exit $1
    fi
}

# Requires Python 3
python3 --version
check_return_code_ok $?

# Install secplugs
pip install secplugs-python-client
check_return_code_ok $?

# Uses pip installed class 
python3 scripts/FileScanExample.py 
check_return_code_ok $?

# Uses Proxy
python3 scripts/PythonFileExamplePseudoSha256.py 
check_return_code_ok $?

# Direct file upload
python3 scripts/PythonFileExample.py 
check_return_code_ok $?

echo 'tests pass'
