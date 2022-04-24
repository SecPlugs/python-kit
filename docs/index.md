---
layout: none
---

## About
A {brand-name} powered, pip installable Python module.

The this code is open source so you can modify as you wish.

## Installation
Install from PyPi as follows 

```sh
pip install secplugs-python-client
```

You'll now have the python module installed ready to import and use in you code

## Usage
Usage pattern is to import the secplugs library, instanciate a secplugs class and use its methods to scan objects and get the results

### Scan a File

```python
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
```

## Contact
Having trouble? [Contact {brand-name} ](https://{brand-root-domain}/contacts)

