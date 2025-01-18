Code to resolve api in havoc.

##########################################################################
import os
import pefile
import json
import sys
#
"""INTERESTING_DLLS = [
    'kernel32.dll', 'comctl32.dll', 'advapi32.dll', 'comdlg32.dll',
    'gdi32.dll',    'msvcrt.dll',   'netapi32.dll', 'ntdll.dll',
    'ntoskrnl.exe', 'oleaut32.dll', 'psapi.dll',    'shell32.dll',
    'shlwapi.dll',  'srsvc.dll',    'urlmon.dll',   'user32.dll',
    'winhttp.dll',  'wininet.dll',  'ws2_32.dll',   'wship6.dll',
    'advpack.dll',
]"""

INTERESTING_DLLS = ['kernel32.dll','ntdll.dll']

exports_dict = {}

def hash_djb2(api_name):
    hash = 5381
    for x in range(len(api_name)):
        ch = api_name[x]
        if ch >= 0x60:
            ch -= 0x20
        hash = ((((hash << 5) + hash) + ch)) & 0xffffffff
    return hash & 0xFFFFFFFF

for filename in os.listdir("C:\\Windows\\System32"):
        # print(filename)
        if filename.lower() in INTERESTING_DLLS:
            pe = pefile.PE("C:\\Windows\\System32\\" + filename)
            
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name is not None:
                    calculated_hash = hash_djb2(exp.name)
                    exports_dict[calculated_hash] = exp.name.decode('utf-8')
                    # print(exports_dict[calculated_hash])

def search(api_hash):
    if api_hash in exports_dict:
        print( exports_dict[api_hash])
    else:
        print("Not Found")


if __name__ == '__main__':
    print("hash of api")
    api_hash = int(input(), 0x10)
    
    
    search(api_hash)


###########################################################################




