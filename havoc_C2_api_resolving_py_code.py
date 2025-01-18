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




#Psuedo code: Api hashing algorithm: 
###########################################################################
'''
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
        # print("%x" % hash)
        hash = (((hash << 5) + hash) + api_name[x] - 0x20) & 0xffffffff
    return hash & 0xFFFFFFFF

for filename in os.listdir("C:\\Windows\\System32"):
        if filename.lower() in INTERESTING_DLLS:
            pe = pefile.PE("C:\\Windows\\System32\\" + filename)
            #print(pe)
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name is not None:
                    calculated_hash = hash_djb2(exp.name)
                    print(calculated_hash)
                    exports_dict[calculated_hash] = exp.name.decode('utf-8')
                    print(exports_dict[calculated_hash])
                    print("""""")

def search(api_hash):
    if api_hash in exports_dict:
        print( exports_dict[api_hash])
    else:
        print("Not Found")


if __name__ == '__main__':
    print("hash of api")
    api_hash = int(input())
    # api_hash = int(input().strip(), 0x10)
    search(api_hash)
'''
##################################################################################
'''
int64 __fastcall sub_7FF8DC95F3F0(int a1)
{
  __int64 v2; // rax
  __int64 v3; // rax
  __int64 *v4; // rbx
  __int64 *v5; // rdi
  int v6; // eax

  v2 = qword_7FF8DC96A3D8; //random memory
  if ( !*(_QWORD *)(qword_7FF8DC96A3D8 + 0x8C2) ) //memory + 0x8C2
    *(_QWORD *)(qword_7FF8DC96A3D8 + 0x8C2) = NtCurrentTeb(); //TEB
  v3 = *(_QWORD *)(*(_QWORD *)(*(_QWORD *)(v2 + 0x8C2) + 0x60i64) + 0x18i64); //{{TEB + 0x8C2 == TEB + 0X60 == {VALUE AT TEB 60 IS PEB } + 0X18 == LDR }}
  v4 = *(__int64 **)(v3 + 0x10); //InLoadOrderModuleList : _LIST_ENTRY
  v5 = (__int64 *)(v3 + 0x10); //InLoadOrderModuleList : _LIST_ENTRY
  while ( v4 != v5 )
  {
    v6 = sub_7FF8DC95D040((unsigned __int8 *)v4[12], *((unsigned __int16 *)v4 + 0x2C), 1);
    if ( !a1 || v6 == a1 )
      return v4[6];
    v4 = (__int64 *)*v4;
  }
  return 0i64;
}

_int64 __fastcall sub_7FF8DC95D040(unsigned __int8 *a1, unsigned int a2, int a3)
{
  __int64 result; // rax
  unsigned __int8 *v4; // r10
  unsigned __int8 v5; // r9

  result = 0i64;
  if ( a1 )
  {
    v4 = a1;
    for ( result = 5381i64; ; result = (unsigned int)v5 + 33 * (_DWORD)result )
    {
      v5 = *v4;
      if ( a2 )
      {
        if ( (int)v4 - (int)a1 >= a2 )
          return result;
        if ( !v5 )
        {
          ++v4;
          goto LABEL_12;
        }
      }
      else if ( !v5 )
      {
        return result;
      }
      if ( v5 > 0x60u )
      {
        if ( a3 )
          v5 -= 32;
      }
LABEL_12:
      ++v4;
    }
  }
  return result;
}
'''

'''
union pe_info
{
  UINT_PTR pe_base;
  IMAGE_DOS_HEADER dos_header;
  IMAGE_NT_HEADERS64 nt_headers;
};
'''


0000000140007965 | 48:8B15 6C1A0100         | mov rdx,qword ptr ds:[1400193D8]        | rdx:LdrGetProcedureAddress
