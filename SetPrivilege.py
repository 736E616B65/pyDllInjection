from ctypes import *
from ctypes.wintypes import *

class LUID(Structure):
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", LONG)
    ]
class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD)
    ]

class TOKEN_PRIVILEGES(Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1)
    ]

TOKEN_ADJUST_PRIVILEGE  = 0x0020
TOKEN_QUERY             = 0x0008
SE_PRIVILEGE_ENABLED    = 0x00000002
ERROR_NOT_ALL_ASSIGNED  = 1300

class SetPrivilege:
    def __init__(self, privilege, enable_privilege):
        self.privilege = privilege
        self.enable_privilege = enable_privilege
        self.h_token = HANDLE()
        self.tp = TOKEN_PRIVILEGES()
        self.luid = LUID()
        self.kernel32 = windll.kernel32
        self.advapi32 = windll.advapi32

    def open_process_token(self):
        if not self.kernel32.OpenProcessToken(self.kernel32.GetCurrentProcess(),
                                              TOKEN_ADJUST_PRIVILEGE | TOKEN_QUERY,
                                              byref(self.h_token)):
            print(f"OpenProcessToken error: [{self.kernel32.GetLastError()}]")
            return False
        return True

    def lookup_privilege_value(self):
        if not self.advapi32.LookupPrivilegeValueW(None, self.privilege, byref(self.luid)):
            print(f"LookupPrivilegeValue error: [{self.kernel32.GetLastError()}]")
            return False
        return True

    def adjust_token_privileges(self):
        self.tp.PrivilegeCount = 1
        self.tp.Privileges[0].Luid = self.luid

        if self.enable_privilege:
            self.tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        else:
            self.tp.Privileges[0].Attributes = 0

        if not self.advapi32.AdjustTokenPrivileges(self.h_token,
                                                   0,
                                                   byref(self.tp),
                                                   sizeof(TOKEN_PRIVILEGES),
                                                   0,
                                                   0):
            print(f"AdjustTokenPrivileges error: [{self.kernel32.GetLastError()}]")
            return False

        if self.kernel32.GetLastError() == ERROR_NOT_ALL_ASSIGNED:
            print(f"The token does not have the specified privilege.")
            return False

        return True