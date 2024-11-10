from Dlllnjection import *
from SetPrivilege import *

SE_DEBUG_NAME = "SeDebugPrivilege"

if __name__ == "__main__":
    setPrivilege = SetPrivilege(SE_DEBUG_NAME, 1)
    dllInjection = DllInjection(sys.argv[1], sys.argv[2])

    #setPrivilege.open_process_token()
    #setPrivilege.lookup_privilege_value()
    #setPrivilege.adjust_token_privileges()

    dllInjection.open_process()
    dllInjection.virtual_alloc_ex()
    dllInjection.write_process_memory()
    dllInjection.get_module_handle()
    dllInjection.get_proc_address()
    dllInjection.create_remote_thread()
    dllInjection.wait_for_single_object()
    dllInjection.close_handle()