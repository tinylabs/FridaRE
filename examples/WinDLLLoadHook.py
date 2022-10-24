#!/bin/env python3
#
# Trap all DLL loads and print info
#
from FridaRE import *


if __name__ == '__main__':

    def dll_load_cb (d):
        if d['name'] == 'load_enter':
            print (f'DLL={d["filename"]}')
        elif d['name'] == 'load_exit':
            print (f'Returned: {d["retval"]}')
        
    load_enter = RPC ('load_enter', dll_load_cb)
    load_exit = RPC ('load_exit', dll_load_cb)
    
    hook_load = HookFn ('LoadLibraryA', ['filename char*', 'void*'])
    hook_load.onEnter (load_enter)
    hook_load.onExit (load_exit)

    # Dump script
    print (hook_load)

    # Create session
    re = FridaRE (sys.argv[1])

    # Run session
    re.run (hook_load)
