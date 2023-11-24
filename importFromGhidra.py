import psutil
import pyhidra
#import ghidra.app.script.GhidraScript
#import ghidra.program.model.data.StringDataType as StringDataType
#import exceptions
def is_ghidra_running():
    # Check for Ghidra in running processes
    for process in psutil.process_iter(['pid', 'name', 'cmdline']):
        # Process name normalization (lowercase)
        process_name = process.info['name'].lower() if process.info['name'] else ""

        # On Windows, Ghidra runs as 'javaw.exe', on Linux it's usually 'java'
        valid_process_names = ['javaw.exe', 'java']

        # Check if the process name is in the list of valid names
        if any(proc_name in process_name for proc_name in valid_process_names):
            # Check if 'ghidra' is in the command line arguments
            cmdline = ' '.join(process.info['cmdline']).lower() if process.info['cmdline'] else ""
            if 'ghidra' in cmdline:
                return True
    return False

if is_ghidra_running():
    print("Ghidra is running.")
else:
    print("Ghidra is not running.")
