import psutil
import pyhidra

def is_ghidra_running():
    # Get a list of all running processes
    for process in psutil.process_iter(['pid', 'name', 'cmdline']):
        print(process)
        # Check if the process is 'javaw.exe' and contains 'ghidra' in its command line
        if process.info['name'].lower() == 'javaw.exe' and 'ghidra' in ' '.join(process.info['cmdline']).lower():
            return True
    return False


if is_ghidra_running():
    print("Ghidra is running.")
else:
    print("Ghidra is not running.")


def main():
    print("Starting threads")
    print("Started the threads")
    print("All threads joined")


main()
