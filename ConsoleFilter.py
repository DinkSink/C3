import json
import re

def find_possible_console_commands(file_path):
        
    with open(file_path, 'r') as file:
        json_data = json.load(file)

    linux_commands = []
    windows_commands = []
        
    with open("./linuxDictionary.txt", "r") as linux_Dict:
        for line in linux_Dict.readlines():
            linux_commands.append(line.strip())
        
    with open("./windowsDictionary.txt", "r") as windows_Dict:
        for line in windows_Dict.readlines():
            windows_commands.append(line.strip())
        
    found_linux_commands = []
    found_windows_commands = []

    for elem in json_data["strings"]:
        if re.search(r" \/[^\/\s]+(?:\/[^\/\s]+)+", elem["value"]):
            found_linux_commands.append(elem)
            continue
        if re.search(r"[a-zA-Z]:\\(?:[^\\\/\s]+\\)*[^\\\/\s]+\.(exe|bat|cmd|ps1)", elem["value"]):
            found_windows_commands.append(elem)
            continue
        for line in linux_commands:
            if ((line + " ") in elem["value"]):
                found_linux_commands.append(elem)
                break
        for line in windows_commands:
            if ((line + " ") in elem["value"]):
                found_windows_commands.append(elem)
                break
    
    return found_linux_commands, found_windows_commands
            
file_path = "./strings_output_C2.json"
found_linux_commands, found_windows_commands = find_possible_console_commands(file_path)
if found_linux_commands:
    print("found linux commands: ")
    for elem in found_linux_commands:
        print(elem)

if found_windows_commands:
    print("found windows commands: ")
    for elem in found_windows_commands:
        print(elem)
