import json
import re

file_path = "./strings_output_C2.json"
with open(file_path, 'r') as file:
    json_data = json.load(file)

count = 0

strings_list = json_data["strings"]

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

for elem in strings_list:
    if re.search(r" \/[^\/\s]+(?:\/[^\/\s]+)+", elem["value"]):
        found_linux_commands.append(elem)
        print(elem)
        continue
    if re.search(r"[a-zA-Z]:\\(?:[^\\\/\s]+\\)*[^\\\/\s]+\.(exe|bat|cmd|ps1)", elem["value"]):
        found_windows_commands.append(elem)
        print(elem)
        continue
    for line in linux_commands:
        if ((line + " ") in elem["value"]):
            found_linux_commands.append(elem)
            print(elem)
            break
    for line in windows_commands:
        if ((line + " ") in elem["value"]):
            found_windows_commands.append(elem)
            print(elem)
            break
    else:
        count += 1
        
print("Filtered out: " + str(count))
