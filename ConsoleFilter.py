import json
import re

file_path = "./strings_output.json"
with open(file_path, 'r') as file:
    json_data = json.load(file)

count = 0

strings_list = json_data["strings"]
    
with open("./linuxDictionary.txt", "r") as linux_Dict:
    linux_commands = linux_Dict.readlines()
    
with open("./windowsDictionary.txt", "r") as windows_Dict:
    windows_commands = windows_Dict.readlines()

    
found_linux_commands = []
found_windows_commands = []

for line in strings_list:
    if (line["value"] in linux_commands) or (re.search(r" \/[^\/\s]+(?:\/[^\/\s]+)+", line["value"])):
        found_linux_commands.append(line)
        print(line)
    elif (line["value"] in windows_commands) or (re.search(r"[a-zA-Z]:\\(?:[^\\\/\s]+\\)*[^\\\/\s]+\.(exe|bat|cmd|ps1)", line["value"])):
        found_windows_commands.append(line)
        print(line)
    else:
        count += 1

print("Filtered out: " + str(count))
