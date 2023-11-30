import json
import re

file_path = "./strings_output_C2.json"
with open(file_path, 'r') as file:
    json_data = json.load(file)

count = 0

strings = []
with open("./English.txt", 'r') as file:
    for line in file:
        strings.append(line.strip())

for item in json_data["strings"]:
    for s in strings:
        if s in item["value"]:
            print(item["value"], " + ", item["location"])
    else:
        count = count + 1    
    
print("Filtered out: " + str(count))