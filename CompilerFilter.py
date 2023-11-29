import json
import re

file_path = "./strings_output.json"
with open(file_path, 'r') as file:
    json_data = json.load(file)

count = 0

strings = []
for item in json_data["strings"]:
    strings.append(item["value"])

for elem in strings:
    if not re.search(r"_ZNSt", elem):
        print(elem)
    else:
        count = count + 1
print("Filtered out: " + str(count))