import json
import re

file_path = "./strings_output_C2.json"
with open(file_path, 'r') as file:
    json_data = json.load(file)

count = 0

strings = []
for item in json_data["strings"]:
    strings.append(item["value"])

for elem in strings:
    if not re.search(r"_Z", elem) and not re.search(r"gxx", elem) and not re.search(r"GLIBC", elem) and not re.search(r"CXX", elem) and not re.search(r"GCC", elem) and not (elem == "None") and not re.search(r"align", elem):
        print(elem)
    else:
        count = count + 1
print("Filtered out: " + str(count))