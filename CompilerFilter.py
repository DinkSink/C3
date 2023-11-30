import json
import re

file_path = "./strings_output_C2.json"
with open(file_path, 'r') as file:
    json_data = json.load(file)

count = 0

strings = []
for item in json_data["strings"]:
    if not re.search(r"_Z", item["value"]) and not re.search(r"gxx", item["value"]) and not re.search(r"GLIBC", item["value"]) and not re.search(r"CXX", item["value"]) and not re.search(r"GCC", item["value"]) and not (item["value"] == "None") and not re.search(r"align", item["value"]):
        print(item["value"], " + ", item["location"])
    else:
        count = count + 1    
    
print("Filtered out: " + str(count))