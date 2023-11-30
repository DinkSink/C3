import json
import re

def find_english_words(file_path):
    
    with open(file_path, 'r') as file:
        json_data = json.load(file)

    strings = []
    with open("./English.txt", 'r') as file:
        for line in file:
            strings.append(line.strip())
            
    found_words = []

    for item in json_data["strings"]:
        for s in strings:
            if s in item["value"]:
                found_words.append(item)
    
    return found_words

file_path = "./strings_output_C2.json"
found_words = find_english_words(file_path)
print("English Words Found: ")
for elem in found_words:
    print(elem)