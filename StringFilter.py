# Example Ghidra script to extract and print strings from memory

import json
import subprocess
# Get the current program
currentProgram = getCurrentProgram()

# Get the listing
listing = currentProgram.getListing()

# Define the output file path
output_file_path = "./strings_output.json"

# Create a list to store string information
strings_list = []

# Iterate through data and add potential strings with their locations to the list
for data in listing.getDefinedData(True):
    string_value = data.getValue()
    data_location = data.getAddress()
    strings_list.append({"location": str(data_location), "value": str(string_value)})

# Iterate through instructions and add mnemonics to the list
instructions_list = []
for instruction in listing.getInstructions(True):
    mnemonic = instruction.getMnemonicString()
    instructions_list.append({"mnemonic": mnemonic})

# Create a dictionary to store the final JSON structure
json_data = {"strings": strings_list, "instructions": instructions_list}

# Open the output file for writing
with open(output_file_path, 'w') as output_file:
    # Write the JSON data to the file
    json.dump(json_data, output_file, indent=2)

# Print a message indicating the file has been written
print("JSON file has been written to:", output_file_path)

script_path = "./App_GUI.py"
subprocess.call(["python", script_path])