# Example Ghidra script to extract and print strings from memory

# Get the current program
currentProgram = getCurrentProgram()

# Get the listing
listing = currentProgram.getListing()

# Define the output file path
output_file_path = "./strings_output.txt"

# Open the output file for writing
with open(output_file_path, 'w') as output_file:
    # Iterate through data and print potential strings with their locations
    for data in listing.getDefinedData(True):
        string_value = data.getValue()
        data_location = data.getAddress()
        output_line = "Potential String at {}: {}".format(data_location, string_value)
        print(output_line)
        output_file.write(output_line + '\n')

    # Iterate through instructions and print mnemonics
    for instruction in listing.getInstructions(True):
        mnemonic = instruction.getMnemonicString()
        # print("Mnemonic:", mnemonic)

# Print a message indicating the file has been written

