# PE File Analyzer

This Python script analyzes Portable Executable (PE) files, focusing on extracting regular strings, discovering potentially obfuscated strings, and retrieving embedded data. The script utilizes the `pefile` library for handling PE files and the `gooey` library for creating a graphical user interface (GUI).

## Functions

### `retrieve_all_embedded_data_pe(pe)`

- Retrieves all embedded data from a PE file.
- Parameters:
  - `pe` (pefile.PE): The PE file object.
- Returns:
  - dict: A dictionary containing section names or resource types as keys and corresponding embedded data as values.

### `get_regular_strings(pe)`

- Retrieves regular ASCII strings from the given PE file.
- Parameters:
  - `pe` (pefile.PE): The PE file object.
- Returns:
  - list: A list of regular ASCII strings.

### `discover_obfuscated_strings(pe, regular_strings)`

- Discovers potentially obfuscated strings by analyzing the strings for uncommon patterns.
- Parameters:
  - `pe` (pefile.PE): The PE file object.
  - `regular_strings` (list): A list of regular ASCII strings.
- Returns:
  - list: A list of potentially obfuscated strings.

### `write_results_to_text_file(regular_strings, obfuscated_strings, embedded_data, output_file_path)`

- Writes the analysis results to a text file.
- Parameters:
  - `regular_strings` (list): A list of regular ASCII strings.
  - `obfuscated_strings` (list): A list of potentially obfuscated strings.
  - `embedded_data` (dict): A dictionary containing embedded data.
  - `output_file_path` (str): Path to the output text file.

### `main()`

- The main function decorated with `Gooey` for creating a user-friendly GUI.
- Parses command-line arguments, including the path to the PE file and the output text file.
- Loads the PE file using `pefile.PE`.
- Calls other functions to analyze the PE file, including retrieving regular strings, discovering obfuscated strings, and retrieving embedded data.
- Writes the analysis results to the specified output text file.

## Usage

- Execute the script from the command line or use the generated GUI to analyze a PE file.
- Provide the path to the PE file and specify the output text file.
- The script analyzes the file, extracts regular and potentially obfuscated strings, retrieves embedded data, and saves the results to the specified output file.
