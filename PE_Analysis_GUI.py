import pefile
import re
from gooey import Gooey, GooeyParser  # Import Gooey decorators


def retrieve_all_embedded_data_pe(pe):
    """
    Retrieve all embedded data from a PE (Portable Executable) file.

    Parameters:
    - pe (pefile.PE): The PE file object.

    Returns:
    - dict: A dictionary containing section names or resource types as keys
            and corresponding embedded data as values.
    """
    embedded_data = {}

    # Extract section data
    for section in pe.sections:
        section_name = section.Name.decode('utf-8').rstrip('\x00')
        section_data = section.get_data()
        embedded_data[section_name] = section_data

    # Extract resources
    resources = pe.DIRECTORY_ENTRY_RESOURCE.entries
    for resource_type in resources:
        resource_type_name = pefile.RESOURCE_TYPE.get(resource_type.id, str(resource_type.id))
        for resource_name in resource_type.directory.entries:
            for resource_lang in resource_name.directory.entries:
                data_offset = resource_lang.data.struct.OffsetToData
                data_size = resource_lang.data.struct.Size
                data = pe.get_memory_mapped_image()[data_offset:data_offset + data_size]
                embedded_data[(resource_type_name, resource_name.name, resource_lang.name)] = data

    # Extract overlay data
    overlay_data = pe.get_overlay()
    if overlay_data:
        embedded_data["Overlay"] = overlay_data

    return embedded_data


def get_regular_strings(pe):
    """
    Get regular ASCII  strings from the given PE file.
    """
    regular_strings = []

    # Extract ASCII and Unicode strings from each section
    for section in pe.sections:
        section_data = section.get_data()

        # Match ASCII strings
        ascii_strings = re.findall(b"[ -~]{5,}", section_data)
        regular_strings.extend(ascii_strings)

    return regular_strings


def discover_obfuscated_strings(pe, regular_strings):
    """
    Discover potentially obfuscated strings by analyzing the strings for uncommon patterns.
    """
    obfuscated_strings = []

    # Extract all strings from the PE file
    all_strings = re.findall(b"[ -~]{5,}", pe.get_memory_mapped_image())

    # Find strings that are not in the list of regular strings
    for string in all_strings:
        if string not in regular_strings:
            obfuscated_strings.append(string)

    return obfuscated_strings


def write_results_to_text_file(regular_strings, obfuscated_strings, embedded_data, output_file_path):
    with open(output_file_path, 'w', encoding='utf-8') as output_file:
        output_file.write("Regular Strings:\n")
        for regular_string in regular_strings:
            output_file.write(f"{regular_string.decode('utf-8', errors='ignore')}\n")

        output_file.write("\nPotentially Obfuscated Strings:\n")
        for obfuscated_string in obfuscated_strings:
            output_file.write(f"{obfuscated_string.decode('utf-8', errors='ignore')}\n")

        output_file.write("\nEmbedded Data Results:\n")
        output_file.write("=" * 40 + "\n")
        for key, data in embedded_data.items():
            output_file.write(f"{key}:\n{data[:]}...\n")

        print(f"Results written to {output_file_path}")


@Gooey(program_name="PE File Analyzer", navigation='TABBED')
def main():
    parser = GooeyParser(
        description="Analyze strings in a PE file, discover potentially obfuscated strings, and retrieve embedded data.")
    parser.add_argument("pe_file", widget="FileChooser", help="Path to the PE file")
    parser.add_argument("output_file", widget="FileSaver", help="Path to the output text file")

    args = parser.parse_args()

    # Load the PE file using pefile
    try:
        pe = pefile.PE(args.pe_file)
    except pefile.PEFormatError as e:
        print(f"Error: {e}")
        return

    # Get regular strings from the PE file
    regular_strings = get_regular_strings(pe)

    # Discover potentially obfuscated strings
    obfuscated_strings = discover_obfuscated_strings(pe, regular_strings)

    # Retrieve embedded data
    embedded_data = retrieve_all_embedded_data_pe(pe)

    # Write results to a text file
    write_results_to_text_file(regular_strings, obfuscated_strings, embedded_data, args.output_file)


# Ensure that the __name__ check is outside of the decorated function


if __name__ == "__main__":
    main()
