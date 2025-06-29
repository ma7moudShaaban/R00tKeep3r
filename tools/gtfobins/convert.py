import os
import sys
import json
import yaml  # Requires: pip install pyyaml

def convert_md_to_json(md_directory, output_file):
    """
    Recursively scan the given directory for all .md files, parse their YAML front matter,
    and consolidate the parsed data into a single JSON file.
    
    Each file's YAML data is stored under a key derived from its relative path (without the .md extension).
    """
    consolidated_data = {}
    file_count = 0

    # Walk through the directory tree to get all markdown files.
    for root, _, files in os.walk(md_directory):
        for filename in files:
            if filename.lower().endswith(".md"):
                file_path = os.path.join(root, filename)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read()
                except Exception as e:
                    print(f"Error reading file {file_path}: {e}")
                    continue

                # Expect YAML front matter between the first two '---' delimiters.
                if content.startswith('---'):
                    parts = content.split('---')
                    if len(parts) < 3:
                        print(f"Warning: '{file_path}' does not contain valid YAML front matter. Skipping.")
                        continue
                    yaml_block = parts[1].strip()
                else:
                    print(f"Warning: '{file_path}' does not start with YAML front matter. Skipping.")
                    continue

                try:
                    parsed_data = yaml.safe_load(yaml_block)
                except Exception as e:
                    print(f"Error parsing YAML in '{file_path}': {e}")
                    continue

                # Use relative path from the md_directory as the key (without .md extension)
                key = os.path.splitext(os.path.relpath(file_path, md_directory))[0]
                consolidated_data[key] = parsed_data
                file_count += 1

    # Write the consolidated dictionary to the output JSON file.
    try:
        with open(output_file, "w", encoding="utf-8") as out_f:
            json.dump(consolidated_data, out_f, indent=4)
    except Exception as e:
        print(f"Error writing JSON to '{output_file}': {e}")
        sys.exit(1)

    print(f"Successfully converted {file_count} Markdown files into '{output_file}'.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python convert_gtfobins.py <md_directory> <output_json_file>")
        sys.exit(1)
    
    md_directory = sys.argv[1]
    output_file = sys.argv[2]
    convert_md_to_json(md_directory, output_file)
