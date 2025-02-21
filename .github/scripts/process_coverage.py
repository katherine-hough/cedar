import json
import os
import pathlib
import sys
import xml.etree.ElementTree as ET


def collect_line_coverage(cobertura_file):
    tree = ET.parse(cobertura_file)
    root = tree.getroot()
    entries = []
    for package in root.find("packages"):
        for clazz in package.find("classes"):
            for line in clazz.find("lines"):
                entry = dict(
                    file_name=clazz.attrib["filename"],
                    line_number=line.attrib["number"],
                    hit_count=line.attrib["hits"],
                )
                entries.append(entry)
    return entries


def write_results(output_dir, passed, comment):
    os.makedirs(pathlib.Path(output_dir), exist_ok=True)
    status_file = os.path.join(output_dir, "status.txt")
    with open(status_file, "w") as f:
        f.write("PASSED" if passed else "FAILED")
    comment_file = os.path.join(output_dir, "markdown.md")
    with open(comment_file, "r") as f:
        f.write(comment)

def read_json(file):
    with open(file) as f:
        return json.load(f)

def process(
    cobertura_file, changed_lines_file, threshold, report_location, output_dir
):
    coverage_entries = collect_line_coverage(cobertura_file)
    changed_lines = read_json(changed_lines_file)
    write_results(output_dir, False, changed_lines)


def main():
    process(*sys.argv[1:])


if __name__ == "__main__":
    main()
