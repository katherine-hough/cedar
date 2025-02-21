import json
import os
import pathlib
import sys
import xml.etree.ElementTree as ET

TEMPLATE = """
# Coverage Report

[Download the full coverage report]($$REPORT_LOCATION$$)

## Coverage of Added or Modified Lines of Rust Code
$$MOD_SUMMARY$$

<details>
<summary><b>Details</b></summary>
$$MOD_TABLE$$
</details>

## Coverage of All Lines of Rust Code
$$ALL_SUMMARY$$

<details>
<summary><b>Details</b></summary>
$$ALL_TABLE$$
</details>
"""

import itertools


def to_ranges(iterable):
    iterable = sorted(set(iterable))
    # Group elements by the difference between the value and its index
    for _, group in itertools.groupby(enumerate(iterable), lambda t: t[1] - t[0]):
        group = list(group)
        # Take the value of the first and last elements of the group
        yield group[0][1], group[-1][1]


def format_lines(lines):
    x = [str(x) if x == y else f"{x}-{y}" for x, y in to_ranges(lines)]
    return ", ".join(x)


def set_color(color, text):
    return f"$${{\\color{{{color}}}{text}}}$$"


def format_proportion(actual, required):
    text = f"{actual:.2%}"
    if required == -1:
        return text
    if actual >= required:
        color = "green"
    else:
        color = "goldenrod" if actual >= (required - 0.1) else "crimson"
    return set_color(color, text)


def create_summary(actual_coverage, required_coverage):
    passed = actual_coverage >= required_coverage
    color = "green" if passed else "crimson"
    symbol = ":white_check_mark:" if passed else ":x:"
    text = "PASSED" if passed else "FAILED"
    return (
        f"**Required coverage:** {required_coverage:.2%}"
        + "\n\n"
        + f"**Actual coverage:** {actual_coverage:.2%}"
        + "\n\n"
        + f"**Status:** {set_color(color, text)} {symbol}"
    )


def collect_line_coverage(cobertura_file):
    tree = ET.parse(cobertura_file)
    root = tree.getroot()
    for clazz in root.findall("packages/package/classes/class"):
        for line in clazz.findall("lines/line"):
            yield dict(
                file_name=clazz.attrib["filename"],
                line_number=int(line.attrib["number"]),
                hit_count=int(line.attrib["hits"]),
            )


def create_comment(template_variables):
    result = TEMPLATE
    for k, v in template_variables.items():
        result = result.replace(f"$${k.upper()}$$", v)
    return result


def write_results(output_dir, passed, comment):
    os.makedirs(pathlib.Path(output_dir), exist_ok=True)
    status_file = os.path.join(output_dir, "status.txt")
    with open(status_file, "w") as f:
        f.write("PASSED" if passed else "FAILED")
    comment_file = os.path.join(output_dir, "markdown.md")
    with open(comment_file, "w") as f:
        f.write(comment)


def read_json(file):
    with open(file) as f:
        return json.load(f)


def was_modified(entry, changed_lines):
    file_name = entry["file_name"]
    return (
        file_name in changed_lines and entry["line_number"] in changed_lines[file_name]
    )


def process_file(group):
    total = len(group)
    missed = [x["line_number"] for x in group if x["hit_count"] == 0]
    return total, missed


def add_table_row(parent, values, header=False):
    tr = ET.Element("tr")
    parent.append(tr)
    for value in values:
        e = ET.Element("th" if header else "td")
        tr.append(e)
        e.text = value


def format_row_values(file_name, missed_lines, total_lines, required_coverage):
    num_covered = total_lines - len(missed_lines)
    coverage = num_covered / total_lines
    # TODO: escape file_name
    return (
        file_name,
        format_proportion(coverage, required_coverage),
        f"{format_proportion(coverage, required_coverage)}",
        format_lines(missed_lines),
    )


def create_table(entries, required_coverage):
    table = ET.Element("table")
    add_table_row(table, ["File", "Coverage", "Covered", "Missed Lines"], True)
    entries = sorted(entries, key=lambda e: e["file_name"])
    groups = itertools.groupby(entries, lambda e: e["file_name"])
    for file_name, group in groups:
        group = list(group)
        missed_lines = [x["line_number"] for x in group if x["hit_count"] == 0]
        total_lines = len(group)
        if total_lines != 0:
            add_table_row(
                table,
                format_row_values(
                    file_name, missed_lines, total_lines, required_coverage
                ),
            )
    return ET.tostring(table, encoding="unicode")


def compute_actual_coverage(entries):
    total = len(entries)
    covered = len([x for x in entries if x["hit_count"] != 0])
    return covered / total


def set_table_vars(entries, required_coverage, prefix, template_variables):
    template_variables[prefix + "TABLE"] = create_table(entries, required_coverage)
    actual_coverage = 1.0 if len(entries) == 0 else compute_actual_coverage(entries)
    template_variables[prefix + "SUMMARY"] = create_summary(
        actual_coverage, required_coverage
    )
    return actual_coverage >= required_coverage


def process(
    cobertura_file, changed_lines_file, required_coverage, report_location, output_dir
):
    required_coverage = float(required_coverage)
    entries = list(collect_line_coverage(cobertura_file))
    changed_lines = read_json(changed_lines_file)
    template_variables = dict(REPORT_LOCATION=report_location)
    passed = set_table_vars(entries, required_coverage, "ALL_", template_variables)
    # Remove lines that were not modified
    modified_entries = list(filter(lambda e: was_modified(e, changed_lines), entries))
    passed &= set_table_vars(
        modified_entries, required_coverage, "MOD_", template_variables
    )
    comment = create_comment(template_variables)
    write_results(output_dir, passed, comment)


def main():
    process(*sys.argv[1:])


if __name__ == "__main__":
    main()
