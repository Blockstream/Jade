#!/usr/bin/env python3

import json
import sys
from collections import defaultdict

def parse_gcovr_json(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)

    line_counts = defaultdict(int)

    for file_data in data['files']:
        file_name = file_data['file']
        for line in file_data['lines']:
            if not line.get('gcovr/noncode', False):
                line_number = line['line_number']
                execution_count = line['count']
                line_counts[(file_name, line_number)] += execution_count

    return line_counts

def main(file_path):
    line_counts = parse_gcovr_json(file_path)
    sorted_lines = sorted(line_counts.items(), key=lambda item: item[1], reverse=True)

    for (file_name, line_number), count in sorted_lines:
        print(f'{file_name} Line {line_number}: {count}')

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: python script.py <coverage_json_file>')
        sys.exit(1)

    file_path = sys.argv[1]
    main(file_path)
