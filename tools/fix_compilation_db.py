#!/usr/bin/env python3
"""Prepare the compilation database for GitLab Advanced SAST CPP."""

import json
import os
from pathlib import Path


def main():
    project_dir = os.environ['CI_PROJECT_DIR'].rstrip('/')
    build_src = '/builds/blockstream/jade/build/'
    build_dst = f'{project_dir}/build_sast_jade/'

    # Remove /opt/ files and rebase remaining
    content = Path('build_sast_jade/compile_commands.json').read_text()
    entries = [
        entry for entry in json.loads(content)
        if '/opt/' not in entry.get('file', '')
    ]
    content = json.dumps(entries)
    content = content.replace(
        f'"directory": "{build_src[:-1]}"',
        f'"directory": "{build_dst[:-1]}"',
    ).replace(build_src, build_dst).replace('/opt/', f'{build_dst}opt/')

    # Remove flags unsupported by SAST
    for flag in (
        '-mlongcalls',
        '-mdisable-hardware-atomics',
        '-fstrict-volatile-bitfields',
        '-fno-tree-switch-conversion',
        '-freorder-blocks',
        '@',
    ):
        content = content.replace(flag, '')

    # Remove files from external directories
    entries = [
        entry for entry in json.loads(content)
        if not any(directory in entry.get('file', '') for directory in (
            'bootloader_components/',
            'managed_components/',
        ))
    ]

    # Create the new compilation database
    Path(os.environ['SAST_COMPILATION_DATABASE']).write_text(
        json.dumps(entries, indent=2) + '\n'
    )


if __name__ == '__main__':
    main()
