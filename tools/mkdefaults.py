#!/usr/bin/env python

import itertools
import json
import os
import subprocess
import sys

# Our files in this directory
TOOLPATH = os.path.dirname(os.path.abspath(__file__))
DATAFILE = os.path.join(TOOLPATH, 'mkdefaults.dat.json')
TEMPFILE = './sdkconfig.defaults.tmp'

# Load config updates
with open(DATAFILE, 'r') as json_file:
    CFG_UPDATES = json.load(json_file)

# Sanity check params
if len(sys.argv) < 3:
    known_directives = [d for d in CFG_UPDATES.keys()]
    known_directives = str(known_directives).replace(',', ' |').replace('\'', '')
    print(f'Usage: {sys.argv[0]} <base configfile> {known_directives} ...')
    sys.exit(-1)

inputfilename = sys.argv[1]
directives = sys.argv[2:]

if any(d not in CFG_UPDATES for d in directives):
    print(f'Unknown directive: {[d for d in directives if d not in CFG_UPDATES]}')
    print(f'Known directives: {[d for d in CFG_UPDATES.keys()]}')
    sys.exit(-2)

# Collapse lists of updates into one, if multiple keys given on cmdline
updates = [CFG_UPDATES[d] for d in directives]
updates = [itertools.chain.from_iterable(u) for u in zip(*updates)]
assert len(updates) == 2  # [ <what to add>, <what to remove> ]
toadd, toremove = list(updates[0]), set(updates[1])

# Sanity check no conflicts in configs to add and remove
assert len(toremove.intersection(toadd)) == 0, f'Conflict list: {toremove.intersection(toadd)}'

# Process inputfile, write temporary file
with open(inputfilename, 'r') as infile, open(TEMPFILE, 'w') as outfile:
    # Write the new flags
    outfile.writelines(cfg + os.linesep for cfg in toadd)

    # Copy the input file, filtering as necessary
    outfile.writelines(cfg for cfg in infile if cfg.strip() not in toremove)

# Backup/remove existing sdkconfig files
if os.path.isfile('./sdkconfig.defaults'):
    os.rename('./sdkconfig.defaults', './sdkconfig.defaults.orig')
if os.path.isfile('./sdkconfig'):
    os.remove('./sdkconfig')

# Process tempfile with 'idf.py reconfigure write-defconfig' to create new sdkconfig.defaults
subprocess.check_call(f'idf.py -D SDKCONFIG_DEFAULTS="{TEMPFILE}" reconfigure save-defconfig',
                      shell=True)

# Remove tempfile
os.remove(TEMPFILE)
