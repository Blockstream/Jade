#!/usr/bin/env python

import sys
import glob
import json
import logging
import os

import fwtools

# Enable logging
logger = logging.getLogger('jade')
logger.setLevel(logging.INFO)

INDEX_FILENAME = 'index.json'
PATTERN_FW = '**/*.bin'


def process_fw_filename(fwname):
    fwtype, info, info2 = fwtools.parse_compressed_filename(fwname)
    assert info is not None
    desc = {'filename': fwname,
            'version': info.version,
            'config': info.config,
            'fwsize': info.fwsize}

    if fwtype == fwtools.FWFILE_TYPE_FULL:
        assert info2 is None
    elif fwtype == fwtools.FWFILE_TYPE_PATCH:
        assert info2 is not None
        desc['from_version'] = info2.version
        desc['from_config'] = info2.config
        desc['patch_size'] = info2.fwsize

    return desc


def is_delta(desc):
    return desc.get('patch_size') is not None


def process_current_directory(vstable, vbeta):
    def _new_release_dict():
        return {'full': [], 'delta': []}

    def _sort_release_dict(rd):
        def _sortkey(rec):
            return rec['version'] + "_" + rec['config'] + '_' + \
                rec.get('from_version', '') + '_' + rec.get('from_config', '')
        return {k: sorted(v, key=_sortkey, reverse=True) for k, v in rd.items()}

    previous = _new_release_dict()
    stable = _new_release_dict()
    beta = _new_release_dict() if vbeta else {}

    # Add description dict to the 'full' or 'delta' list under the relevant
    # release label (beta, stable, previous)
    def _add_to_release(desc):
        subkey = 'delta' if is_delta(desc) else 'full'
        if vbeta and desc['version'] == vbeta:
            beta[subkey].append(desc)
        elif desc['version'] == vstable:
            stable[subkey].append(desc)
        else:
            previous[subkey].append(desc)

    # Iterate through firmware files, collating the summary info about each one
    # in dictionaries for each release label (beta, stable, previous)
    for fwname in glob.iglob(PATTERN_FW, recursive=True):
        try:
            desc = process_fw_filename(fwname)
            _add_to_release(desc)
        except Exception as e:
            logger.error(f'Skipping "{fwname}":- {e}')

    return {'beta': _sort_release_dict(beta),
            'stable': _sort_release_dict(stable),
            'previous': _sort_release_dict(previous)}


# Can be run as a utility
if __name__ == '__main__':
    jadehandler = logging.StreamHandler()
    logger.addHandler(jadehandler)

    assert len(sys.argv) in [3, 4], f'Usage: {sys.argv[0]} <directory> <ver_stable> [ <ver_beta> ]'
    dir, vstable, vbeta = sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None
    assert os.path.exists(dir) and os.path.isdir(dir), f'Directory {dir} not found.'

    # Gather the metadata for the existing base directory including delta patches.
    # Change to given directory, so all file paths are generated relative to this root
    os.chdir(dir)
    data = process_current_directory(vstable, vbeta)

    # Write as index file (just filename, now we have chdir()'d)
    # NOTE: this will be 'newdir' if one was passed, otherwise 'basedir'
    with open(INDEX_FILENAME, 'w') as f:
        json.dump(data, f, indent=2)

    logger.info('Done')
