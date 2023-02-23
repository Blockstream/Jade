Jade fw release scripts
=======================

NOTE: the directories 'fwsvr_mirror' and 'staging' are work areas and are not
persisted in the git repo.  Release helper scripts are in 'scripts'.
All scripts should be run from 'release' directory.

* scripts/checkfwsvr.sh [ <dest dir> ]
eg. './scripts/checkfwsvr.sh' or './scripts/checkfwsvr.sh fresh_mirror'
- For each hw variant, downloads all index files(*) and all fw files referenced
  by those index files.  (* - new index 'index.json', and legacy index files 'LATEST',
  'BETA', 'PREVIOUS')
- Ensures the fw files listed are present - does not check that they are valid
  or correct - merely that the exist and are downloadable.
- All files are downloaded to given directory or by default to 'fwsvr_mirror'
  (any existing directory is is deleted before the download starts.)
  NOTE: it isn't a true mirror as is based on the index files - if files were
  uploaded to the server but not listed in the index files, this would not pull
  these files.
- Any files listed in the index files but not available for download are displayed
  (and listed in 'missing.log').
  *** These should be fixed asap - otherwise users will start to see errors
  when a fw is advertised but then is not available for download.

  NOTE: this command can be run at any time to check the integrity of the files
  on the fw server.


* scripts/prepver.sh <new version>
eg. './scripts/prepver.sh 0.1.33'
- Ensures 'staging' directory exists.
- Creates per-hw subdirectories under the given versioned directory under
  'staging'.
- Runs 'scripts/checkfwserver.sh' to create an new and up-to-date
  'staging/fwsvr_mirror' directory.
  **NOTE: any existing 'fwsvr_mirror' dir is deleted and the contents lost!
- Creates a copy of that mirror called 'upload' - the work area to to be
  updated and ultimately uploaded.
  **NOTE: any existing 'upload' dir is deleted and the contents lost!


* scripts/devfw.sh <new version>
eg. './scripts/devfw.sh 0.1.33'
- For each dev build dir (ie. jadedev and jade1.1dev, ble and noradio variants),
  signs the dev firmware 'jade.bin' with the dev/test key present in the
  scripts dir.  Validates with the pubkey.  Creates 'jade_signed.bin'.
- Runs 'jade/tools/fwprep.py' on the signed binary 'jade_signed.bin'.  This
  compresses the firmware file and generates the descriptive name using the
  standard/agreed format (<ver>_<cfg>_<decompressed_size>)_fw.bin).  Also writes
  the hash of un-compressed firmware into a file with the same name with a .hash
  postfix.
- Lists the firmware files in (legacy) index file 'BETA'.
- Copies fw files, hash files, and 'BETA' index files to the relevant directories
  under 'staging/upload'.


* scripts/prodfw.sh <new version>
eg. './scripts/prodfw.sh 0.1.33'
- For each prod build dir (ie. jade and jade1.1, ble and noradio variants),
  runs 'jade/tools/fwprep.py' on the signed binary 'jade_signed.bin'.  This
  compresses the firmware file and generates the descriptive name using the
  standard/agreed format (<ver>_<cfg>_<decompressed_size>)_fw.bin).  Also writes
  the hash of un-compressed firmware into a file with the same name with a .hash
  postfix.
- Lists the firmware files in (legacy) index file 'BETA'.
- Copies fw files, hash files,  and 'BETA' index files to the relevant directoriess
  under 'staging/upload'.
- **NOTE: production firmware should be supplied already signed.


* scripts/promotebeta.sh
eg. './scripts/promotebeta.sh'
- For each subdir under 'staging/upload' (ie. jade, jade1.1, jadedev,
  jade1.1dev) concatenates the 'LATEST' and 'PREVIOUS' files into a new
  'PREVIOUS' file.
- Copies 'BETA' to 'LATEST'


* scripts/mkdeltas.sh <target ver> <prior ver> [ <prior ver> ... ]
eg: './scripts/mkdeltas.sh 0.1.33 0.1.32 0.1.31 0.1.30'
- For each subdir (ie. jade, jade1.1, jadedev, jade1.1dev) in 'staging/upload',
  creates deltas between the target firmware and all listed prior firmwares.
- Patches are created between the same ble/noradio configs.
  eg:
    0.1.32-ble -> 0.1.33-ble
    0.1.33-ble -> 0.1.32-ble
    0.1.32-noradio -> 0.1.33-noradio
    0.1.33-noradio -> 0.1.32-noradio
    0.1.31-ble -> 0.1.33-ble
    0.1.33-ble -> 0.1.31-ble
    0.1.31-noradio -> 0.1.31-noradio
    0.1.31-noradio -> 0.1.31-noradio
    ...
- Patches are created between ble and noradio variants for the target version.
  eg:
    0.1.33-noradio -> 0.1.33-ble
    0.1.33-ble -> 0.1.33-noradio
- All patches are created compressed, and with the standard format name
  (<ver>_<cfg>_from_<basever>_<basecfg>_sizes_<uncompressed_fw_size>_<uncompressed_patch_size>_patch.bin)
- Lists the patch files in index file 'DELTAS'.


* scripts/mkindexes.sh <stable version> [ <beta version> ]
eg: './scripts/mkindexes.sh 0.1.33' or './scripts/mkindexes.sh 0.1.32 0.1.33'
- For each subdir (ie. jade, jade1.1, jadedev, jade1.1dev) in 'staging/upload',
  creates 'index.json' for all firmwares and patches in that directory.
- The <stable version> files are listed under the section 'stable'.
- If a <beta version> is given, those files are listed under 'beta', otherwise
  'beta' is null.
- All other versions are listed under 'previous'.
- NOTE: reads the .hash files to populate the 'fwhash' data element, if available.

* scripts/mkhashes.sh <version> [ <version> ... ]
eg: './scripts/mkhashes.sh 0.1.33' or './scripts/mkhashes.sh 0.1.32 0.1.33 0.1.34'
- For each subdir (ie. jade, jade1.1, jadedev, jade1.1dev) in 'staging/upload',
  uncompresses each compressed firmware file into a temporary directory, and then
  runs 'jade/tools/fwprep.py' on the file.  This re-compresses the firmware file
  and writes the hash of ithe un-compressed firmware into a file with the appropriate
  name.  If the newly-compresse file is identical to the original, the hash file is
  copied into the original subdirectory.
- NOTE: Should not be needed in normal operation, as the hash files are produced at
  the same times as the compressed firmware file.
  Needed to generate hash files for older fw files, or to regenerate hash files.
