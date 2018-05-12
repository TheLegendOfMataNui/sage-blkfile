# SAGE blkfile

Python module and CLI utility for the BLK files use by the SAGE engine.


## Overview

Useful for the BLK files in some SAGE (Saffire Advanced Game Engine) games.

Works with both Python 2 and Python 3.

Games known to use this format:

- BIONICLE: The Legend of Mata Nui

NOTE: New archives are currently created without compression.


## Usage

```
usage: blkfile.py [-h] [-l] paths [paths ...]

SAGE BLK file tool
Version: 1.0.0

positional arguments:
  paths       Paths to run on

optional arguments:
  -h, --help  show this help message and exit
  -l, --list  Just list archived files

Copyright (c) 2018 JrMasterModelBuilder
Licensed under the Mozilla Public License, v. 2.0

LZSS code based on LZSS.C 4/6/1989 Haruhiko Okumura
```


## Bugs

If you find a bug or have compatibility issues, please open a ticket under issues section for this repository.


## License

Copyright (c) 2018 JrMasterModelBuilder

Licensed under the Mozilla Public License, v. 2.0

LZSS code based on LZSS.C 4/6/1989 Haruhiko Okumura
