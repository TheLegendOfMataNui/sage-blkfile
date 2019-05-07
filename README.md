# SAGE blkfile

Python module and CLI utility for the BLK files use by the SAGE engine.


## Overview

Useful for the BLK files in some SAGE (Saffire Advanced Game Engine) games.

Works with both Python 2 and Python 3.

Games known to use this format:

- BIONICLE: The Legend of Mata Nui


## Usage

```
usage: blkfile.py [-h] [-c | -d] [-l] [-o OUTPUT] paths [paths ...]

SAGE BLK file tool
Version: 2.2.0

positional arguments:
  paths                 Paths to run on

optional arguments:
  -h, --help            show this help message and exit
  -c, --compressed      Force all file data to be compressed (defaults to smaller option)
  -d, --decompressed    Force all file data to be decompressed (defaults to smaller option)
  -l, --list            Just list archived files
  -o OUTPUT, --output OUTPUT
                        Override the default output path

Copyright (c) 2018-2019 JrMasterModelBuilder
Licensed under the Mozilla Public License, v. 2.0

LZSS code based on LZSS.C 4/6/1989 Haruhiko Okumura
```


## Bugs

If you find a bug or have compatibility issues, please open a ticket under issues section for this repository.


## License

Copyright (c) 2018-2019 JrMasterModelBuilder

Licensed under the Mozilla Public License, v. 2.0

LZSS code based on LZSS.C 4/6/1989 Haruhiko Okumura
