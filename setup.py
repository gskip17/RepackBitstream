from __future__ import print_function 
from setuptools import setup
from setuptools import Command

import sys

sys.path.append(".")
if sys.version_info[0] < 3 or sys.version_info[1] < 5: 
    print("------------------------------")
    print("Must use python 3.5 or greater", file=sys.stderr)
    print("Found python version ", sys.version_info, file=sys.stderr)
    print("Installation aborted", file=sys.stderr)
    print("------------------------------")
    sys.exit()

setup(
    name = "bitstream_decryptor", 
    author = "Grant Skipper, Adam Duncan",
    license="http://www.apache.org/licenses/LICENSE-2.0",
    install_requires=[
        "struct",
        "binascii",
        "bitstring",
        "subprocess",
        "pycrypto"
    ], 
)
