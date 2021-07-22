# -*- encoding: utf-8 -*-
"""
Copyright (c) 2021 - present Orange Cyberdefense
"""

from hashlib import sha256
from zipfile import ZipFile, is_zipfile

def sha256sum(file_path):
    sha256_hash = sha256()
    with open(file_path, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

        from zipfile import ZipFile, is_zipfile

def check_zipfile(zip_path):
    error = False
    msg = ""
    if not is_zipfile(zip_path):
        error = True
        msg = "invalid zip file"
    else:
        for zinfo in ZipFile(zip_path, "r").infolist():
            if zinfo.flag_bits & 0x1:
                error = True
                msg = "encrypted zip file"
                break
    return error, msg