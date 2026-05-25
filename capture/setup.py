import os
import sys
import urllib.request
import zipfile
from setuptools import setup, Extension
import pybind11

sdk_dir = os.path.abspath("npcap-sdk")
zip_path = "npcap-sdk.zip"

if not os.path.exists(sdk_dir):
    print("Downloading Npcap SDK...")
    try:
        req = urllib.request.Request(
            "https://npcap.com/dist/npcap-sdk-1.13.zip",
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        with urllib.request.urlopen(req) as response, open(zip_path, 'wb') as out_file:
            out_file.write(response.read())
        print("Extracting SDK...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(sdk_dir)
        os.remove(zip_path)
    except Exception as e:
        print(f"Failed to download Npcap SDK: {e}")
        sys.exit(1)

include_dirs = [
    pybind11.get_include(),
    os.path.join(sdk_dir, "Include")
]

# Use x64 libs
library_dirs = [
    os.path.join(sdk_dir, "Lib", "x64")
]

ext_modules = [
    Extension(
        "wolfcap",
        ["wolfcap.cpp"],
        include_dirs=include_dirs,
        library_dirs=library_dirs,
        libraries=["wpcap", "Packet"],
        language="c++",
        extra_compile_args=["/std:c++17", "/DWIN32", "/DHAVE_REMOTE"],
    ),
]

setup(
    name="wolfcap",
    ext_modules=ext_modules,
)
