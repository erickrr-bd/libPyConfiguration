from pathlib import Path
from setuptools import find_packages, setup

HERE = Path(__file__).parent

VERSION = '1.3.0'
PACKAGE_NAME = 'libPyConfiguration' 
AUTHOR = 'Erick Roberto Rodríguez Rodriguez'
AUTHOR_EMAIL = 'erickrr.tbd93@gmail.com, erodriguez@tekium.mx' 
URL = 'https://github.com/erickrr-bd/libPyConfiguration' 

LICENSE = 'GPLv3' 
DESCRIPTION = "Dynamic, memory-secure configuration management engine written in Python." 
LONG_DESCRIPTION = (HERE / "README.md").read_text(encoding ='utf-8')
LONG_DESC_TYPE = "text/markdown"

setup(
    name = PACKAGE_NAME,
    version = VERSION,
    description = DESCRIPTION,
    long_description = LONG_DESCRIPTION,
    long_description_content_type = LONG_DESC_TYPE,
    author = AUTHOR,
    author_email = AUTHOR_EMAIL,
    url = URL,
    license = LICENSE,
    packages = find_packages(),
    include_package_data = True
)