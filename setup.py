#!/usr/bin/env python

__author__ = "Andrea Fioraldi"
__copyright__ = "Copyright 2017, Carbonara Project"
__license__ = "BSD 2-clause"
__email__ = "andreafioraldi@gmail.com"

from setuptools import setup

VER = "1.0.1"

setup(
    name='carbonara_r2',
    version=VER,
    license=__license__,
    description='Carbonara Project Radare2 plugin',
    author=__author__,
    author_email=__email__,
    url='https://github.com/Carbonara-Project/Carbonara-R2',
    download_url = 'https://github.com/Carbonara-Project/Carbonara-R2/archive/' + VER + '.tar.gz',
    package_dir={'carbonara_r2': 'carbonara_r2'},
    packages=['carbonara_r2'],
    install_requires=[
        'progressbar2',
        'guanciale'
    ],
    entry_points={
        'console_scripts': [
            'carbonara_r2 = carbonara_r2.main:main',
            'carbr2 = carbonara_r2.main:main'
        ]
    },
)

