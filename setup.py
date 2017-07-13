# -*- coding: utf-8 -*-
"""
Setup for PyPI.
"""
from os import path
from setuptools import setup

HERE = path.abspath(path.dirname(__file__))
with open(path.join(HERE, 'README.md'), 'r') as fil:
    LONG_DESC = fil.read()

setup(
    name='packerinspector-api',
    version='1.0.0',
    description='Deep Packer Inspector API',
    long_description=LONG_DESC,
    url='https://github.com/7flying/packerinspector-api',
    author='Deep Packer Inspector team',
    author_email='packerinspector@deusto.es',
    license='GPLv3',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: Science/Research',
        'Natural Language :: English',
        'Topic :: Security',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
    ],
    keywords='malware packers packerinspector deep packer inspector',
    packages=['packerinspector'],
    install_requires=['requests >= 2.18.1'],
    zip_safe=False)
