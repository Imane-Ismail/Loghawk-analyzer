from setuptools import setup, find_packages

setup(
    name='loghawk',
    version='1.4',
    packages=find_packages(),
    install_requires=[
        'pyfiglet',
    ],
    entry_points={
        'console_scripts': [
            'loghawk=loghawk.loghawk_cli:main',
        ],
    },
    author='Imane Ismail',
    description='A lightweight log analysis tool for cyber defenders',
    classifiers=[
        'Programming Language :: Python :: 3',
    ],
)
