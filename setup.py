from setuptools import setup, find_packages

setup(
    name='loghawk',
    version='1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'pyfiglet',
        'pandas',
        'colorama',
        'regex'
    ],
    entry_points={
        'console_scripts': [
            'loghawk=loghawk.loghawk_cli:main'
        ],
    },
)
