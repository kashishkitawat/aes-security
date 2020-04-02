"""Setup file for package."""

from setuptools import setup

with open('README.md') as f:
    readme = f.read()

setup(
    name='aes-security',
    py_module=['aes-security'],
    package_data=['bin', 'data'],
    description='AES Security for IoT devices',
    long_description=readme,
    python_requires='>=3.5',
    install_requires=[
        'getpass',
        'pathlib',
        'pycrypto',
        'pandas'
    ]
)
