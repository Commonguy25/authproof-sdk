from setuptools import setup, find_packages

setup(
    name="authproof-py",
    version="1.6.0",
    packages=find_packages(),
    install_requires=[
        "cryptography>=41.0.0",
        "aiohttp>=3.9.0",
    ],
    python_requires=">=3.9",
    author="Ryan Nelson",
    description="Python SDK for AuthProof cryptographic delegation receipts",
    url="https://github.com/Commonguy25/authproof-sdk",
)
