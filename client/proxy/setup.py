from setuptools import setup, find_packages

setup(
    name="krb-client",
    version="1.0",
    packages=find_packages(),
    install_requires=[
        "fastapi>=0.100.0",
        "uvicorn>=0.23.2",
        "websockets>=11.0.3"
    ],
    entry_points={
        "console_scripts": [
            "krb-client=client.proxy.main:main"
        ]
    }
)