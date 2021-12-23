#!/usr/bin/env python

from setuptools import setup, find_namespace_packages

setup(
    name="proton-keyring-linux",
    version="0.0.0",
    description="Proton Technologies keyring plugins for linux",
    author="Proton Technologies",
    author_email="contact@protonmail.com",
    url="https://github.com/ProtonMail/python-proton-core",
    install_requires=["proton-core", "keyring"],
    entry_points={
        "proton_loader_keyring": [
            "kwallet = proton.keyring_linux:KeyringBackendLinuxKwallet",
            "secret_service = proton.keyring_linux:KeyringBackendLinuxSecretService"
        ]
    },
    packages=find_namespace_packages(include=['proton.*']),
    include_package_data=True,
    license="GPLv3",
    platforms="OS Independent",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python",
        "Topic :: Security",
    ]
)
