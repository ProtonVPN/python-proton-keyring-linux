#!/usr/bin/env python

from setuptools import setup, find_namespace_packages

setup(
    name="proton-keyring-linux",
    version="0.0.1",
    description="Proton Technologies keyring plugins for linux",
    author="Proton Technologies",
    author_email="contact@protonmail.com",
    url="https://github.com/ProtonMail/python-proton-core",
    install_requires=["proton-core", "keyring"],
    extras_require={
        "development": ["pytest", "pytest-cov"]
    },
    packages=find_namespace_packages(include=['proton.keyring_linux.core']),
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
