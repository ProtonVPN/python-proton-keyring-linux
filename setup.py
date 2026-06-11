#!/usr/bin/env python

from setuptools import setup, find_namespace_packages

setup(
    name="proton-keyring-linux",
    version="0.2.3",
    description="Proton Technologies keyring plugins for linux",
    author="Proton AG",
    author_email="opensource@proton.me",
    url="https://github.com/ProtonVPN/python-proton-keyring-linux",
    install_requires=["proton-core", "keyring"],
    extras_require={
        "development": ["pytest", "pytest-coverage", "pylint", "flake8"]
    },
    packages=find_namespace_packages(include=[
        "proton.keyring_linux.core*", "proton.keyring_linux.secretservice*","proton.keyring_linux.libsecret*"]),
    include_package_data=True,
    entry_points={
        "proton_loader_keyring": [
            "secret_service = proton.keyring_linux.secretservice:KeyringBackendLinuxSecretService",
            "libsecret = proton.keyring_linux.libsecret:LibsecretKeyringBackend" 
        ]
    },
    python_requires=">=3.9",
    license="GPLv3",
    platforms="Linux",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python",
        "Topic :: Security",
    ]
)
