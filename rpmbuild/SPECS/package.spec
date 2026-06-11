%define unmangled_name proton-keyring-linux
%define pep_625_name proton_keyring_linux
%define version 0.2.3
%define release 1

Prefix: %{_prefix}

Name: python3-%{unmangled_name}
Version: %{version}
Release: %{release}%{?dist}
Summary: %{unmangled_name} library

Group: ProtonVPN
License: GPLv3
Vendor: Proton AG <opensource@proton.me>
URL: https://github.com/ProtonVPN/python-%{unmangled_name}
Source0: %{pep_625_name}-%{version}.tar.gz
BuildArch: noarch
BuildRoot: %{_tmppath}/%{pep_625_name}-%{version}-%{release}-buildroot

BuildRequires: python3-devel
BuildRequires: python3-setuptools
BuildRequires: gnome-keyring
BuildRequires: python3-keyring
BuildRequires: python3-secretstorage 
BuildRequires: python3-proton-core

Requires: gnome-keyring
Requires: python3-keyring
Requires: python3-secretstorage 
Requires: python3-proton-core

Conflicts: python3-proton-keyring-linux-secretservice < 0.1.0
Obsoletes: python3-proton-keyring-linux-secretservice

%{?python_disable_dependency_generator}

%description
Package %{unmangled_name} library.

%prep
%setup -q -n %{pep_625_name}-%{version}

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files proton 

%check
%pyproject_check_import

%files -n %{name} -f %{pyproject_files}

%changelog
* Mon Jun 11 2026 Elena Švilpė <elena.svilpe@proton.ch> 0.2.3
- Restrict libsecret backend to Snap only.

* Mon Jun 1 2026 Elena Švilpė <elena.svilpe@proton.ch> 0.2.2
- Add libsecret backend.

* Mon Sep 22 2025 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.2.1
- Update spec file.

* Tue Nov 19 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.2.0
- Drop Ubuntu 20.04 support.

* Tue Sep 24 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.1.0
- Merge proton-keyring-linux-secret-service into this one.

* Wed Mar 20 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.0.2
- Update class property

* Tue Jun 28 2022 Proton Technologies AG <opensource@proton.me> 0.0.1
- First RPM release
