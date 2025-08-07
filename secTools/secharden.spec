%global python3_pkgversion 3.11

Summary: Security Hardening Toolkit
Name   : secharden
Version: 1.0
Release: 1.0
Source0: secharden
Source1: conf
License: Mulan PSL v2
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: python3 python3-pyyaml python3-jsonschema coreutils setools-console libselinux dim dim_tools

BuildArch: noarch
BuildRequires: python3-setuptools pyproject-rpm-macros python3-pytest python3-pytest-mock python3-wheel

%description
Security Hardening Toolkit, a set of tools to help secure and harden systems.

%global debug_package %{nil}

%prep
%__rm -rf %{_builddir}/*

%build
%__cp -r %{SOURCE0}/* %_builddir
%pyproject_build

%check
%global __pytest_addopts --ignore=tests/cmd/test_gendoc.py
%{pytest}

%install
%pyproject_install
# install config files
%{__install} -d -m0755 $RPM_BUILD_ROOT%{_sysconfdir}/secharden
%{__install} -m0644 %{SOURCE1}/secharden.conf $RPM_BUILD_ROOT%{_sysconfdir}/secharden/secharden.conf
%{__install} -d -m0755 $RPM_BUILD_ROOT%{_sysconfdir}/secharden/secharden.conf.d

%clean
%__rm -rf $RPM_BUILD_ROOT
%__rm -rf %{_builddir}/*

%pre

%post

%preun

%postun

%files -n secharden
%defattr(-,root,root)
%attr(0644,root,root) %config %{_sysconfdir}/secharden/secharden.conf
%attr(0644,root,root) %doc README.md
%attr(0755,root,root) %{_bindir}/secharden
%{python3_sitelib}/secharden/
%{python3_sitelib}/secharden-*.dist-info/

%changelog
* Fri Jul 25 2025 Tomahawkd <tomahawkd00@outlook.com> - 1.0-1.0
- inital Security Hardening Toolkit