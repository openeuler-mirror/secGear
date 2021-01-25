Name:		secGear
Version:	1.0
Release:	1%{?dist}
Summary:	secGear is an SDK to develop confidential computing apps based on hardware enclave features

Group:		OS Securitt
License:	MulanPSL2
URL:		https://gitee.com/openeuler-src/secGear
Source0:	%{name}-%{version}.tar.gz

BuildRequires:	gcc python3 automake autoconf libtool gcc-g++ 
BUildRequires:	glibc glibc-devel
%ifarch x86_64
BUildRequires:	linux-sgx-driver linux-sgx-sdk libsgx-launch libsgx-urts
%endif
BUildRequires:	cmake ocaml-dune

Requires:	rsyslog
%ifarch x86_64
Requires:	linux-sgx-driver linux-sgx-sdk libsgx-launch libsgx-urts
%endif
%description
secGear is an SDK to develop confidential computing apps based on hardware enclave features

%package	devel
Summary:	Development files for %{name}
Requires:	%{name}%{?isa} = %{version}-%{release}
%description	devel
The %{name}-devel is package contains Header file for developing applications that 
us %{name}

%prep
%setup -q


%build
source ./environment
%ifarch x86_64
source /opt/intel/sgxsdk/environment
cmake -DCMAKE_BUILD_TYPE=Debug -DCC_SGX=on -DSGXSDK=/opt/intel/sgxsdk
make 
%else
#The itrustee OS is not released 
%endif


%install
make install DESTDIR=%{buildroot}
install -d %{buildroot}/%{_includedir}/secGear
install -d %{buildroot}/%{_includedir}/secGear/host_inc
install -d %{buildroot}/%{_includedir}/secGear/enclave_inc
#install -pm 644 inc/host_inc/* %{buildroot}/%{_includedir}/secGear/host_inc
%ifarch x86_64
install -d %{buildroot}/%{_includedir}/secGear/host_inc/sgx
install -d %{buildroot}/%{_includedir}/secGear/enclave_inc/sgx
install -pm 644 inc/host_inc/*.h %{buildroot}/%{_includedir}/secGear/host_inc
install -pm 644 inc/host_inc/sgx/*.h %{buildroot}/%{_includedir}/secGear/host_inc/sgx
install -pm 644 inc/enclave_inc/*.h %{buildroot}/%{_includedir}/secGear/enclave_inc
install -pm 644 inc/enclave_inc/sgx/*.h %{buildroot}/%{_includedir}/secGear/enclave_inc/sgx
%else
install -d %{buildroot}/%{_includedir}/secGear/host_inc/gp
install -d %{buildroot}/%{_includedir}/secGear/enclave_inc/gp
install -pm 644 inc/host_inc/*.h %{buildroot}/%{_includedir}/secGear/host_inc
install -pm 644 inc/host_inc/gp/*.h %{buildroot}/%{_includedir}/secGear/host_inc/gp
install -pm 644 inc/enclave_inc/*.h %{buildroot}/%{_includedir}/secGear/enclave_inc
install -pm 644 inc/enclave_inc/gp/*.h %{buildroot}/%{_includedir}/secGear/enclave_inc/gp
%endif


%files
%defattr(-,root,root)
%{_libdir}/libsecgear_tee.a
%{_libdir}/libsecgear.so
%ifarch x86_64
%{_libdir}/libsgx_0.so
%else
#The itrustee OS is not released
%endif
%config(noreplace) %attr(0600,root,root) %{_sysconfdir}/rsyslog.d/secgear.conf
%config(noreplace) %attr(0600,root,root) %{_sysconfdir}/logrotate.d/secgear
%files devel
%{_includedir}/secGear/*

%changelog
* Mon Jan 11 2021 wanghongzhe<wanghongzhe@huawei.com> - 1.0-1
- DESC:init secgear
