Name:		secGear
Version:	0.1.0
Release:	4%{?dist}
Summary:	secGear is an SDK to develop confidential computing apps based on hardware enclave features
ExclusiveArch:	x86_64

Group:		OS Security
License:	Mulan PSL v2
URL:		https://gitee.com/openeuler/secGear
Source0:	https://gitee.com/openeuler/secGear/repository/archive/v%{version}.tar.gz

BuildRequires:	gcc python3 automake autoconf libtool
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

%package        sim
Summary:        simulation package files for %{name}
Requires:       %{name}%{?isa} = %{version}-%{release}
%description    sim
The %{name}-sim is package contains simulation libraries for developing applications

%prep
%setup -q -n secGear


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

rm %{buildroot}/home* -rf

%files
%defattr(-,root,root)
/%{_lib}/libsecgear_tee.a
/%{_lib}/libsecgear.so
%ifarch x86_64
/%{_lib}/libsgx_0.so
%else
#The itrustee OS is not released
%endif
%config(noreplace) %attr(0600,root,root) %{_sysconfdir}/rsyslog.d/secgear.conf
%config(noreplace) %attr(0600,root,root) %{_sysconfdir}/logrotate.d/secgear
%files devel
%{_includedir}/secGear/*

%files sim
%defattr(-,root,root)
/%{_lib}/libsecgearsim.so
%ifarch x86_64
/%{_lib}/libsgxsim_0.so
%else
#The itrustee OS is not released
%endif

%changelog
* Mon Feb 22 2021 chenmaodong<chenmaodong@huawei.com> - 0.1.0-4
- DESC:delete unnecessary BuildRequires

* Sat Feb 20 2021 chenmaodong<chenmaodong@huawei.com> - 0.1.0-3
- DESC:fix url and source0 description error

* Sun Feb 7 2021 chenmaodong<chenmaodong@huawei.com> - 0.1.0-2
- DESC:fix secGear build error and add secGear-sim rpm package

* Wed Feb 3 2021 wanghongzhe<wanghongzhe@huawei.com> - 0.1.0-1
- DESC:init secGear.tar.gz

* Mon Jan 11 2021 wanghongzhe<wanghongzhe@huawei.com> - 1.0-1
- DESC:init secgear
