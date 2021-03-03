Name:		secGear
Version:	0.1.0
Release:	5%{?dist}
Summary:	secGear is an SDK to develop confidential computing apps based on hardware enclave features
ExclusiveArch:	x86_64

Group:		OS Security
License:	Mulan PSL v2
URL:		https://gitee.com/openeuler/secGear
Source0:	https://gitee.com/openeuler/secGear/repository/archive/v%{version}.tar.gz

Patch0:		0001-add-README.cn.md.patch
Patch1:		0002-it-is-better-to-define-enum-from-0-rather-than-1.patch
Patch2:		0003-update-README.cn.md.patch
Patch3:		0004-update-README.cn.md.patch
Patch4:		0005-delete-unnecessary-README.cn.md.patch
Patch5:		0006-fix-issues-about-double-create-destory.patch
Patch6:		0007-to-make-secGear-log-more-clear.patch
Patch7:		0008-modify-path-error.patch

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
%autosetup -n %{name} -p1


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
#install -pm 644 inc/host_inc/* %{buildroot}/%{_includedir}/secGear/host_inc
%ifarch x86_64
install -d %{buildroot}/%{_bindir}
install -pm 644 inc/host_inc/*.h %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/host_inc/sgx/*.h %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/host_inc/sgx/*.edl %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/enclave_inc/*.h %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/enclave_inc/sgx/*.h %{buildroot}/%{_includedir}/secGear
install -pm 751 bin/codegen_x86_64 %{buildroot}/%{_bindir}
install -pm 751 tools/sign_tool/sign_tool.sh %{buildroot}/%{_bindir}
%else
install -d %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/host_inc/*.h %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/host_inc/gp/*.h %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/enclave_inc/*.h %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/enclave_inc/gp/*.h %{buildroot}/%{_includedir}/secGear
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
%{_bindir}/*
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
* Wed Mar 3 2021 zhangguangzhi<zhangguangzhi@huawei.com> - 0.1.0-5
- DESC: add codegen and sign_tool, modify file path and backport patch

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
