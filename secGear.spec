Name:		secGear
Version:	0.1.0
Release:	13%{?dist}
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
Patch8:		0009-fix-sgxssl-edl.patch
Patch9:		0010-update-docs-build_install.md.patch
Patch10:	0011-modify-the-prompt-information.patch
Patch11:	0012-parse-new-error-code-and-del-redundant-print.patch
Patch12:	0013-fix-error-print.patch
Patch13:	0014-set-umask-in-sign_tool.sh.patch
Patch14:	0015-1.fix-the-race-of-ecall-and-enclave-destroy.patch	
Patch15:	0016-fix-wrong-spelling-and-null-pointer-dereference-issu.patch
Patch16:    0017-update-signtool-codegen.patch

BuildRequires:	gcc python3 automake autoconf libtool
BUildRequires:	glibc glibc-devel
%ifarch x86_64
BUildRequires:	linux-sgx-driver sgxsdk libsgx-launch libsgx-urts
%endif
BUildRequires:	cmake ocaml-dune

Requires:	rsyslog
%ifarch x86_64
Requires:	linux-sgx-driver sgxsdk libsgx-launch libsgx-urts
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
install -d %{buildroot}/%{_datarootdir}/licenses/secGear
install -pm 644 License/Third_Party_Open_Source_Software_Notice.md %{buildroot}/%{_datarootdir}/licenses/secGear
install -d %{buildroot}/%{_includedir}/secGear
#install -pm 644 inc/host_inc/* %{buildroot}/%{_includedir}/secGear/host_inc
%ifarch x86_64
install -d %{buildroot}/%{_bindir}
install -pm 644 inc/host_inc/*.h %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/host_inc/sgx/*.h %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/host_inc/sgx/*.edl %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/enclave_inc/*.h %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/enclave_inc/sgx/*.h %{buildroot}/%{_includedir}/secGear
install -pm 751 bin/codegen %{buildroot}/%{_bindir}
install -pm 751 tools/sign_tool/sign_tool.sh %{buildroot}/%{_bindir}
%else
install -d %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/host_inc/*.h %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/host_inc/gp/*.h %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/enclave_inc/*.h %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/enclave_inc/gp/*.h %{buildroot}/%{_includedir}/secGear
%endif
pushd %{buildroot}
rm `find . -name secgear_helloworld` -rf
rm `find . -name secgear_seal_data` -rf
popd

%files
%license License/LICENSE
%license License/Third_Party_Open_Source_Software_Notice.md
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
%license License/LICENSE
/%{_lib}/libsecgearsim.so
%ifarch x86_64
/%{_lib}/libsgxsim_0.so
%else
#The itrustee OS is not released
%endif

%changelog
* Wed May 12 2021 yanlu<yanlu14@huawei.com> - 0.1.0-13
- DESC: update signtool and codegen

* Thu Apr 27 2021 chenmaodong<chenmaodong@huawei.com> - 0.1.0-12
- DESC: add licenses and thirdparty opensource notice

* Tue Apr 13 2021 wanghongzhe<wanghongzhe@huawei.com> - 0.1.0-11
- DESC: add licenses and thirdparty opensource notice

* Sat Mar 20 2021 zhangguangzhi<zhangguangzhi3@huawei.com> - 0.1.0-10
- DESC: backport patch

* Thu Mar 19 2021 wanghongzhe<wanghongzhe@huawei.com> - 0.1.0-9
- DESC: fix local compile error

* Thu Mar 18 2021 gaoyusong<gaoyusong1@huawei.com> - 0.1.0-8
- DESC: backport patch

* Mon Mar 15 2021 zhangguangzhi<zhangguangzhi3@huawei.com> - 0.1.0-7
- DESC: backport patch

* Wed Mar 10 2021 chenmaodong<chenmaodong@huawei.com> - 0.1.0-6
- DESC: change requires from linux-sgx-sdk to sgxsdk

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
