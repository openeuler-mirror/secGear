Name:		secGear
Version:	0.1.0
Release:	35
Summary:	secGear is an SDK to develop confidential computing apps based on hardware enclave features


Group:		OS Security
License:	MulanPSL-2.0
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
Patch8:		0009-fix-cmake-error-of-missing-CMAKE_CXX_COMPILER.patch
Patch9:		0010-fix-sgxssl-edl.patch
Patch10:	0011-update-docs-build_install.md.patch
Patch11:	0012-modify-the-prompt-information.patch
Patch12:	0013-parse-new-error-code-and-del-redundant-print.patch
Patch13:	0014-fix-error-print.patch
Patch14:	0015-set-umask-in-sign_tool.sh.patch
Patch15:	0016-1.fix-the-race-of-ecall-and-enclave-destroy.patch
Patch16:	0017-fix-wrong-spelling-and-null-pointer-dereference-issu.patch
Patch17:	0018-update-sign_tool.doc.patch
Patch18:	0019-normalized-codegen-from-arm-and-x86.patch
Patch19:	0020-rm-e-parameter-normalize-c-parameter.patch
Patch20:	0021-example-use-absolute-path-to-find-enclave.sign.so.patch
Patch21:	0022-add-example-of-using-sgxssl-lib.patch
Patch22:	0023-tls_enclave-is-not-compiled-by-default.patch
Patch23:	0024-Cmake-replace-minial-cmake-from-3.12-to-3.10.patch
Patch24:	0025-example-add-example-for-LRT-long-running-task.patch
Patch25:	0026-example-add-Dockerfile-to-build-lrt-example-image.patch
Patch26:	0027-Change-to-use-the-milestone-picture-with-English.patch
Patch27:	0028-example-use-the-sgx-device-plugin-from-intel.patch
Patch28:	0029-some-adaptations-for-trustzone.patch
Patch29:	0030-fix-sgx-two-step-mode-bug-add-dump-command.patch
Patch30:	0031-set-signtool_v3.py-path.patch
Patch31:	0032-del-size_to_aligned_size.patch
Patch32:	0033-modify-the-error-information-when-missing-c-and-m.patch
Patch33:	0034-normalize-the-log-printed-by-PrintInfo.patch
Patch34:	0035-itrustee-add-lrt-support-itrustee.patch
Patch35:	0036-enclave-use-the-can-pull-image-from-hub.oepkgs.net.patch
Patch36:	0037-add-description-about-file-parameter-path-for-sign_t.patch
Patch37:	0038-fix-use-after-free-in-cc_enclave_create.patch
Patch38:	0039-clean-memory-when-it-come-to-error_handle.patch
Patch39:	0040-fix-double-free.patch
Patch40:	0041-fix-logs-redirection-error-and-delete-rsa_public_key.patch
Patch41:	0042-destroy-rwlock-when-create-enclave-failed.patch
Patch42:	0043-fix-partial-resource-leak.patch
Patch43:	0044-fix-pointer-without-init-or-check-NULL.patch
Patch44:	0045-optimize-the-private-key-usage-of-the-single-step-si.patch
Patch45:	0046-fix-return-value.patch
Patch46:        0047-del-print-uncontrol-form-string.patch
Patch47:        0048-Delete-the-null-determination-of-out_buf-in-codegene.patch
Patch48:        0049-support-switchless-feature.patch
Patch49:        0050-switchless-schedule-policy.patch
Patch50:        0051-asynchronous-switchless.patch
Patch51:        0052-rollback-to-common-invoking-when-async-invoking-fail.patch
Patch52:        0053-asynchronous-switchless-example.patch
Patch53:        0054-fix-gen-ecall-header-error.patch
Patch54:        0055-switchless-readme-add-async-interface.patch
Patch55:        0056-destroy-enclave-release-remain-shared-memory.patch

BuildRequires:	gcc python automake autoconf libtool
BUildRequires:	glibc glibc-devel cmake ocaml-dune rpm gcc-c++
%ifarch x86_64
BUildRequires:	sgxsdk libsgx-launch libsgx-urts openssl
%else
BUildRequires:	itrustee_sdk itrustee_sdk-devel
%endif

Requires:		rsyslog
%ifarch x86_64
Requires:		linux-sgx-driver sgxsdk libsgx-launch libsgx-urts libsgx-aesm-launch-plugin
%else
Requires:		itrustee_sdk
%endif

%description
secGear is an SDK to develop confidential computing apps based on hardware enclave features

%package		devel
Summary:		Development files for %{name}
Requires:		%{name}%{?isa} = %{version}-%{release} cmake
%ifarch x86_64
Requires:		sgxsdk
%else
Requires:		itrustee_sdk-devel
%endif
%description	devel
The %{name}-devel is package contains Header file for developing applications that
us %{name}

%ifarch x86_64
%package		sim
Summary:		simulation package files for %{name}
Requires:		%{name}%{?isa} = %{version}-%{release}
%description	sim
The %{name}-sim is package contains simulation libraries for developing applications
%endif

%prep
%autosetup -n %{name} -p1

%build
source ./environment
%ifarch x86_64
source /opt/intel/sgxsdk/environment
cmake -DCMAKE_BUILD_TYPE=Debug
make
%else
cmake -DCMAKE_BUILD_TYPE=Debug -DENCLAVE=GP
make
%endif

%install
make install DESTDIR=%{buildroot}
install -d %{buildroot}/%{_datarootdir}/licenses/secGear
install -pm 644 License/Third_Party_Open_Source_Software_Notice.md %{buildroot}/%{_datarootdir}/licenses/secGear
install -d %{buildroot}/%{_includedir}/secGear
install -d %{buildroot}/%{_bindir}
install -pm 751 bin/codegen %{buildroot}/%{_bindir}
install -pm 751 tools/sign_tool/sign_tool.sh %{buildroot}/%{_bindir}
install -d %{buildroot}/lib/secGear/
install -pm 751 tools/sign_tool/*.py %{buildroot}/lib/secGear
%ifarch x86_64
install -pm 644 inc/host_inc/*.h %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/host_inc/sgx/*.h %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/host_inc/sgx/*.edl %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/enclave_inc/*.h %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/enclave_inc/sgx/*.h %{buildroot}/%{_includedir}/secGear
%else
install -d %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/host_inc/*.h %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/host_inc/gp/*.h %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/host_inc/gp/*.edl %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/enclave_inc/*.h %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/enclave_inc/gp/*.h %{buildroot}/%{_includedir}/secGear
install -pm 644 inc/enclave_inc/gp/itrustee/*.h %{buildroot}/%{_includedir}/secGear
%endif
pushd %{buildroot}
rm `find . -name secgear_helloworld` -rf
rm `find . -name secgear_seal_data` -rf
rm `find . -name secgear_switchless` -rf
%ifarch aarch64
rm `find . -name libsecgearsim.so` -rf
%endif
popd

%files
%license License/LICENSE
%license License/Third_Party_Open_Source_Software_Notice.md
%defattr(-,root,root)
%{_libdir}/libsecgear_tee.a
%{_libdir}/libsecgear.so
%ifarch x86_64
%{_libdir}/libsgx_0.so
%else
%{_libdir}/libgp_0.so
%endif
%config(noreplace) %attr(0600,root,root) %{_sysconfdir}/rsyslog.d/secgear.conf
%config(noreplace) %attr(0600,root,root) %{_sysconfdir}/logrotate.d/secgear

%files devel
%{_bindir}/*
%{_includedir}/secGear/*
/lib/secGear/*

%ifarch x86_64
%files sim
%defattr(-,root,root)
%license License/LICENSE
%{_libdir}/libsecgearsim.so
%{_libdir}/libsgxsim_0.so
%endif

%post
systemctl restart rsyslog

%changelog
* Tue Dec 20 2022 houmingyong<houmingyong@huawei.com> - 0.1.0-35
- fix aysnchronous ecall bug

* Tue Dec 20 2022 houmingyong<houmingyong@huawei.com> - 0.1.0-34
- add asynchronous switchless example

* Sat Dec 17 2022 houmingyong<houmingyong@huawei.com> - 0.1.0-33
- switchless support asynchronous ecall

* Tue Nov 22 2022 houmingyong<houmingyong@huawei.com> - 0.1.0-32
- switchless support configure schedule policy

* Sat Nov 12 2022 zhengxiaoxiao <zhengxiaoxiao2@huawei.com> - 0.1.0-31
- add "Delete-the-null-determination-of-out_buf_in_codegene.patch" and "support-switchless-feature.patch" 

* Wed Aug 03 2022 fushanqing <fushanqing@kylinos.cn> - 0.1.0-30
- Unified license name specification

* Wed Aug 3 2022 zhengxiaoxiao <zhengxiaoxiao2@huawei.com> - 0.1.0-29
* DESC: override with 22.03

* Mon Jun 6 2022 zhengxiaoxiao <zhengxiaoxiao2@huawei.com> - 0.1.0-28
* DESC: del print uncontrol form string

* Sun May 15 2022 zhengxiaoxiao <zhengxiaoxiao2@huawei.com> - 0.1.0-27
* DESC: fix return value

* Thu Mar 24 2022 baizhonggui <baizhonggui@huawei.com> - 0.1.0-26
* DESC: delete %{dist}

* Tue Mar 15 2022 wangcheng <wangcheng156@huawei.com> - 0.1.0-25
* DESC: fix the building failure in arm

* Thu Mar 10 2022 wangcheng <wangcheng156@huawei.com> - 0.1.0-24
* DESC: fix some bugs

* Fri Mar 4 2022 gaoyusong <gaoyusong1@huawei.com> - 0.1.0-23
- DESC: fix logs redirection error and del rsa_public_key_cloud.pem

* Wed Feb 23 2022 houmingyong<houmingyong@huawei.com> - 0.1.0-22
- DESC: fix double free bug

* Tue Jan 11 2022 houmingyong<houmingyong@huawei.com> - 0.1.0-21
- DESC: fix no secgear.log after install secGear-devel 

* Mon Jul 19 2021 chenmaodong<chenmaodong@huawei.com> - 0.1.0-20
- DESC: add requires for secGear: libsgx-aesm-launch-plugin ocaml-dune

* Fri Jul 2 2021 zhangguangzhi<zhangguangzhi3@huawei.com> - 0.1.0-19
- DESC: add buildrequires openssl for x86

* Tue Jun 29 2021 zhangguangzhi<zhangguangzhi3@huawei.com> - 0.1.0-18
- DESC: add some buildrequires gcc-c++ rpm

* Fri Jun 4 2021 chenmaodong<chenmaodong@huawei.com> - 0.1.0-17
- DESC: clean enclave memory when it comes to error_handle

* Thu Jun 3 2021 chenmaodong<chenmaodong@huawei.com> - 0.1.0-16
- DESC: backport some patches from openeuler secGear

* Wed Jun 2 2021 chenmaodong<chenmaodong@huawei.com> - 0.1.0-15
- DESC: fix uaf in cc_enclave_create

* Thu May 20 2021 chenmaodong<chenmaodong@huawei.com> - 0.1.0-14
- DESC: update some bugfix form openeuler secGear

* Wed May 12 2021 yanlu<yanlu14@huawei.com> - 0.1.0-13
- DESC: update signtool and codegen

* Tue Apr 27 2021 chenmaodong<chenmaodong@huawei.com> - 0.1.0-12
- DESC: add cmake to Requires

* Tue Apr 13 2021 wanghongzhe<wanghongzhe@huawei.com> - 0.1.0-11
- DESC: add licenses and thirdparty opensource notice

* Sat Mar 20 2021 zhangguangzhi<zhangguangzhi3@huawei.com> - 0.1.0-10
- DESC: backport patch

* Fri Mar 19 2021 wanghongzhe<wanghongzhe@huawei.com> - 0.1.0-9
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
