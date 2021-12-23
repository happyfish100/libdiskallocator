
%define LibDiskallocatorDevel  libdiskallocator-devel
%define CommitVersion %(echo $COMMIT_VERSION)

Name: libdiskallocator
Version: 1.0.0
Release: 1%{?dist}
Summary: rapid disk allocator
License: AGPL
Group: Arch/Tech
URL:  http://github.com/happyfish100/libdiskallocator/
Source: http://github.com/happyfish100/libdiskallocator/%{name}-%{version}.tar.gz

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: libfastcommon-devel >= 1.0.54
BuildRequires: libserverframe-devel >= 1.1.11
Requires: libfastcommon >= 1.0.54
Requires: libserverframe >= 1.1.11
Requires: %__cp %__mv %__chmod %__grep %__mkdir %__install %__id

%description
rapid disk allocator
commit version: %{CommitVersion}

%package devel
Summary: Development header file
Requires: libfastcommon-devel >= 1.0.54
Requires: libserverframe-devel >= 1.1.11
Requires: %{name}%{?_isa} = %{version}-%{release}

%description devel
This package provides the header files of libdiskallocator
commit version: %{CommitVersion}


%prep
%setup -q

%build
./make.sh clean && ./make.sh

%install
rm -rf %{buildroot}
DESTDIR=$RPM_BUILD_ROOT ./make.sh install

%post

%preun

%postun

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
/usr/lib64/libdiskallocator.so*

%files devel
%defattr(-,root,root,-)
/usr/include/diskallocator/*

%changelog
* Wed Dec 22 2021 YuQing
- first RPM release (1.0)
