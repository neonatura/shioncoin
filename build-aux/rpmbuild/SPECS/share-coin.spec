Name:           share-coin
Version:        2.28
Release:        4%{?dist}
Summary:        The share-coin virtual currency server.

Group:          System Environment/Libraries
License:        GPLv3+
URL:            http://www.sharelib.net/
Source0:        http://www.sharelib.net/release/share-coin-2.28.tar.gz

#BuildRequires:  gcc
#Requires:       info 

%description




%prep
%setup -q


%build
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
find $RPM_BUILD_ROOT -name '*.la' -exec rm -f {} ';'


%check
make check


%clean
rm -rf $RPM_BUILD_ROOT


%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
%defattr(-,root,root,-)
%doc
%{_sbindir}/shcoind
%{_bindir}/shc
%{_bindir}/usde
%{_bindir}/emc2
%{_docdir}/share-coin/shcoin_html.tar.gz

%changelog
* Sat Nov 26 2016 Neo Natura <support@neo-natura.com> - 2.28
- The RPM release version of this package.
