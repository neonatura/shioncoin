Name:           share-coin
Version:        3.2.2
Release:        1%{?dist}
Summary:        The share-coin virtual currency server.

Group:          System Environment/Libraries
License:        GPLv3+
URL:            http://www.shcoins.com/
Source0:        ftp://ftp.shcoins.com/release/share-coin/share-coin-3.2.2.tar.gz

#Requires:       libshare
Requires:       info 

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
%{_bindir}/testnet
%{_docdir}/share-coin/shcoin_html.tar.gz

%changelog
* Sat Mar 16 2018 Neo Natura <support@neo-natura.com> - 3.2.2
- The RPM release version of this package.
