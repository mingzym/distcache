#####################################################################
#
# To build RPMs from this spec file, you need some basic RPM stuff set
# up in your account. Do not do any of this stuff as root, and consider
# even setting up an account for nothing other than making RPMs...
#
# You need to create the following directories;
#   mkdir -p ~/rpm/{BUILD,RPMS/noarch,SOURCES,SRPMS,SPECS,tmp}
#
# On x86 machines, you also need;
#   mkdir -p ~/rpm/RPMS/i586
#
# [FIXME: continue this spiel ... useful URLs are at;
#   http://www.linux-mandrake.com/en/howtos/mdk-rpm/
#   http://cvs.mandrakesoft.com/cgi-bin/cvsweb.cgi/SPECS/
# ...]

#############
# Setup stuff
#############

%define name distcache
%define version 0.4dev
%define release 1
# Uncomment one of these lines according to the destination distribution
# (Mandrake) %define targetgroup Networking/Other
# (Redhat) %define targetgroup Applications/System
%define targetgroup Networking/Other

# RPM information
Name: %{name}
Summary: Programs to provide a distributed session caching architecture
Version: %{version}
Release: %{release}
Source: http://www.distcache.org/direct/%{name}-%{version}.tar.bz2
URL: http://www.distcache.org/
Group: ${targetgroup}
Buildroot: %{_tmppath}/%{name}-buildroot
License: LGPL
Packager: Distcache project
# No requirments yet (Requires:)

# RPM information: "devel"
%package devel
Summary: Libraries and header files for building distcache-compatible software
Group: Networking/Other

# RPM description
%description
This package provides tools from the distcache project to deploy a distributed
session caching environment. This is most notably useful for SSL/TLS session
caching with supported OpenSSL-based applications. The caching protocol and API
is independent of SSL/TLS specifics and could be useful in other (non-SSL/TLS)
circumstances.

# RPM information: "devel"
%description devel
This package includes the static libraries and header files from the distcache
project that are required to compile distcache-compatible software. At present
the policy of the distcache project is to use static-linking so there are no
shared-libraries in the base package nor this "devel" package.

######################
# Prepare for building
######################

%prep
rm -rf $RPM_BUILD_ROOT
%setup

#######
# Build
#######

%build
./configure
make

#########
# Install
#########

%install
%makeinstall

#######
# Clean
#######

%clean
rm -rf $RPM_BUILD_ROOT

###########################
# Assemble package contents
###########################

# RPM files
%files
%defattr(-,root,root,0755)
%doc README ANNOUNCE CHANGES FAQ LICENSE
%{_mandir}/man1/*.1*
%{_mandir}/man8/*.8*
%{_bindir}/dc_*

# RPM files: "devel"
%files devel
%{_includedir}/libnal/*.h
%{_includedir}/distcache/*.h
%{_libdir}/libnal.*
%{_libdir}/libdistcache.*
%{_libdir}/libdistcacheserver.*

#########
# Changes
#########

%changelog
* Mon Mar 03 2003 Geoff Thorpe <geoff@geoffthorpe.net> 0.4test-1
- created from Mandrake's excellent HOWTO

