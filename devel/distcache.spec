###############################################################################
#
# To build RPMs from this spec file, you need some basic RPM stuff set up in
# your account. Do not do any of this stuff as root, and consider even setting
# up an account for nothing other than making RPMs...
#
# You need to create the following directories;
#   mkdir -p ~/rpm/{BUILD,RPMS/noarch,SOURCES,SRPMS,SPECS,tmp}
#
# On x86 machines, you also need;
#   mkdir -p ~/rpm/RPMS/i586
#
# You then need two config files setup in your account (ignore the asterisk and
# space at the beginning of each line);
#
# cat > ~/.rpmrc << EOF
# buildarchtranslate: i386: i586
# buildarchtranslate: i486: i586
# buildarchtranslate: i586: i586
# buildarchtranslate: i686: i586
# EOF
#
# cat > ~/.rpmmacros << EOF
# %_topdir               $HOME/rpm
# %_tmppath              $HOME/rpm/tmp
# %distribution          Mandrake Linux
# %vendor                MandrakeSoft
# EOF
#
# Once all that's done you're almost ready to go. The main step-by-step
# instructions will apply to a released distcache 'bz2' tarball. If you're
# working from a fresh CVS checkout, do the following to create such a tarball;
#
# (1) verify that the version in the "configure.ac" file, the second parameter
#     to the AC_INIT() macro, matches exactly the "%define version ..." setting
#     further down in this file.
# (2) run ./bootstrap.sh to generate "./configure" and Makefile.in files
# (3) run "./configure"
# (4) run "make dist-bzip2"
#
# The resulting distcache-X.X.tar.bz2 tarball should be in the top-level
# directory.
#
# Now you have a 'bz2' tarball, the steps to building the RPMs are relatively
# straightforward;
#
# (1) copy the tarball to the RPM 'SOURCES' directory;
#         mv distcache-X.X.tar.bz2 ~/rpm/SOURCES/
# (2) point directly to this spec file when running the rpm build command;
#         rpm -ba distcache-X.X/devel/distcache.spec
#
# If all goes well, the last line of output should mention "exit 0" and there
# should be new RPMs living in ~/rpm/RPMS/i586 and ~/rpm/SRPMS.
#


#############
# Setup stuff
#############

%define name distcache
%define version 0.4pre1
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
Source: http://download.sourceforge.net/distcache/%{name}-%{version}.tar.bz2
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
%{_mandir}/man2/*.2*

#########
# Changes
#########

%changelog
* Sun Mar 09 2003 Geoff Thorpe <geoff@geoffthorpe.net> 0.4pre1
- split into two RPMs (distcache and distcache-devel)
- created from Mandrake's excellent HOWTO

