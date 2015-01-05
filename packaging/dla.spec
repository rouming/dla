Summary:            Futex dead-lock analyser
Name:               dla
Version:            %{_version}
Release:            1
License:            GPLv2+
Source:             dla-%{_version}.tar.gz

%description
Analyses simple ABBA deadlocks (basically pthread_mutex_lock) from user
space, scanning /proc/*/task, reading /proc/*/syscall and /proc/*/status,
doing ptrace.  So definitely this tool is a hack which works only on Linux.

It is not a static analyser, this tool does post-mortem analysis, when
something on your system has stuck and you have to understand what exactly
and to see the locking dependency.

%prep
%setup -q

%build
make %{?_smp_mflags}

%install
%make_install

install -m 755 -d %{buildroot}%{_bindir}

%files
%doc README
%{_bindir}/dla
%{_bindir}/test-deadlock
%{_bindir}/filter-deadlock
