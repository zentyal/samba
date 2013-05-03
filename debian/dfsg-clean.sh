#!/bin/bash -e
# DFSG-Clean a Samba 4 source tarball

srcdir="$1"

if [ -z "$srcdir" ]; then
	srcdir="."
fi

if [ ! -d "$srcdir/source4" ]; then
	echo "Usage: $0 SRCDIR"
	exit 1
fi

pushd $srcdir/source4
rm heimdal/lib/wind/*.txt
pwd
rm -rf ldap_server/devdocs
popd

exit 0
