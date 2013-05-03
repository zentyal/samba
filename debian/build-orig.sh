#!/bin/bash -e

version=$( dpkg-parsechangelog -l`dirname $0`/changelog | sed -n 's/^Version: \(.*:\|\)//p' | sed 's/-[0-9.]\+$//' )

if echo "$version" | egrep "(bzr|git)" >/dev/null; then
	if [ -z "$SAMBA_GIT_URL" ]; then
		SAMBA_GIT_URL=git://git.samba.org/samba.git
	fi

	if [ -d "$SAMBA_GIT_URL/.bzr" ]; then
		bzr co --lightweight "$SAMBA_GIT_URL" samba4-upstream-$version
	else
		git clone "$SAMBA_GIT_URL" samba4-upstream-$version
	fi

	pushd "samba4-upstream-$version"
	./configure
	./buildtools/bin/waf dist
	tar xfz samba-4.*.tar.gz
	rm samba-4*.tar.gz
	mv samba-4* "../samba4-$version"
	popd
	rm -rf "samba4-upstream-$version"
else
	upstream_version=`echo $version | sed -e 's/~alpha1~tp/tp/;s/~beta/beta/;s/~alpha/alpha/;s/~rc/rc/;s/.dfsg[0-9]*$//;'`
	wget ftp://ftp.samba.org/pub/samba/samba-$upstream_version.tar.gz
	wget ftp://ftp.samba.org/pub/samba/samba-$upstream_version.tar.asc
	gunzip samba-$upstream_version.tar.gz
	gpg --verify samba-$upstream_version.tar.asc
	tar xvf samba-$upstream_version.tar
	mv samba-$upstream_version samba-$version
	rm samba-$upstream_version.tar.asc samba-$upstream_version.tar
fi
`dirname $0`/dfsg-clean.sh "samba-$version"
tar cfz samba_$version.orig.tar.gz "samba-$version"
rm -rf "samba-$version"
exit 0
