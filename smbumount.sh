#!/bin/sh -

# smbumount.sh - a front end shell script that calls smbumount-2.2.x
#	or smbumount-2.0.x depending on the kernel that is currently
#	running.

SMBUMOUNTBIN=/usr/bin

SMBFSUMOUNT=smbumount-2.0.x
SAMBAUMOUNT=smbumount-2.2.x

#	Which version
case `uname -r` in
1.*)
	# Give me a break...
	echo "No way this version"
	exit 255
	;;

2.0.*)
	# 2.0 uses the paramters as passed to us.  Just exec the real McCoy.
	exec $SMBUMOUNTBIN/$SMBFSUMOUNT "$@"
	;;
2.[1234].*)
	exec $SMBUMOUNTBIN/$SAMBAUMOUNT "$@"
	;;
*)
	# Huh?
	echo "Unrecognized kernel version"
	exit 255
	;;
esac
