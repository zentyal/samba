#!/bin/sh -

# smbmount.sh - a front end shell script that calls smbmount-2.2.x
#	or smbmount-2.0.x depending on the kernel that is currently
#	running.

SMBMOUNTBIN=/usr/bin

SMBFSMOUNT=smbmount-2.0.x
SAMBAMOUNT=smbmount-2.2.x

#	Which version
case `uname -r` in
1.*)
	# Give me a break...
	echo "No way this version"
	exit 255
	;;

2.0.*)
	# 2.0 uses the paramters as passed to us.  Just exec the real McCoy.
	exec $SMBMOUNTBIN/$SMBFSMOUNT "$@"
	;;
2.[1234].*)
	exec $SMBMOUNTBIN/$SAMBAMOUNT "$@"
	;;
*)
	# Huh?
	echo "Unrecognized kernel version"
	exit 255
	;;
esac
