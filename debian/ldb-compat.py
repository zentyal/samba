#!/usr/bin/python
# LDB has an unstable ABI for plugins that can change at a whim.
# By default, the Samba package is conservative and only allows use of
# the version against which it was built.
#
# debian/ldb-equiv-versions can list ldb versions for which the ABI hasn't changed.

import optparse
parser = optparse.OptionParser("[options] ldb-version")
parser.add_option("--equivfile", dest="equivfile", type=str,
                  default="debian/ldb-equiv-versions",
                  help="File with ldb versions considered to be equivalent.")
(opts, args) = parser.parse_args()

if len(args) != 1:
    parser.error("No version specified.")

def parse_version(version):
    return map(int, version.split('.'))

def format_version(version):
    return '.'.join(map(str, version))

ldb_version = parse_version(args[0])

def next_version(version):
    x = list(version)
    x[-1] = x[-1]+1
    return format_version(x)

f = open(opts.equivfile, 'r')
try:
    for l in f.readlines():
        if l[0] == '#':
            continue
        (begin, end) = l.strip().split('-')
        if (ldb_version < parse_version(begin) or
            ldb_version > parse_version(end)):
            continue
        print begin
        print next_version(parse_version(end))
        break
    else:
        print format_version(ldb_version)
        print next_version(ldb_version)
finally:
    f.close()
