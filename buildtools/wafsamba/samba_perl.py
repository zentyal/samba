# waf build tool for building IDL files with pidl

import Build
from samba_utils import *
from samba_autoconf import *

from Configure import conf

@conf
def SAMBA_CHECK_PERL(conf, mandatory=True, version=(5,14,2)):
    # enable tool to build perl modules
    conf.find_program('perl', var='PERL', mandatory=mandatory)
    conf.find_program('xsltproc', var='XSLTPROC', mandatory=mandatory)
    conf.check_tool('perl')
    path_perl = conf.find_program('perl')
    conf.env.PERL_SPECIFIED = (conf.env.PERL != path_perl)
    conf.check_perl_version(version)

@conf
def SAMBA_CHECK_PERL_HEADERS(conf):
    if conf.env["perl_headers_checked"] == []:
        conf.check_perl_ext_devel()
        conf.env["perl_headers_checked"] = "yes"
    else:
        conf.msg("perl headers", "using cache")

def SAMBA_PERL(bld, name,
               source='',
               deps='',
               public_deps='',
               realname=None,
               cflags='',
               includes='',
               local_include=True,
               vars=None,
               enabled=True):
    '''build a perl module for Samba'''

    source = bld.EXPAND_VARIABLES(source, vars=vars)

    if realname is not None:
        link_name = 'perl_modules/%s' % realname
    else:
        link_name = None

    includes = bld.env.CPPPATH_PERLEXT

    bld.SAMBA_LIBRARY(name,
                      source=source,
                      deps=deps,
                      public_deps=public_deps,
                      includes=includes,
                      cflags=cflags,
                      local_include=local_include,
                      vars=vars,
                      realname=realname,
                      link_name=link_name,
                      private_library=True,
                      pyext=False,
                      perlext=True,
                      target_type='PERL',
                      install_path='${ARCHDIR_PERL}/auto',
                      allow_undefined_symbols=True,
                      enabled=enabled)

Build.BuildContext.SAMBA_PERL = SAMBA_PERL
