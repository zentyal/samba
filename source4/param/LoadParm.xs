/*
Copyright (C) 2013 Zentyal S.L.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License, version 2, as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>

#include "LoadParm.h"
#include <talloc.h>
#include <param.h>
#include <dynconfig.h>

MODULE = Samba::LoadParm        PACKAGE = Samba::LoadParm
PROTOTYPES: ENABLE

LoadParm *
new(class)
    SV *class
CODE:
    TALLOC_CTX *mem_ctx = NULL;
    LoadParm *self = NULL;
    //const char *classname;

    if (sv_isobject(class)) {
        //classname = sv_reftype(SvRV(class), 1);
    } else {
        if (!SvPOK(class))
            croak("%s: Need an object or class name as first "
                  "argument to the constructor", __func__);
        //classname = SvPV_nolen(class);
    }

    mem_ctx = talloc_named(NULL, 0, "Samba::LoadParm");
    if (mem_ctx == NULL) {
        croak("%s: No memory allocating memory context", __func__);
        XSRETURN_UNDEF;
    }

    self = talloc_zero(mem_ctx, LoadParm);
    if (self == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating private data", __func__);
        XSRETURN_UNDEF;
    }
    self->mem_ctx = mem_ctx;

    self->lp_ctx = loadparm_init(mem_ctx);
    if (self->lp_ctx == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating loadparm context", __func__);
        XSRETURN_UNDEF;
    }

    RETVAL = self;
OUTPUT:
    RETVAL

MODULE = Samba::LoadParm    PACKAGE = LoadParmPtr   PREFIX = lpPtr_
PROTOTYPES: ENABLE

const char *
lpPtr_default_path(self)
    LoadParm *self
    CODE:
    RETVAL = lp_default_path();
    OUTPUT:
    RETVAL

const char *
lpPtr_setup_dir(self)
    LoadParm *self
    CODE:
    RETVAL = dyn_SETUPDIR;
    OUTPUT:
    RETVAL

const char *
lpPtr_modules_dir(self)
    LoadParm *self
    CODE:
    RETVAL = dyn_MODULESDIR;
    OUTPUT:
    RETVAL

const char *
lpPtr_bin_dir(self)
    LoadParm *self
    CODE:
    RETVAL = dyn_BINDIR;
    OUTPUT:
    RETVAL

const char *
lpPtr_sbin_dir(self)
    LoadParm *self
    CODE:
    RETVAL = dyn_SBINDIR;
    OUTPUT:
    RETVAL

const char *
lpPtr_private_path(self, name)
    LoadParm *self
    const char *name
    CODE:
    char *path;
    path = lpcfg_private_path(self->mem_ctx, self->lp_ctx, name);
    RETVAL = path;
    talloc_free(path);
    OUTPUT:
    RETVAL

const char *
lpPtr_server_role(self)
    LoadParm *self
    CODE:
    uint32_t role;
    role = lpcfg_server_role(self->lp_ctx);
    switch (role) {
    case ROLE_STANDALONE:
        RETVAL = "ROLE_STANDALONE";
        break;
    case ROLE_DOMAIN_MEMBER:
        RETVAL = "ROLE_DOMAINMEMBER";
        break;
    case ROLE_DOMAIN_BDC:
        RETVAL = "ROLE_DOMAIN_BDC";
        break;
    case ROLE_DOMAIN_PDC:
        RETVAL = "ROLE_DOMAIN_PDC";
        break;
    case ROLE_ACTIVE_DIRECTORY_DC:
        RETVAL = "ROLE_ACTIVE_DIRECTORY_DC";
        break;
    case ROLE_AUTO:
        RETVAL = "ROLE_AUTO";
        break;
    default:
        croak("Unknown role");
    }
    OUTPUT:
    RETVAL

int
lpPtr_load(self, filename)
    LoadParm *self
    const char *filename
    CODE:
    bool ret;
    ret = lpcfg_load(self->lp_ctx, filename);
    if (!ret) {
        croak("Unable to load file %s", filename);
    }
    RETVAL = ret;
    OUTPUT:
    RETVAL

int
lpPtr_load_default(self)
    LoadParm *self
    CODE:
    bool ret;
    ret = lpcfg_load_default(self->lp_ctx);
    if (!ret) {
        croak("Unable to load dafault file");
    }
    RETVAL = ret;
    OUTPUT:
    RETVAL

int
lpPtr_is_myname(self, name)
    LoadParm *self
    const char *name
    CODE:
    RETVAL = lpcfg_is_myname(self->lp_ctx, name);
    OUTPUT:
    RETVAL

int
lpPtr_is_mydomain(self, name)
    LoadParm *self
    const char *name
    CODE:
    RETVAL = lpcfg_is_mydomain(self->lp_ctx, name);
    OUTPUT:
    RETVAL

void
lpPtr_DESTROY(self)
    LoadParm *self
CODE:
    talloc_free(self->mem_ctx);
