/*
   Unix SMB/CIFS implementation.
   SMB torture tester
   Copyright (C) Andrew Bartlett 2012

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "torture/smbtorture.h"
#include "dlz_minimal.h"
#include <talloc.h>
#include <ldb.h>
#include "lib/param/param.h"
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "auth/session.h"
#include "auth/gensec/gensec.h"
#include "auth/credentials/credentials.h"
#include "lib/cmdline/popt_common.h"
#include "gen_ndr/ndr_dnsp.h"

struct torture_context *tctx_static;

static void dlz_bind9_log_wrapper(int level, const char *fmt, ...)
{
	va_list ap;
	char *msg;
	va_start(ap, fmt);
	msg = talloc_vasprintf(NULL, fmt, ap);
	torture_comment(tctx_static, "%s\n", msg);
	TALLOC_FREE(msg);
	va_end(ap);
}

static bool test_dlz_bind9_version(struct torture_context *tctx)
{
	unsigned int flags = 0;
	torture_assert_int_equal(tctx, dlz_version(&flags),
				 DLZ_DLOPEN_VERSION, "got wrong DLZ version");
	return true;
}

static bool test_dlz_bind9_create(struct torture_context *tctx)
{
	void *dbdata;
	const char *argv[] = {
		"samba_dlz",
		"-H",
		lpcfg_private_path(tctx, tctx->lp_ctx, "dns/sam.ldb"),
		NULL
	};
	tctx_static = tctx;
	torture_assert_int_equal(tctx, dlz_create("samba_dlz", 3, discard_const_p(char *, argv), &dbdata,
						  "log", dlz_bind9_log_wrapper, NULL), ISC_R_SUCCESS,
		"Failed to create samba_dlz");

	dlz_destroy(dbdata);

	return true;
}

static isc_result_t dlz_bind9_writeable_zone_hook(dns_view_t *view,
					   const char *zone_name)
{
	struct torture_context *tctx = talloc_get_type((void *)view, struct torture_context);
	struct ldb_context *samdb = samdb_connect_url(tctx, NULL, tctx->lp_ctx,
						      system_session(tctx->lp_ctx),
						      0, lpcfg_private_path(tctx, tctx->lp_ctx, "dns/sam.ldb"));
	struct ldb_message *msg;
	int ret;
	const char *attrs[] = {
		NULL
	};
	if (!samdb) {
		torture_fail(tctx, "Failed to connect to samdb");
		return ISC_R_FAILURE;
	}

	ret = dsdb_search_one(samdb, tctx, &msg, NULL,
			      LDB_SCOPE_SUBTREE, attrs, DSDB_SEARCH_SEARCH_ALL_PARTITIONS,
			      "(&(objectClass=dnsZone)(name=%s))", zone_name);
	if (ret != LDB_SUCCESS) {
		torture_fail(tctx, talloc_asprintf(tctx, "Failed to search for %s: %s", zone_name, ldb_errstring(samdb)));
		return ISC_R_FAILURE;
	}
	talloc_free(msg);

	return ISC_R_SUCCESS;
}

static bool test_dlz_bind9_configure(struct torture_context *tctx)
{
	void *dbdata;
	const char *argv[] = {
		"samba_dlz",
		"-H",
		lpcfg_private_path(tctx, tctx->lp_ctx, "dns/sam.ldb"),
		NULL
	};
	tctx_static = tctx;
	torture_assert_int_equal(tctx, dlz_create("samba_dlz", 3, discard_const_p(char *, argv), &dbdata,
						  "log", dlz_bind9_log_wrapper,
						  "writeable_zone", dlz_bind9_writeable_zone_hook, NULL),
				 ISC_R_SUCCESS,
				 "Failed to create samba_dlz");

	torture_assert_int_equal(tctx, dlz_configure((void*)tctx, dbdata),
						     ISC_R_SUCCESS,
				 "Failed to configure samba_dlz");

	dlz_destroy(dbdata);

	return true;
}

/*
 * Test that a ticket obtained for the DNS service will be accepted on the Samba DLZ side
 *
 */
static bool test_dlz_bind9_gensec(struct torture_context *tctx, const char *mech)
{
	NTSTATUS status;

	struct gensec_security *gensec_client_context;

	DATA_BLOB client_to_server, server_to_client;

	void *dbdata;
	const char *argv[] = {
		"samba_dlz",
		"-H",
		lpcfg_private_path(tctx, tctx->lp_ctx, "dns/sam.ldb"),
		NULL
	};
	tctx_static = tctx;
	torture_assert_int_equal(tctx, dlz_create("samba_dlz", 3, discard_const_p(char *, argv), &dbdata,
						  "log", dlz_bind9_log_wrapper,
						  "writeable_zone", dlz_bind9_writeable_zone_hook, NULL),
				 ISC_R_SUCCESS,
				 "Failed to create samba_dlz");

	torture_assert_int_equal(tctx, dlz_configure((void*)tctx, dbdata),
						     ISC_R_SUCCESS,
				 "Failed to configure samba_dlz");

	status = gensec_client_start(tctx, &gensec_client_context,
				     lpcfg_gensec_settings(tctx, tctx->lp_ctx));
	torture_assert_ntstatus_ok(tctx, status, "gensec_client_start (client) failed");

	status = gensec_set_target_hostname(gensec_client_context, torture_setting_string(tctx, "host", NULL));
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_target_hostname (client) failed");

	status = gensec_set_credentials(gensec_client_context, cmdline_credentials);
	torture_assert_ntstatus_ok(tctx, status, "gensec_set_credentials (client) failed");

	status = gensec_start_mech_by_sasl_name(gensec_client_context, mech);
	torture_assert_ntstatus_ok(tctx, status, "gensec_start_mech_by_sasl_name (client) failed");

	server_to_client = data_blob(NULL, 0);

	/* Do one step of the client-server update dance */
	status = gensec_update(gensec_client_context, tctx, server_to_client, &client_to_server);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {;
		torture_assert_ntstatus_ok(tctx, status, "gensec_update (client) failed");
	}

	torture_assert_int_equal(tctx, dlz_ssumatch(cli_credentials_get_username(cmdline_credentials),
						    lpcfg_dnsdomain(tctx->lp_ctx),
						    "127.0.0.1", "type", "key",
						    client_to_server.length,
						    client_to_server.data,
						    dbdata),
				 ISC_R_SUCCESS,
				 "Failed to check key for update rights samba_dlz");

	dlz_destroy(dbdata);

	return true;
}

static bool test_dlz_bind9_gssapi(struct torture_context *tctx)
{
	return test_dlz_bind9_gensec(tctx, "GSSAPI");
}

static bool test_dlz_bind9_spnego(struct torture_context *tctx)
{
	return test_dlz_bind9_gensec(tctx, "GSS-SPNEGO");
}

static bool test_dlz_bind9_add_wins_rr(struct torture_context *tctx,
		const char *zone)
{
	struct ldb_context *samdb;
	char *url;
	struct ldb_dn *basedn, *zonedn;
	struct ldb_result *res;
	struct ldb_message_element *el;
	int i, ret;
	struct dnsp_DnssrvRpcRecord *rec;
	NTTIME t;
	enum ndr_err_code ndr_err;
	uint32_t soa_serial;
	bool have_wins;
	const char *zone_prefixes[] = {
		"CN=MicrosoftDNS,DC=DomainDnsZones",
		"CN=MicrosoftDNS,DC=ForestDnsZones",
		"CN=MicrosoftDNS,CN=System",
		NULL
	};
	const char *attrs[] = {
		"dnsRecord",
		NULL
	};

	url = lpcfg_private_path(tctx, tctx->lp_ctx, "dns/sam.ldb");
	samdb = samdb_connect_url(tctx, tctx->ev, tctx->lp_ctx,
					system_session(tctx->lp_ctx), 0, url);
	basedn = ldb_get_default_basedn(samdb);

	for (i=0; zone_prefixes[i]; i++) {
		zonedn = ldb_dn_copy(tctx, basedn);
		if (!ldb_dn_add_child_fmt(zonedn, "DC=@,DC=%s,%s", zone, zone_prefixes[i])) {
			torture_fail(tctx, "ldb_dn_add_child_fmt failed");
			return false;
		}
		ret = ldb_search(samdb, tctx, &res, zonedn, LDB_SCOPE_BASE,
				attrs, "objectClass=dnsNode");
		if (ret == LDB_SUCCESS) {
			break;
		}
	}
	if (ret != LDB_SUCCESS || res->count == 0) {
		torture_fail(tctx, "zone not found");
		return false;
	}

	// We have the entry, check if WINS record is present
	have_wins = false;
	el = ldb_msg_find_element(res->msgs[0], "dnsRecord");
	for (i=0; i<el->num_values; i++) {
		struct dnsp_DnssrvRpcRecord r;

		ndr_err = ndr_pull_struct_blob(&el->values[i], tctx, &r,
				(ndr_pull_flags_fn_t)ndr_pull_dnsp_DnssrvRpcRecord);
		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			torture_fail(tctx, "failed to parse dnsRecord");
			return false;
		}
		if (r.wType == DNS_TYPE_SOA) {
			soa_serial = r.data.soa.serial;
		} else if (r.wType == DNS_TYPE_WINS) {
			/* Already have WINS record */
			have_wins = true;
		}
	}

	if (have_wins) {
		torture_comment(tctx, "Zone already have WINS record\n");
		return true;
	}

	el->values = talloc_realloc(el, el->values, struct ldb_val, el->num_values+1);
	if (el->values == NULL) {
		torture_fail(tctx, "No memory");
		return false;
	}
	el->num_values++;

	rec = talloc_zero(tctx, struct dnsp_DnssrvRpcRecord);
	rec->wType = DNS_TYPE_WINS;
	unix_to_nt_time(&t, time(NULL));
	t /= 10*1000*1000; /* convert to seconds (NT time is in 100ns units) */
	t /= 3600;         /* convert to hours */
	rec->rank        = DNS_RANK_ZONE;
	rec->dwSerial    = soa_serial;
	rec->dwTimeStamp = (uint32_t)t;
	rec->dwTtlSeconds = 0;
	rec->data.wins.dwMappingFlags = 0;
	rec->data.wins.dwLookupTimeout = 2;
	rec->data.wins.dwCacheTimeout = 900;
	rec->data.wins.cWinsServerCount = 1;
	rec->data.wins.aipWinsServers = talloc_realloc(rec,
		rec->data.wins.aipWinsServers, const char *,
		rec->data.wins.cWinsServerCount);
	rec->data.wins.aipWinsServers[0] = talloc_strdup(rec, "1.2.3.4");

	ndr_err = ndr_push_struct_blob(&el->values[el->num_values - 1], rec, rec,
					(ndr_push_flags_fn_t)ndr_push_dnsp_DnssrvRpcRecord);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		torture_fail(tctx, "failed to push dnsRecord");
		return false;
	}

	el->flags = LDB_FLAG_MOD_REPLACE;
	ret = ldb_modify(samdb, res->msgs[0]);
	if (ret != LDB_SUCCESS) {
		torture_fail(tctx, "failed to modify entry");
		return false;
	}

	torture_comment(tctx, "WINS record added to zone\n");

	return true;
}

static isc_result_t dlz_bind9_putrr_wrapper(dns_sdlzlookup_t *lookup,
		const char *type, dns_ttl_t ttl, const char *data)
{
	return ISC_R_SUCCESS;
}

static bool test_dlz_bind9_query_soa(struct torture_context *tctx)
{
	isc_result_t result;
	void *dbdata;
	const char *zone;
	dns_sdlzlookup_t *lookup = NULL;
	const char *argv[] = {
		"samba_dlz",
		"-H",
		lpcfg_private_path(tctx, tctx->lp_ctx, "dns/sam.ldb"),
		NULL
	};

	tctx_static = tctx;
	zone = lpcfg_dnsdomain(tctx->lp_ctx);
	torture_assert(tctx, test_dlz_bind9_add_wins_rr(tctx, zone),
		"Failed to add WINS record");

	torture_assert_int_equal(tctx,
		dlz_create("samba_dlz", 3, discard_const_p(char *, argv),
			&dbdata, "log", dlz_bind9_log_wrapper,
			"writeable_zone", dlz_bind9_writeable_zone_hook,
			"putrr", dlz_bind9_putrr_wrapper,
			NULL),
		ISC_R_SUCCESS, "Failed to create samba_dlz");

	torture_assert_int_equal(tctx,
		dlz_configure((void*)tctx, dbdata), ISC_R_SUCCESS,
			"Failed to configure samba_dlz");

#ifdef BIND_VERSION_9_8
	result = dlz_lookup(zone, "@", dbdata, lookup);
#else
	result = dlz_lookup(zone, "@", dbdata, lookup, NULL, NULL);
#endif
	torture_assert_int_equal(tctx, result, ISC_R_SUCCESS,
		"Failed to query SOA record");

	return true;
}

static struct torture_suite *dlz_bind9_suite(TALLOC_CTX *ctx)
{
	struct torture_suite *suite = torture_suite_create(ctx, "dlz_bind9");

	suite->description = talloc_strdup(suite,
	                                   "Tests for the BIND 9 DLZ module");
	torture_suite_add_simple_test(suite, "version", test_dlz_bind9_version);
	torture_suite_add_simple_test(suite, "create", test_dlz_bind9_create);
	torture_suite_add_simple_test(suite, "configure", test_dlz_bind9_configure);
	torture_suite_add_simple_test(suite, "gssapi", test_dlz_bind9_gssapi);
	torture_suite_add_simple_test(suite, "spnego", test_dlz_bind9_spnego);
	torture_suite_add_simple_test(suite, "query_soa", test_dlz_bind9_query_soa);
	return suite;
}

/**
 * DNS torture module initialization
 */
NTSTATUS torture_bind_dns_init(void)
{
	struct torture_suite *suite;
	TALLOC_CTX *mem_ctx = talloc_autofree_context();

	/* register DNS related test cases */
	suite = dlz_bind9_suite(mem_ctx);
	if (!suite) return NT_STATUS_NO_MEMORY;
	torture_register_suite(suite);

	return NT_STATUS_OK;
}
