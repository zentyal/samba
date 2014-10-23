/*
   Unix SMB/CIFS implementation.

   ldb database library - Extended match rules

   Copyright (C) 2014 Samuel Cabrero <samuelcabrero@kernevil.me>

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
#include <ldb.h>
#include "dsdb/samdb/samdb.h"
#include "ldb_matching_rules.h"

static int ldb_eval_transitive_filter_helper(
		TALLOC_CTX *mem_ctx,
		struct ldb_context *ldb,
		const char *attr,
		const struct ldb_val *value_to_match,
		struct ldb_dn *to_visit,
		struct ldb_dn **visited,
		unsigned int *visited_count,
		bool *matched)
{
	int ret, i, j;
	struct ldb_result *res;
	struct ldb_message *msg;
	struct ldb_message_element *el;
	const char *attrs[] = { attr, NULL };
	const struct dsdb_schema *schema;
	const struct dsdb_attribute *schema_attr;
	bool canonicalize;

	/* Fetch the entry to_visit */
	ret = ldb_search(ldb, mem_ctx, &res, to_visit, LDB_SCOPE_BASE, attrs,
			 "(objectClass=*)");
	if (ret != LDB_SUCCESS) {
		return ret;
	}
	if (res->count != 1) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	msg = res->msgs[0];

	/* Fetch the attribute to match */
	el = ldb_msg_find_element(msg, attr);
	if (el == NULL) {
		*matched = false;
		return LDB_SUCCESS;
	}

	/* Get the syntax of the attribute to match */
	schema = dsdb_get_schema(ldb, mem_ctx);
	if (schema == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}
	schema_attr = dsdb_attribute_by_lDAPDisplayName(schema, attr);
	if (schema_attr == NULL) {
		return LDB_ERR_NO_SUCH_ATTRIBUTE;
	}

	/* Check if the attribute to match has to be canonicalized before
	 * comparision.
	 */
	if (strcmp(schema_attr->syntax->ldap_oid, DSDB_SYNTAX_STRING_DN) == 0 ||
	    strcmp(schema_attr->syntax->ldap_oid, DSDB_SYNTAX_BINARY_DN) == 0 ||
	    strcmp(schema_attr->syntax->ldap_oid, DSDB_SYNTAX_OR_NAME)   == 0 ||
	    strcmp(schema_attr->syntax->ldap_oid, DSDB_SYNTAX_ACCESS_POINT) == 0) {
		canonicalize = true;
	} else {
		canonicalize = false;
	}

	/* If the value to match is present in the attribute values, set
	 * matched to true and return OK
	 */
	for (i = 0; i < el->num_values; i++) {
		const struct ldb_schema_syntax *a;
		struct ldb_val *v2;

		a = schema_attr->ldb_schema_attribute->syntax;
		if (canonicalize) {
			if (a->canonicalise_fn(ldb, mem_ctx,
					       value_to_match, v2)) {
				return LDB_ERR_INVALID_ATTRIBUTE_SYNTAX;
			}
		} else {
			v2 = &el->values[i];
		}

		if (a->comparison_fn(ldb, mem_ctx, value_to_match,
				     &el->values[i]) == 0) {
			*matched = true;
			return LDB_SUCCESS;
		}
	}

	/* Add the entry being visited now (to_visit) to the visited array */
	if (visited == NULL) {
		visited = talloc_array(mem_ctx, struct ldb_dn *, 1);
		visited[0] = to_visit;
		(*visited_count) = 1;
	} else {
		visited = talloc_realloc(mem_ctx, visited, struct ldb_dn *,
					 (*visited_count) + 1);
		visited[(*visited_count)] = to_visit;
		(*visited_count)++;
	}

	/* Iterate over the values of the attribute of the entry being
	 * visited (to_visit). If the value is in the visited array, skip it.
	 * Otherwise, call to this function to visit it.
	 */
	for (i=0; i<el->num_values; i++) {
		struct ldb_dn *next_to_visit;
		bool skip = false;

		next_to_visit = ldb_dn_from_ldb_val(mem_ctx, ldb, &el->values[i]);
		if (next_to_visit == NULL) {
			return LDB_ERR_INVALID_DN_SYNTAX;
		}

		/* If the value is already in the visited array, skip.
		 * Note the last element of the array is ignored because it is
		 * the current entry DN.
		 */
		for (j=0; j < (*visited_count) - 1; j++) {
			struct ldb_dn *visited_dn = visited[j];
			if (ldb_dn_compare(visited_dn, next_to_visit) == 0) {
				skip = true;
				break;
			}
		}
		if (skip) {
			continue;
		}

		/* If the value is not in the visited array, evaluate it */
		ret = ldb_eval_transitive_filter_helper(mem_ctx, ldb, attr,
							value_to_match,
							next_to_visit, visited,
							visited_count, matched);
		if (ret != LDB_SUCCESS) {
			return ret;
		}
		if (*matched) {
			return LDB_SUCCESS;
		}
	}

	*matched = false;
	return LDB_SUCCESS;
}

static int ldb_eval_transitive_filter(
		TALLOC_CTX *mem_ctx,
		struct ldb_context *ldb,
		const char *attr,
		const struct ldb_val *v,
		struct ldb_dn *dn,
		bool *matched)
{
	const struct dsdb_schema *schema;
	const struct dsdb_attribute *schema_attr;
	struct ldb_val v2;
	unsigned int count;

	schema = dsdb_get_schema(ldb, mem_ctx);
	if (schema == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	schema_attr = dsdb_attribute_by_lDAPDisplayName(schema, attr);
	if (schema_attr == NULL) {
		return LDB_ERR_NO_SUCH_ATTRIBUTE;
	}

	/* If the attribute is of Object(DN-String), Object(DN-Binary),
	 * Object(OR-Name), or Object(Access-Point) syntax, let v2 equal the
	 * object_DN portion of v. Otherwise, let v2 equal v.
	 */
	if (strcmp(schema_attr->syntax->ldap_oid, DSDB_SYNTAX_STRING_DN)    == 0 ||
	    strcmp(schema_attr->syntax->ldap_oid, DSDB_SYNTAX_BINARY_DN)    == 0 ||
	    strcmp(schema_attr->syntax->ldap_oid, DSDB_SYNTAX_OR_NAME)      == 0 ||
	    strcmp(schema_attr->syntax->ldap_oid, DSDB_SYNTAX_ACCESS_POINT) == 0) {
		if (schema_attr->ldb_schema_attribute->syntax->canonicalise_fn(ldb, mem_ctx, v, &v2)) {
			return LDB_ERR_INVALID_DN_SYNTAX;
		}
	} else {
		v2 = ldb_val_dup(mem_ctx, v);
	}

	return ldb_eval_transitive_filter_helper(mem_ctx, ldb, attr, &v2, dn,
						 NULL, &count, matched);
}

/*
 * This rule provides recursive search of a link attribute
 * Implementation details on [MS-ADTS] section 3.1.1.3.4.4.3
*/
static int ldb_comparator_trans(struct ldb_context *ldb,
				const char *oid,
				const struct ldb_message *msg,
				const char *attribute_to_match,
				const struct ldb_val *value_to_match,
				bool *matched)
{
	const struct dsdb_schema *schema;
	const struct dsdb_attribute *schema_attr;
	TALLOC_CTX *tmp_ctx;
	int ret;

	tmp_ctx =  talloc_new(ldb);

	/* If the target attribute to match is not a linked attribute, then
	 * the filter evaluates to undefined */
	schema = dsdb_get_schema(ldb, tmp_ctx);
	if (schema == NULL) {
		return LDB_ERR_OPERATIONS_ERROR;
	}

	schema_attr = dsdb_attribute_by_lDAPDisplayName(schema, attribute_to_match);
	if (schema_attr == NULL) {
		return LDB_ERR_NO_SUCH_ATTRIBUTE;
	}

	if (schema_attr->linkID <= 0) {
		return LDB_ERR_INAPPROPRIATE_MATCHING;
	}

	ret = ldb_eval_transitive_filter(tmp_ctx, ldb,
					 attribute_to_match,
					 value_to_match,
					 msg->dn, matched);
	talloc_free(tmp_ctx);
	return ret;
}


int ldb_register_samba_matching_rules(struct ldb_context *ldb)
{
	struct ldb_extended_match_rule *transitive_eval;
	int ret;

	if (ldb_get_opaque(ldb, "SAMBA_MATCHING_RULES_REGISTERED") != NULL) {
		return LDB_SUCCESS;
	}

	transitive_eval = talloc_zero(ldb, struct ldb_extended_match_rule);
	transitive_eval->oid = SAMBA_LDAP_MATCH_RULE_TRANSITIVE_EVAL;
	transitive_eval->callback = ldb_comparator_trans;
	ret = ldb_register_extended_match_rule(ldb, transitive_eval);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	ret = ldb_set_opaque(ldb, "SAMBA_MATCHING_RULES_REGISTERED", (void*)1);
	if (ret != LDB_SUCCESS) {
		return ret;
	}

	return LDB_SUCCESS;
}
