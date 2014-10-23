#!/usr/bin/env python

import optparse
import sys
import os
import unittest
import samba
import samba.getopt as options

from subunit.run import SubunitTestRunner
from samba.tests import delete_force
from samba.samdb import SamDB
from samba.auth import system_session
from ldb import Message, MessageElement, Dn
from ldb import FLAG_MOD_ADD, FLAG_MOD_REPLACE, FLAG_MOD_DELETE
from ldb import SCOPE_BASE, SCOPE_SUBTREE 

class MatchRulesTests(samba.tests.TestCase):
    def setUp(self):
        super(MatchRulesTests, self).setUp()
        self.ldb = ldb
        self.base_dn = ldb.domain_dn()
        self.ou = "ou=matchrulestest,%s" % self.base_dn
        self.ou_users = "ou=users,%s" % self.ou
        self.ou_groups = "ou=groups,%s" % self.ou

        # Add a organizational unit to create objects
        ldb.add({
            "dn": self.ou,
            "objectclass": "organizationalUnit"})
        ldb.add({
            "dn": self.ou_users,
            "objectclass": "organizationalUnit"})
        ldb.add({
            "dn": self.ou_groups,
            "objectclass": "organizationalUnit"})

        # Add four groups
        ldb.add({
            "dn": "cn=g1," + self.ou_groups,
            "objectclass": "group" })
	ldb.add({
            "dn": "cn=g2," + self.ou_groups,
            "objectclass": "group" })
	ldb.add({
            "dn": "cn=g3," + self.ou_groups,
            "objectclass": "group" })
	ldb.add({
            "dn": "cn=g4," + self.ou_groups,
            "objectclass": "group" })

	# Add four users
	ldb.add({
            "dn": "cn=u1," + self.ou_users,
            "objectclass": "user"})
	ldb.add({
            "dn": "cn=u2," + self.ou_users,
            "objectclass": "user"})
	ldb.add({
            "dn": "cn=u3," + self.ou_users,
            "objectclass": "user"})
	ldb.add({
            "dn": "cn=u4," + self.ou_users,
            "objectclass": "user"})

        # Create the following hierarchy:
        # g4
        # |--> u4
        # |--> g3
        # |    |--> u3
        # |    |--> g2
        # |    |    |--> u2
        # |    |    |--> g1
        # |    |    |    |--> u1

        # u1 member of g1
        m = Message()
        m.dn = Dn(ldb, "cn=g1," + self.ou_groups)
        m["member"] = MessageElement("cn=u1," + self.ou_users,
                                     FLAG_MOD_ADD, "member")
        ldb.modify(m)

        # u2 member of g2
        m = Message()
        m.dn = Dn(ldb, "cn=g2," + self.ou_groups)
        m["member"] = MessageElement("cn=u2," + self.ou_users,
                                     FLAG_MOD_ADD, "member")
        ldb.modify(m)

        # u3 member of g3
        m = Message()
        m.dn = Dn(ldb, "cn=g3," + self.ou_groups)
        m["member"] = MessageElement("cn=u3," + self.ou_users,
                                     FLAG_MOD_ADD, "member")
        ldb.modify(m)

        # u4 member of g4
        m = Message()
        m.dn = Dn(ldb, "cn=g4," + self.ou_groups)
        m["member"] = MessageElement("cn=u4," + self.ou_users,
                                     FLAG_MOD_ADD, "member")
        ldb.modify(m)

	# g3 member of g4
        m = Message()
        m.dn = Dn(ldb, "cn=g4," + self.ou_groups)
        m["member"] = MessageElement("cn=g3," + self.ou_groups,
                                     FLAG_MOD_ADD, "member")
        ldb.modify(m)

	# g2 member of g3
        m = Message()
        m.dn = Dn(ldb, "cn=g3," + self.ou_groups)
        m["member"] = MessageElement("cn=g2," + self.ou_groups,
                                     FLAG_MOD_ADD, "member")
        ldb.modify(m)

	# g1 member of g2
        m = Message()
        m.dn = Dn(ldb, "cn=g2," + self.ou_groups)
        m["member"] = MessageElement("cn=g1," + self.ou_groups,
                                     FLAG_MOD_ADD, "member")
        ldb.modify(m)

    def tearDown(self):
        super(MatchRulesTests, self).tearDown()
        delete_force(self.ldb, "cn=u4," + self.ou_users)
        delete_force(self.ldb, "cn=u3," + self.ou_users)
        delete_force(self.ldb, "cn=u2," + self.ou_users)
        delete_force(self.ldb, "cn=u1," + self.ou_users)
        delete_force(self.ldb, "cn=g4," + self.ou_groups)
        delete_force(self.ldb, "cn=g3," + self.ou_groups)
        delete_force(self.ldb, "cn=g2," + self.ou_groups)
        delete_force(self.ldb, "cn=g1," + self.ou_groups)
        delete_force(self.ldb, self.ou_users)
        delete_force(self.ldb, self.ou_groups)
        delete_force(self.ldb, self.ou)

    def test_u1_member_of_g4(self):
	# Search without transitive match must return 0 results
        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                        scope=SCOPE_BASE,
                        expression="member=cn=u1,%s" % self.ou_users)
        self.assertTrue(len(res1) == 0)

        res1 = self.ldb.search("cn=u1,%s" % self.ou_users,
                        scope=SCOPE_BASE,
                        expression="memberOf=cn=g4,%s" % self.ou_groups)
        self.assertTrue(len(res1) == 0)

	# Search with transitive match must return 1 results
        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                        scope=SCOPE_BASE,
                        expression="member:1.2.840.113556.1.4.1941:=cn=u1,%s" % self.ou_users)
        self.assertTrue(len(res1) == 1)

        res1 = self.ldb.search("cn=u1,%s" % self.ou_users,
                        scope=SCOPE_BASE,
                        expression="memberOf:1.2.840.113556.1.4.1941:=cn=g4,%s" % self.ou_groups)
        self.assertTrue(len(res1) == 1)

    def test_g1_member_of_g4(self):
	# Search without transitive match must return 0 results
        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                        scope=SCOPE_BASE,
                        expression="member=cn=g1,%s" % self.ou_groups)
        self.assertTrue(len(res1) == 0)

        res1 = self.ldb.search("cn=g1,%s" % self.ou_groups,
                        scope=SCOPE_BASE,
                        expression="memberOf=cn=g4,%s" % self.ou_groups)
        self.assertTrue(len(res1) == 0)

	# Search with transitive match must return 1 results
        res1 = self.ldb.search("cn=g4,%s" % self.ou_groups,
                        scope=SCOPE_BASE,
                        expression="member:1.2.840.113556.1.4.1941:=cn=g1,%s" % self.ou_groups)
        self.assertTrue(len(res1) == 1)
        
        res1 = self.ldb.search("cn=g1,%s" % self.ou_groups,
                        scope=SCOPE_BASE,
                        expression="memberOf:1.2.840.113556.1.4.1941:=cn=g4,%s" % self.ou_groups)
        self.assertTrue(len(res1) == 1)

    def test_u1_groups(self):
        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member=cn=u1,%s" % self.ou_users)
        self.assertTrue(len(res1) == 1);

        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member:1.2.840.113556.1.4.1941:=cn=u1,%s" % self.ou_users)
        self.assertTrue(len(res1) == 4);

    def test_u2_groups(self):
        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member=cn=u2,%s" % self.ou_users)
        self.assertTrue(len(res1) == 1);

        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member:1.2.840.113556.1.4.1941:=cn=u2,%s" % self.ou_users)
        self.assertTrue(len(res1) == 3);
        
    def test_u3_groups(self):
        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member=cn=u3,%s" % self.ou_users)
        self.assertTrue(len(res1) == 1);

        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member:1.2.840.113556.1.4.1941:=cn=u3,%s" % self.ou_users)
        self.assertTrue(len(res1) == 2);

    def test_u4_groups(self):
        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member=cn=u4,%s" % self.ou_users)
        self.assertTrue(len(res1) == 1);

        res1 = self.ldb.search(self.ou_groups,
                        scope=SCOPE_SUBTREE,
                        expression="member:1.2.840.113556.1.4.1941:=cn=u4,%s" % self.ou_users)
        self.assertTrue(len(res1) == 1);

parser = optparse.OptionParser("match_rules.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))

# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

samba.ensure_external_module("testtools", "testtools")
samba.ensure_external_module("subunit", "subunit/python")

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

if not "://" in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host

ldb = SamDB(host, credentials=creds, session_info=system_session(lp), lp=lp)

runner = SubunitTestRunner()
rc = 0
if not runner.run(unittest.makeSuite(MatchRulesTests)).wasSuccessful():
    rc = 1
sys.exit(rc)
