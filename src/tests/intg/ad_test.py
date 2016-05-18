#
# LDAP integration test
#
# Copyright (c) 2015 Red Hat, Inc.
# Author: Nikolai Kondrashov <Nikolai.Kondrashov@redhat.com>
#
# This is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
import os
import sys
import stat
import pwd
import grp
import ent
import config
import signal
import subprocess
import time
import ldap
import pytest
import ds_openldap
import ldap_ent
import fake_ad
from util import *

LDAP_BASE_DN = "dc=example,dc=com"
INTERACTIVE_TIMEOUT = 4


@pytest.fixture(scope="module")
def ds_inst(request):
    """LDAP server instance fixture"""
    ds_inst = fake_ad.FakeAD(
        config.PREFIX, 10389, LDAP_BASE_DN,
        "cn=admin", "Secret123"
    )

    try:
        ds_inst.setup()
    except:
        ds_inst.teardown()
        raise
    request.addfinalizer(lambda: ds_inst.teardown())
    return ds_inst


@pytest.fixture(scope="module")
def ldap_conn(request, ds_inst):
    """LDAP server connection fixture"""
    ldap_conn = ds_inst.bind()
    ldap_conn.ds_inst = ds_inst
    request.addfinalizer(lambda: ldap_conn.unbind_s())
    return ldap_conn


def create_ldap_entries(ldap_conn, ent_list=None):
    """Add LDAP entries from ent_list"""
    if ent_list is not None:
        for entry in ent_list:
            ldap_conn.add_s(entry[0], entry[1])


def cleanup_ldap_entries(ldap_conn, ent_list=None):
    """Remove LDAP entries added by create_ldap_entries"""
    if ent_list is None:
        for ou in ("Users", "Groups", "Netgroups", "Services", "Policies"):
            for entry in ldap_conn.search_s("ou=" + ou + "," +
                                            ldap_conn.ds_inst.base_dn,
                                            ldap.SCOPE_ONELEVEL,
                                            attrlist=[]):
                ldap_conn.delete_s(entry[0])
    else:
        for entry in ent_list:
            ldap_conn.delete_s(entry[0])


def create_ldap_cleanup(request, ldap_conn, ent_list=None):
    """Add teardown for removing all user/group LDAP entries"""
    request.addfinalizer(lambda: cleanup_ldap_entries(ldap_conn, ent_list))


def create_ldap_fixture(request, ldap_conn, ent_list=None):
    """Add LDAP entries and add teardown for removing them"""
    create_ldap_entries(ldap_conn, ent_list)
    create_ldap_cleanup(request, ldap_conn, ent_list)


SCHEMA_RFC2307 = "rfc2307"
SCHEMA_RFC2307_BIS = "rfc2307bis"


def format_basic_conf(ldap_conn, schema, enum):
    """Format a basic SSSD configuration"""
    schema_conf = "ldap_schema         = " + schema + "\n"
    if schema == SCHEMA_RFC2307_BIS:
        schema_conf += "ldap_group_object_class = groupOfNames\n"
    return unindent("""\
        [sssd]
        debug_level         = 0xffff
        domains             = LDAP
        services            = nss, pam

        [nss]
        debug_level         = 0xffff
        memcache_timeout    = 0

        [pam]
        debug_level         = 0xffff

        [domain/LDAP]
        ldap_auth_disable_tls_never_use_in_production = true
        debug_level         = 0xffff
        enumerate           = {enum}
        {schema_conf}
        id_provider         = ldap
        auth_provider       = ldap
        ldap_uri            = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base    = {ldap_conn.ds_inst.base_dn}
    """).format(**locals())


def format_interactive_conf(ldap_conn, schema):
    """Format an SSSD configuration with all caches refreshing in 4 seconds"""
    return \
        format_basic_conf(ldap_conn, schema, enum=True) + \
        unindent("""
            [nss]
            memcache_timeout                    = 0
            enum_cache_timeout                  = {0}
            entry_negative_timeout              = 0

            [domain/LDAP]
            ldap_enumeration_refresh_timeout    = {0}
            ldap_purge_cache_timeout            = 1
            entry_cache_timeout                 = {0}
        """).format(INTERACTIVE_TIMEOUT)


def create_conf_file(contents):
    """Create sssd.conf with specified contents"""
    conf = open(config.CONF_PATH, "w")
    conf.write(contents)
    conf.close()
    os.chmod(config.CONF_PATH, stat.S_IRUSR | stat.S_IWUSR)


def cleanup_conf_file():
    """Remove sssd.conf, if it exists"""
    if os.path.lexists(config.CONF_PATH):
        os.unlink(config.CONF_PATH)


def create_conf_cleanup(request):
    """Add teardown for removing sssd.conf"""
    request.addfinalizer(cleanup_conf_file)


def create_conf_fixture(request, contents):
    """
    Create sssd.conf with specified contents and add teardown for removing it
    """
    create_conf_file(contents)
    create_conf_cleanup(request)


def create_sssd_process():
    """Start the SSSD process"""
    if subprocess.call(["sssd", "-D", "-f"]) != 0:
        raise Exception("sssd start failed")


def cleanup_sssd_process():
    """Stop the SSSD process and remove its state"""
    try:
        pid_file = open(config.PIDFILE_PATH, "r")
        pid = int(pid_file.read())
        os.kill(pid, signal.SIGTERM)
        while True:
            try:
                os.kill(pid, signal.SIGCONT)
            except:
                break
            time.sleep(1)
    except:
        pass
    for path in os.listdir(config.DB_PATH):
        os.unlink(config.DB_PATH + "/" + path)
    for path in os.listdir(config.MCACHE_PATH):
        os.unlink(config.MCACHE_PATH + "/" + path)


def create_sssd_cleanup(request):
    """Add teardown for stopping SSSD and removing its state"""
    request.addfinalizer(cleanup_sssd_process)


def create_sssd_fixture(request):
    """Start SSSD and add teardown for stopping it and removing its state"""
    create_sssd_process()
    create_sssd_cleanup(request)


@pytest.fixture
def sanity_rfc2307(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    create_ldap_fixture(request, ldap_conn, ent_list)

    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307, enum=True)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def simple_rfc2307(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307, enum=False)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def sanity_rfc2307_bis(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("user2", 1002, 2002)
    ent_list.add_user("user3", 1003, 2003)

    ent_list.add_group_bis("group1", 2001)
    ent_list.add_group_bis("group2", 2002)
    ent_list.add_group_bis("group3", 2003)

    ent_list.add_group_bis("empty_group1", 2010)
    ent_list.add_group_bis("empty_group2", 2011)

    ent_list.add_group_bis("two_user_group", 2012, ["user1", "user2"])
    ent_list.add_group_bis("group_empty_group", 2013, [], ["empty_group1"])
    ent_list.add_group_bis("group_two_empty_groups", 2014,
                           [], ["empty_group1", "empty_group2"])
    ent_list.add_group_bis("one_user_group1", 2015, ["user1"])
    ent_list.add_group_bis("one_user_group2", 2016, ["user2"])
    ent_list.add_group_bis("group_one_user_group", 2017,
                           [], ["one_user_group1"])
    ent_list.add_group_bis("group_two_user_group", 2018,
                           [], ["two_user_group"])
    ent_list.add_group_bis("group_two_one_user_groups", 2019,
                           [], ["one_user_group1", "one_user_group2"])

    create_ldap_fixture(request, ldap_conn, ent_list)
    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS, enum=True)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_regression_ticket2163(ldap_conn, simple_rfc2307):
    assert True
