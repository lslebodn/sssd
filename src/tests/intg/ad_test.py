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

if sys.version_info[0] > 2:
    LOCAL_PYEXECDIR = config.PY3EXECDIR
    LOCAL_PYDIR = config.PY3DIR
else:
    LOCAL_PYEXECDIR = config.PY2EXECDIR
    LOCAL_PYDIR = config.PY2DIR

for path in [LOCAL_PYEXECDIR, LOCAL_PYDIR]:
   if path not in sys.path:
       sys.path.insert(0, path)

import pysss_nss_idmap

LDAP_BASE_DN = "dc=example,dc=com"


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


def format_basic_conf(ldap_conn):
    """Format a basic SSSD configuration"""
    return unindent("""\
        [sssd]
        domains = FakeAD
        services = nss

        [nss]

        [pam]

        [domain/FakeAD]
        ldap_search_base = {ldap_conn.ds_inst.base_dn}
        ldap_referrals = false

        id_provider = ldap
        auth_provider = ldap
        chpass_provider = ldap
        access_provider = ldap

        ldap_uri = {ldap_conn.ds_inst.ldap_url}
        ldap_default_bind_dn = {ldap_conn.ds_inst.admin_dn}
        ldap_default_authtok_type = password
        ldap_default_authtok = {ldap_conn.ds_inst.admin_pw}

        ldap_schema = ad
        ldap_id_mapping = true
        ldap_idmap_default_domain_sid = S-1-5-21-1305200397-2901131868-73388776
        case_sensitive = False
    """).format(**locals())


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
def simple_ad(request, ldap_conn):
    create_ldap_fixture(request, ldap_conn)

    conf = format_basic_conf(ldap_conn)

    # Set domainID for fake AD domain
    sssd_cache_ldif = unindent("""\
        dn: cn=sysdb
        cn: sysdb
        description: base object
        version: 0.17
        distinguishedName: cn=sysdb

        dn: cn=FakeAD,cn=sysdb
        cn: FakeAD
        domainID: S-1-5-21-1305200397-2901131868-73388776
        distinguishedName: cn=FakeAD,cn=sysdb
    """)
    sssd_cache = config.DB_PATH + "cache_FakeAD.ldb"

    ldbadd = subprocess.Popen(
        ["ldbadd", "-H", config.DB_PATH + "/cache_FakeAD.ldb"],
        stdin=subprocess.PIPE, close_fds=True
    )
    ldbadd.communicate(sssd_cache_ldif)
    if ldbadd.returncode != 0:
        raise Exception("Failed to import initila data with ldbadd")

    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_regression_ticket2163(ldap_conn, simple_ad):
    user = 'user1_dom1-19661'
    user_id = pwd.getpwnam(user).pw_uid
    user_sid = 'S-1-5-21-1305200397-2901131868-73388776-82809'

    output = pysss_nss_idmap.getsidbyname(user)[user]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_USER
    assert output[pysss_nss_idmap.SID_KEY] == user_sid

    output = pysss_nss_idmap.getsidbyid(user_id)[user_id]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_USER
    assert output[pysss_nss_idmap.SID_KEY] == user_sid

    output = pysss_nss_idmap.getidbysid(user_sid)[user_sid]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_USER
    assert output[pysss_nss_idmap.ID_KEY] == user_id

    output = pysss_nss_idmap.getnamebysid(user_sid)[user_sid]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_USER
    assert output[pysss_nss_idmap.NAME_KEY] == user


def test_group_operations(ldap_conn, simple_ad):
    group = 'group3_dom1-17775'
    group_id = grp.getgrnam(group).gr_gid
    group_sid = 'S-1-5-21-1305200397-2901131868-73388776-82764'

    output = pysss_nss_idmap.getsidbyname(group)[group]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.SID_KEY] == group_sid

    output = pysss_nss_idmap.getsidbyid(group_id)[group_id]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.SID_KEY] == group_sid

    output = pysss_nss_idmap.getidbysid(group_sid)[group_sid]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.ID_KEY] == group_id

    output = pysss_nss_idmap.getnamebysid(group_sid)[group_sid]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.NAME_KEY] == group


def test_group_operations2(ldap_conn, simple_ad):
    # https://fedorahosted.org/sssd/ticket/3283
    # resolve group and also member of this group
    group = 'Domain Users'
    group_id = grp.getgrnam(group).gr_gid
    group_sid = 'S-1-5-21-1305200397-2901131868-73388776-513'

    user = 'user1_dom1-19661'
    user_id = pwd.getpwnam(user).pw_uid
    user_sid = 'S-1-5-21-1305200397-2901131868-73388776-82809'

    # it will fail with case insensitive domain
    # https://fedorahosted.org/sssd/ticket/3284
    output = pysss_nss_idmap.getsidbyname(group)[group]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.SID_KEY] == group_sid

    output = pysss_nss_idmap.getsidbyid(group_id)[group_id]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.SID_KEY] == group_sid

    output = pysss_nss_idmap.getidbysid(group_sid)[group_sid]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.ID_KEY] == group_id

    output = pysss_nss_idmap.getnamebysid(group_sid)[group_sid]
    assert output[pysss_nss_idmap.TYPE_KEY] == pysss_nss_idmap.ID_GROUP
    assert output[pysss_nss_idmap.NAME_KEY] == group.lower()
