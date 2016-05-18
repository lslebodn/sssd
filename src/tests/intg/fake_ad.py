#
# Fake Active directory based on OpenLDAP directory server
#
# Copyright (c) 2016 Red Hat, Inc.
# Author: Lukas Slebodnik <lslebodn@redhat.com>
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

import hashlib
import base64
import urllib
import time
import ldap
import os
import errno
import signal
import shutil
import sys
from util import *
from ds_openldap import DSOpenLDAP


def hash_password(password):
    """Generate userPassword value for a password."""
    salt = os.urandom(4)
    hash = hashlib.sha1(password)
    hash.update(salt)
    return "{SSHA}" + base64.standard_b64encode(hash.digest() + salt)


class FakeAD(DSOpenLDAP):
    """Fake Active Directory based on OpenLDAP directory server."""

    def __init__(self, dir, port, base_dn, admin_rdn, admin_pw):
        """
            Initialize the instance.

            Arguments:
            dir         Path to the root of the filesystem hierarchy to create
                        the instance under.
            port        TCP port on localhost to bind the server to.
            base_dn     Base DN.
            admin_rdn   Administrator DN, relative to BASE_DN.
            admin_pw    Administrator password.
        """
        super(FakeAD, self).__init__(dir, port, base_dn, admin_rdn, admin_pw)

    def _setup_config(self):
        """Setup the instance initial configuration."""

        #
        # Import ad schema
        #

        slapadd = subprocess.check_call(
            ["slapadd", "-F", self.conf_slapd_d_dir, "-b", "cn=config",
             "-l", "data/ad_schema.ldif"],
        )

    def setup(self):
        """Setup the instance."""
        ldapi_socket = self.run_dir + "/ldapi"
        self.ldapi_url = "ldapi://" + urllib.quote(ldapi_socket, "")
        self.url_list = self.ldapi_url + " " + self.ldap_url

        os.makedirs(self.conf_slapd_d_dir)
        os.makedirs(self.run_dir)
        os.makedirs(self.data_dir)

        super(FakeAD, self)._setup_config()
        self._setup_config()

        #
        # Start the daemon
        #
        super(FakeAD, self)._start_daemon()

        #
        # Relax requirement of surname attribute presence in person
        #
        modlist = [
            (ldap.MOD_DELETE, "olcObjectClasses",
             "{4}( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top "
             "STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ "
             "telephoneNumber $ seeAlso $ description ) )"),
            (ldap.MOD_ADD, "olcObjectClasses",
             "{4}( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top "
             "STRUCTURAL MUST ( cn ) MAY ( sn $ userPassword $ "
             "telephoneNumber $ seeAlso $ description ) )"),
        ]
        ldap_conn = ldap.initialize(self.ldapi_url)
        ldap_conn.simple_bind_s(self.admin_rdn + ",cn=config", self.admin_pw)
        ldap_conn.modify_s("cn={0}core,cn=schema,cn=config", modlist)
        ldap_conn.unbind_s()

        # restart daemon for reloading schema
        super(FakeAD, self)._stop_daemon()
        super(FakeAD, self)._start_daemon()

        #
        # Add data
        #
        ldap_conn = ldap.initialize(self.ldap_url)
        ldap_conn.simple_bind_s(self.admin_dn, self.admin_pw)
        ldap_conn.add_s(self.base_dn, [
            ("objectClass", ["dcObject", "organization"]),
            ("o", "Example Company"),
        ])
        ldap_conn.add_s("cn=Manager," + self.base_dn, [
            ("objectClass", "organizationalRole"),
        ])
        for ou in ("Users", "Groups", "Netgroups", "Services", "Policies"):
            ldap_conn.add_s("ou=" + ou + "," + self.base_dn, [
                ("objectClass", ["top", "organizationalUnit"]),
            ])
        ldap_conn.unbind_s()

        # import data from real AD
        slapadd = subprocess.check_call(
            ["ldapadd", "-x", "-w", self.admin_pw, "-D",
             self.admin_dn, "-H", self.ldap_url,
             "-f", "data/ad_data.ldif"],
        )

    def teardown(self):
        """Teardown the instance."""
        super(FakeAD, self).teardown()
