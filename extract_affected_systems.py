#!/usr/bin/python
#
# Copyright 2011 Giulio Fidente <gfidente@redhat.com>
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import xmlrpclib
import sys
from optparse import OptionParser

RHN_URL = "https://rhn.redhat.com/rpc/api"


def main():
 usage = "usage: %prog -c RH-ADVISORY:NAME -u USERNAME -p PASSWORD [-P]"
 version = "0.1"
 parser = OptionParser(usage=usage, version=version)
 parser.add_option("-a", action="store", dest="adv", help="Advisory Name (like RHSA-2012:0350)")
 parser.add_option("-u", action="store", dest="username", help="rhn username (must be an organization administrator)")
 parser.add_option("-p", action="store", dest="password", help="rhn password")
 parser.add_option("-P", action="store_true", dest="list_packages", help="also lists affected Packages")
 (options, args) = parser.parse_args()
 if options.adv != None and options.username != None and options.password != None:
  execute(options.username, options.password, options.adv, options.list_packages)
 else:
  parser.print_usage()


def login(username, password):
 client = xmlrpclib.Server(RHN_URL, verbose=0)
 sessionkey = client.auth.login(username, password)
 return client, sessionkey


def logout(client, sessionkey):
 client.auth.logout(sessionkey)


def getAdvisoryName(client, sessionkey, cve):
 cvedata = client.errata.findByCve(sessionkey, cve)
 if len(cvedata) == 0:
  advname = None
 else:
  advname = cvedata[0]['advisory_name']
 return advname


def getAffectedPackages(client, sessionkey, advname):
 packages = client.errata.listPackages(sessionkey, advname)
 return packages


def getAffectedSystems(client, sessionkey, advname):
 systems = client.errata.listAffectedSystems(sessionkey, advname)
 if len(systems) == 0:
  systems = None
 else:
  return systems


def execute(username, password, adv, list_packages):
 (client, sessionkey) = login(username, password)
 #advname = getAdvisoryName(client, sessionkey, cve)
 advname = adv
 if advname is None:
  print "Advisory not found"
  sys.exit(1)
 systems = getAffectedSystems(client, sessionkey, advname)
 if systems is None:
  print "No systems are currently affected"
  sys.exit(0)
 print "Systems list..."
 for system in systems:
  print system['system_name']
 if list_packages:
  packages = getAffectedPackages(client, sessionkey, advname)
  print "Packages list..."
  for package in packages:
   print package['package_name'] + "-" + package['package_version']
 logout(client, sessionkey)


if __name__ == "__main__":
 main()
