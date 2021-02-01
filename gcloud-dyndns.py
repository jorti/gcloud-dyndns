#!/usr/bin/python3

"""
Copyright 2021 Juan Orti Alcaine <jortialc@redhat.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import sys
import argparse
import yaml
import ipaddress
import netifaces
from google.cloud import dns
from google.oauth2 import service_account


class DnsRecord():
    def __init__(self, hostname, address, type, ttl, gcp_client):
        self.hostname = hostname
        self.type = type
        self.address = address
        self.ttl = ttl
        self.gcp_client = gcp_client
        self.gcp_zone = self._get_gcp_zone()
        self.gcp_recordset = self._get_gcp_recordset()

    def _get_gcp_zone(self):
        zones = self.gcp_client.list_zones()
        for zone in zones:
            if zone.dns_name == self.base_domain() + '.':
                return zone

    def _get_gcp_recordset(self):
        records = self.gcp_zone.list_resource_record_sets()
        for record in records:
            if record.name == self.record_set() and record.record_type == self.type:
                return record

    def gcp_update(self):
        changes = self.gcp_zone.changes()
        if self.gcp_recordset and self.gcp_recordset.rrdatas[0] == str(
                self.address) and self.gcp_recordset.ttl == self.ttl:
            print("OK: %30s %6s %4s %s" % (
                self.gcp_recordset.name, self.gcp_recordset.ttl, self.gcp_recordset.record_type,
                self.gcp_recordset.rrdatas[0]))
            return
        if self.gcp_recordset:
            print("Deleting {} record {} -> {}".format(self.gcp_recordset.record_type, self.gcp_recordset.name,
                                                       self.gcp_recordset.rrdatas[0]))
            changes.delete_record_set(self.gcp_recordset)
        new_record = self.gcp_zone.resource_record_set(self.record_set(), self.type,
                                                       self.ttl, [str(self.address), ])
        print("Adding {} record {} -> {}".format(new_record.record_type, new_record.name, new_record.rrdatas[0]))
        changes.add_record_set(new_record)
        changes.create()

    def base_domain(self) -> str:
        return '.'.join(self.hostname.split('.')[-2:])

    def record_set(self) -> str:
        return self.hostname + '.'

    def __str__(self):
        return "{} {}".format(self.type, self.hostname)

    def __repr__(self):
        return "DnsRecord(hostname={}, address={}, type={})".format(self.hostname, self.address, self.type)


def get_ipv4_address(source: dict) -> ipaddress.IPv4Address:
    if source["type"] == "interface":
        addresses = netifaces.ifaddresses(source["interface"])[netifaces.AF_INET]
        return ipaddress.ip_address(addresses[0]["addr"])
    if source["type"] == "file":
        with open(source["file"], "r") as f:
            content = f.readline().rstrip()
        return ipaddress.ip_address(content)
    print("ERROR: Unknown IPv4 source type'{}'".format(source["type"]))
    sys.exit(1)


def get_ipv6_prefix(source: dict) -> ipaddress.IPv6Network:
    if source["type"] == "interface":
        addresses = netifaces.ifaddresses(source["interface"])[netifaces.AF_INET6]
        for address in addresses:
            prefix = address["netmask"].split('/')[1]
            net = ipaddress.ip_network(address["addr"] + '/' + prefix, strict=False)
            if net.is_global and net.prefixlen <= 64:
                return net
    if source["type"] == "file":
        with open(source["file"], "r") as f:
            content = f.readline().rstrip()
        return ipaddress.ip_network(content)
    print("ERROR: Unknown IPv6 source type '{}'".format(source["type"]))
    sys.exit(1)


def calculate_ipv6_address(prefix: ipaddress.IPv6Network, subnet_hint, host_addr) -> ipaddress.IPv6Address:
    if prefix.prefixlen < 64:
        subnets = list(prefix.subnets(new_prefix=64))
        target_subnet = subnets[int(str(subnet_hint), 16)]
    else:
        print("WARNING: IPv6 Prefix length is {}, ignoring ipv6_subnet_hint".format(prefix.prefixlen))
        target_subnet = prefix
    target_address = target_subnet[int(str(host_addr), 16)]
    return target_address


parser = argparse.ArgumentParser(description='Google cloud DynDNS')
parser.add_argument("--conf-file", "-c", default="/etc/gcloud-dyndns.yml", help="Configuration file")
args = parser.parse_args()
with open(args.conf_file, 'r') as conf_file:
    conf = yaml.load(conf_file, Loader=yaml.SafeLoader)

if "ipv4" in conf["sources"]:
    ipv4_address = get_ipv4_address(conf["sources"]["ipv4"])
    print("Discovered IPv4 address: {}".format(ipv4_address))
else:
    ipv4_address = None
if "ipv6" in conf["sources"]:
    ipv6_prefix = get_ipv6_prefix(conf["sources"]["ipv6"])
    print("Discovered IPv6 prefix: {}".format(ipv6_prefix))
else:
    ipv6_prefix = None

gcp_credentials = service_account.Credentials.from_service_account_file(conf["gcp"]["credentials_file"])
gcp_client = dns.Client(project=conf["gcp"]["project"], credentials=gcp_credentials)

# Create DnsRecords
dns_records = []
for dns_record in conf["dns_records"]:
    if dns_record["ipv4"] and ipv4_address:
        dns_records.append(DnsRecord(dns_record["hostname"], ipv4_address, "A", conf["global"]["ttl"], gcp_client))
    if dns_record["ipv6"] and ipv6_prefix:
        ipv6_address = calculate_ipv6_address(ipv6_prefix, dns_record["ipv6_subnet_hint"], dns_record["ipv6_host_addr"])
        dns_records.append(DnsRecord(dns_record["hostname"], ipv6_address, "AAAA", conf["global"]["ttl"], gcp_client))

# Update
for dns_record in dns_records:
    dns_record.gcp_update()

print("Goodbye")
