#!/usr/bin/python3

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
            if zone.dns_name == self.domain() + '.':
                return zone

    def _get_gcp_recordset(self):
        records = self.gcp_zone.list_resource_record_sets()
        for record in records:
            if record.name == self.record_set() and record.record_type == self.type:
                return record

    def gcp_update(self):
        changes = self.gcp_zone.changes()
        if self.gcp_recordset and self.gcp_recordset.rrdatas[0] == str(self.address) and self.gcp_recordset.ttl == self.ttl:
            return
        if self.gcp_recordset:
            print("Deleting {} record {} -> {}".format(self.gcp_recordset.record_type, self.gcp_recordset.name, self.gcp_recordset.rrdatas[0]))
            changes.delete_record_set(self.gcp_recordset)
        new_record = self.gcp_zone.resource_record_set(self.record_set(), self.type,
                                                       self.ttl, [str(self.address), ])
        print("Adding {} record {} -> {}".format(new_record.record_type, new_record.name, new_record.rrdatas[0]))
        changes.add_record_set(new_record)
        changes.create()

    def domain(self):
        return '.'.join(self.hostname.split('.')[-2:])

    def record_set(self):
        return self.hostname + '.'

    def __str__(self):
        return self.hostname

    def __repr__(self):
        return "DnsRecord(hostname={}, address={}, type={})".format(self.hostname, self.address, self.type)


def get_ipv4_address(source):
    if source["type"] == "interface":
        addresses = netifaces.ifaddresses(source["interface"])[netifaces.AF_INET]
        return ipaddress.ip_address(addresses[0]["addr"])
    if source["type"] == "file":
        with open(source["file"], "r") as f:
            content = f.readline().rstrip()
        return ipaddress.ip_address(content)
    print("ERROR: Unknown IPv4 source type'{}'".format(source["type"]))
    sys.exit(1)


def get_ipv6_prefix(source):
    if source["type"] == "file":
        with open(source["file"], "r") as f:
            content = f.readline().rstrip()
        return ipaddress.ip_network(content)
    print("ERROR: Unknown IPv6 source type '{}'".format(source["type"]))
    sys.exit(1)


def calculate_ipv6_address(prefix, subnet_hint, host_addr):
    subnets = list(prefix.subnets(new_prefix=64))
    target_subnet = subnets[subnet_hint]
    target_address = target_subnet[int(str(host_addr), 16)]
    return target_address


parser = argparse.ArgumentParser(description='Google cloud DynDNS')
parser.add_argument("--conf-file", "-c", default="/etc/gcloud-dyndns.conf", help="Configuration file")
args = parser.parse_args()
with open(args.conf_file, 'r') as conf_file:
    conf = yaml.load(conf_file, Loader=yaml.SafeLoader)

if conf["sources"]["ipv4"]:
    ipv4_address = get_ipv4_address(conf["sources"]["ipv4"])
if conf["sources"]["ipv6"]:
    ipv6_prefix = get_ipv6_prefix(conf["sources"]["ipv6"])

gcp_credentials = service_account.Credentials.from_service_account_file(conf["gcp_dns"]["credentials_file"])
gcp_client = dns.Client(project=conf["gcp_dns"]["project"], credentials=gcp_credentials)

# Create DnsRecords
dns_records = []
for dns_record in conf["dns_records"]:
    if dns_record["ipv4"]:
        dns_records.append(DnsRecord(dns_record["hostname"], ipv4_address, "A", conf["global"]["ttl"], gcp_client))
    if dns_record["ipv6"]:
        ipv6_address = calculate_ipv6_address(ipv6_prefix, dns_record["ipv6_subnet_hint"], dns_record["ipv6_host_addr"])
        dns_records.append(DnsRecord(dns_record["hostname"], ipv6_address, "AAAA", conf["global"]["ttl"], gcp_client))

# Update
for dns_record in dns_records:
    dns_record.gcp_update()

print("Goodbye")
