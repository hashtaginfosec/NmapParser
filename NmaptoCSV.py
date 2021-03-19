#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this output_file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License.

#Requires python-libnmap  --> pip install python-libnmap
#Other requirements:
# A targets.txt file that contains Subnets and names of those subnets (e.g., "192.168.1.0/24, GA DataCenter VLAN 1")




from libnmap.parser import NmapParser
import csv, argparse, sys
from netaddr import *

if not len(sys.argv) >= 2:
    print("You missed Nmap XML name.")
    print("Syntax: python NmaptoCSV.py filename.xml")
    sys.exit()
else:
    nmapResults = sys.argv[1]

csvFileName = sys.argv[1].split(".")[0] + ".csv"
print(csvFileName)

#Create a dictionary with CIDR and environment name as key:value pair
with open('targets.txt') as f:
  targets = dict(x.rstrip().split(":", 1) for x in f)

#CSV file that we'll write to
csvfile = open(csvFileName, 'w')
csvwriter = csv.writer(csvfile, dialect=csv.excel, quotechar='|', quoting=csv.QUOTE_MINIMAL)

#create variable to store parsed XML report in
nmap_report=NmapParser.parse_fromfile(nmapResults, data_type='XML')

#Write header row in CSV output
csvwriter.writerow(['IPv4', 'Hostname', 'Subnet', 'Environment', 'Port', 'State', 'Protocol', 'Service', 'Reason', 'Banner'])

for scanned_host in nmap_report.hosts:
    if scanned_host.is_up:
        ipv4 = scanned_host.ipv4
        #ipv6 = scanned_host.ipv6
        for key in targets.keys():
            if IPAddress(ipv4) in IPNetwork(key):
                subnet = str(key)
                environment = str(targets[key])
                break

        hostname = scanned_host.hostnames
        if scanned_host.os_fingerprinted is True and scanned_host.os_match_probabilities() is not None:
            operating_systems = scanned_host.os_match_probabilities()
            if len(operating_systems) > 0:
                os=operating_systems[0].name
        if scanned_host.scripts_results is not None:
            scriptResults = scanned_host.scripts_results

        for services in scanned_host.services:
            port = services.port
            state = services.state
            protocol = services.protocol
            banner = services.banner
            service = services.service
            reason = services.reason
            csvwriter.writerow([ipv4, hostname, subnet, environment, port, state, protocol, service, reason, banner])

csvfile.close()
