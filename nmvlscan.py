#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Script - nmap scan for network hosts to search some vulnerabilities
For example - wannacry's vulnerability:
https://gist.github.com/Neo23x0/60268852ff3a5776ef66bc15d50a024a

"""
import nmvlscan_lib as lib  # my lib with diffrenent fuctions
from configparser import RawConfigParser # lib for config reading
from os import path
from sys import (exit, argv)
from netaddr import IPNetwork   # lib for host/network ip working
from subprocess import (Popen, PIPE)
# pip install dnspython
from dns import (resolver, reversename)
from tqdm import tqdm   # lib for progress bar
from time import sleep
from datetime import datetime

# config.ini file must be near the script!
# we check it:
if not (path.exists("config.ini") and path.isfile("config.ini")):
    lib.error_exit("There is no config.ini file there!")

# if it is, we parse config and read values
else:
    nmap_conf = RawConfigParser()
    nmap_conf.read("config.ini")

# if user forget ro enter ip or subnet
if len(argv) < 2:
    # we print help and exit
    lib.print_help()
    lib.error_exit("You forgot to specify the IP address!")

# check - first run or not.
flag = nmap_conf.get("files", "first_run_flag")

# If first - we need to check nmap version and download script in the folder
if lib.chk_first_run(flag):

    if not lib.chk_nmap(nmap_conf.get("nmap", "min_ver"), \
                 nmap_conf.get("script", "nmap_script_dir_v1"), \
                 nmap_conf.get("script", "nmap_script_dir_v1"), \
                 nmap_conf.get("script", "script_url"), \
                 nmap_conf.get("script", "nse_script_name")):

        lib.error_exit("Something went wrong... (")

# now, we have checked all conditions and can to scan host/network...
# nmap command for our scan (example):
#   nmap -sC -p445  -n --open --max-hostgroup 3 --max-parallelism 3 --max-rate 60 -d 5 --script smb-vuln-ms17-010.nse $HOST_ADDR 2>/dev/null

# so, let's build it:
scan_port = nmap_conf.get("nmap", "scan_port")
max_hostgroup = nmap_conf.get("nmap", "max_hostgroup")
max_parallelism = nmap_conf.get("nmap", "max_parallelism")
max_rate = nmap_conf.get("nmap", "max_rate")
debug = nmap_conf.get("nmap", "debug")
script_name = nmap_conf.get("script", "nse_script_name")

# geneate correct command with parameters from config.ini file
nmap_run_cmd = "nmap -sC -p%s  -n --open --max-hostgroup %s --max-parallelism %s --max-rate %s -d %s --script %s" % \
               (scan_port, max_hostgroup, max_parallelism, max_rate, debug, script_name)

# let's scan and create dictionary with results:
print("Start scanning...")
scan_results = dict()

grep_sting = nmap_conf.get("search", "grep_string")

# calculate count of ip's addr to create progress bar
scan_network=IPNetwork(argv[1])
ip_count=len(list(scan_network))

# initiate progress bar
pbar = tqdm(total=ip_count)

# start scanning..
for ip in scan_network:
    host_scan_cmd = nmap_run_cmd + ' ' + str(ip) + ' 2>/dev/null | grep ' + grep_sting + ' | cut -f 2 -d ":"'
    host_scan_res = str(Popen(host_scan_cmd, shell=True, stdout=PIPE).communicate()[0][:-1])[2:][:-1]

    # config dns resolver
    dns_resolver = resolver.Resolver()
    dns_resolver.nameservers = [nmap_conf.get("dns", "primary_dns"), nmap_conf.get("dns", "secondary_dns")]

    # resolv name of host ip via DNS
    resolv_addr = reversename.from_address(str(ip))
    try:
        host_scan_name = str(dns_resolver.query(resolv_addr, "PTR")[0])
    except Exception:
        host_scan_name = "DNS query name does not exist"

    # add entry about host and scan result into dictionary
    scan_results[ip] = [host_scan_name, host_scan_res]
    pbar.update(1)

pbar.close()

sleep(1) # progress bar should have time to unsubscribe
print("Scan completed! \n Creating log...")

# get now time
now_time = datetime.now().strftime("%Y-%m-%d %H:%M")

# we finished scan network, let's create report!
log_filename = nmap_conf.get("files", "report_log_file_name") + '_' + now_time + '.log'
logfile = open(log_filename, 'w')
srch_message = nmap_conf.get("search", "status")

# initiate progress bar
pbar = tqdm(total=ip_count)

# start write scan log to file
for host in scan_results:
    if (srch_message in scan_results[host][1]):
        logfile.write("ip:%s | hostname:%s | status:%s \n" % (host, scan_results[host][0], scan_results[host][1] ))
    pbar.update(1)

logfile.close()
pbar.close()

sleep(1) # progress bar should have time to unsubscribe

print("All works were done! \n See %s for results" % log_filename)
exit(0)


