# Vuln. Nmap scanner

Utility that allows you to scan a host/network for vulnerabilities using nmap and save the result to a file

## Getting Started

Download it, check/change config.ini and run it

### Prerequisites

You need to have installed the following packages to Python3:

```
pip3 install configparser
pip3 install dnspython
pip3 install netaddr
pip3 install wget
pip3 install tqdm
```

### Running

Check config.ini file:

```
[nmap]
min_ver=7.40
scan_port=445
max_hostgroup=1
max_parallelism=1
max_rate=60
debug=5

[script]
nse_script_name = smb-vuln-ms17-010.nse
script_url = https://github.com/cldrn/nmap-nse-scripts/blob/master/scripts/smb-vuln-ms17-010.nse

nmap_script_dir_v1 = /usr/share/nmap/scripts/
nmap_script_dir_v2 = /usr/local/share/nmap/scripts/

[files]
first_run_flag = /tmp/nmap_wc_fist_run.flag
report_log_file_name= nmap_scan

[dns]
primary_dns = 10.62.0.4
secondary_dns = 10.62.0.5

[search]
grep_string = State:
status = VULNERABLE
```

And change it as desired for Your task


## Running 

To start it's very simple - call the Python3 interpreter, provide the script name and Ip address of the host or network

```
python3 nmvlscan.py 10.62.0.0/19
```

### Reading logs

In your directory, after the test, the script creates a log file with a time stamp of the scan. The file format is as follows:

```
ip:127.0.0.1 | hostname: hostname.local | status: VULNERABLE 
```

