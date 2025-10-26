# IpRangeGenerator

A powerful Python tool for generating IP address ranges

# Features
- Support for CIDR notation and custom ranges
- Network and broadcast address calculation
- Generate IP lists to files

# Dependencies

```
pip3 install pwn
```

# Help panel

```
# python ipRangeGenerator.py -h
usage: ipRangeGenerator.py [-h] (-lr LOWER_RANGE -ur UPPER_RANGE | -cidr CIDR) [-o OUTPUT]

options:
  -h, --help           show this help message and exit
  -lr, --lower-range   Start IP of range (e.g., 192.168.1.1)
  -cidr                CIDR notation (e.g., 192.168.1.0/24)
  -ur, --upper-range   End IP of range (e.g., 192.168.1.100)
  -o, --output         Output filename (e.g., ips.txt)
```

# Usage

```
git clone https://github.com/Justice-Reaper/ipRangeGenerator.git  
cd ipRangeGenerator
python ipRangeGenerator.py -cidr "127.0.0.1/8" -o ips.txt  
[+] Generating IPs for network 127.0.0.1/8  
[+] Output file: ips.txt  
[+] Generating IPs: Completed! 16,777,214 IPs generated in ips.txt  
[+] Progress: 100%   
```
