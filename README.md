# ipRangeGenerator

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
usage: ipRangeGenerator.py [-h] (-lr LOWER_RANGE -ur UPPER_RANGE | -lr LOWER_RANGE -r RANGE_COUNT | -cidr CIDR) [-o OUTPUT]

options:
  -h, --help           show this help message and exit
  -cidr                CIDR notation (e.g., 192.168.1.0/24)
  -lr, --lower-range   Start IP of range (e.g., 192.168.1.1)
  -ur, --upper-range   End IP of range (e.g., 192.168.1.100)
  -r, --range-count    Number of IPs to generate from start IP (e.g., 520)
  -o, --output         Output filename (e.g., ips.txt)
```

# Usage

```
# python ipRangeGenerator.py -cidr "127.0.0.1/8" -o ips.txt  
[+] Generating IPs for network 127.0.0.1/8  
[+] Output file: ips.txt  
[+] Generating IPs: Completed! 16,777,214 IPs generated in ips.txt  
[+] Progress: 100%   
```
