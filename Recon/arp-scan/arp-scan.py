import re
from subprocess import CalledProcessError, check_output as echo
from sys import platform
from socket import gethostbyaddr

# Config
IGNORE_BROADCAST = True
LOOKUP_HOSTNAMES = True

def get_host(ip):
    try:
        return gethostbyaddr(ip)[0]
    except:
        return '(timed out)'

if 'win' in platform:

    ARP_CM = ["arp", "-a"]
    ARP_IF = r"Interface: ((?:\d+.)+\d)"
    ARP_IP = r"((?:\d+\.){3}\d+)\s+((?:\w+-)+\w+)\s+(\w+)"

    TABLE_FMT = [
        '+-----------------+-------------------+------------+',
        '| IP              | MAC               | Allocation |',
        '|-----------------|-------------------|------------|',
    ]
    
    network, interface = {}, None
    for line in echo(ARP_CM).decode().splitlines():
        matches = re.search(ARP_IF, line)
        if matches:
            if interface:
                print(TABLE_FMT[0])
            interface = matches.group(1)
            print(interface)
            print('\n'.join(TABLE_FMT))
            
        matches = re.search(ARP_IP, line)
        if IGNORE_BROADCAST and '255' in line:
            continue
        if matches:
            ip, mac, alloc = matches.groups()
            print('| %15s | %17s | %10s | ' % (ip, mac, alloc), end='')

            hostname = get_host(ip) if LOOKUP_HOSTNAMES else ''
            print(hostname)

            entry = (hostname, ip, mac, alloc)
            if interface in network:
                network[interface] += [entry]
            else:
                network[interface] = [entry]

    if interface:
        print(TABLE_FMT[0])