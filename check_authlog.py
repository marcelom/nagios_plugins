#! /usr/bin/python

import socket

def nslookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

# Reads /var/log/auth.log, looking for IPs that have generated more than N=10 invalid users or
# incorrect passwords and merges them in to the /etc/hosts.deny file.

from datetime import datetime

now = datetime.utcnow()
print
print 'Starting check-auth-log.py at', now

Nbad = 10

ipcounts = {}
f=open('/var/log/auth.log')
for line in f:
    if 'Invalid user' in line:
        # Aug 27 12:22:58 oven sshd[17384]: Invalid user olga from 72.9.253.90
        ip = line.strip().split(' ')[-1]
    elif 'Failed password' in line:
        # Aug 27 12:23:01 oven sshd[17387]: Failed password for invalid user boris from 72.9.253.90 port 59161 ssh2
        ip = line.strip().split(' ')[-4]
    else:
        continue
    ipcounts[ip] = ipcounts.get(ip, 0) + 1

# keep only the bad IPs.
ips=[ip for (ip,n) in ipcounts.items() if n > Nbad]

#for ip in ips:
#    print 'Adding to blacklist: %-16s' % ip, nslookup(ip) or ''
#for ip in ips:
#    print 'Blacklisting: "%s"' % ip

marker="### check-auth-log.py blacklist starts here -- don't add anything below here! ###"

f=open('/etc/hosts.deny')
# grab lines that we pass through unchanged
out = []
for line in f:
    if line.startswith(marker):
        break
    out.append(line.strip())

# grab existing lines...
for line in f:
    if line.startswith('#'):
        continue
    toks = line.strip().split(' ')
    if toks == ['']:
        continue
    if len(toks) < 2:
        print 'bad line:', toks
        continue
    ips.append(toks[1])

# sort by IP
ips = list(set(ips))
ips.sort(key=lambda(ip): sum([f*int(x) for (x,f) in zip(ip.split('.'),[2**i for i in [24,16,8,0]])]))

# White-list:
# these entries should only have to be temporary...
ips2 = []
for ip in ips:
    if ip in [
        '128.122.47.62', #  Rob Fergus
        '209.2.234.37', # Adam Greenberg
        '128.122.53.236', # astrometry.net
        '128.122.53.143', # broiler
        ]:
        print 'Whitelisting ', ip
        continue
    ips2.append(ip)
ips = ips2

do_name_lookups = False

ipstrings = []
for ip in ips:
    name = None
    if do_name_lookups:
        name = nslookup(ip)
        if name is not None:
            ipstrings.append('#   %s\n' % name)
    ipstrings.append('ALL: %s\n' % ip)
    print 'Blacklisting IP: %-16s' % ip, (name or '')

f=open('/etc/hosts.deny', 'w')
f.write('\n'.join(out) + '\n' + marker + '\n' + '\n'.join(ipstrings) + '\n')
f.close()
