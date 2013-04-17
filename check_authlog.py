#!/usr/bin/env python

# This is a Nagios plugin that checks auth.log for suspicious activity.
# In particular, it looks for abnormal escalation of privileges and root logins from unauthorized locations.
# It retains the last time stamp to speedup the check process

# The script returns: UNKNOWN for state errors (cannot open or save state file), WARNING for whitelisted alerts,
# and CRITICAL for full fledged alerts.

# It needs to have a directory writeable under /var/lib/nagios, otherwise it will not be able to save the state...

import getopt
import sys
from datetime import datetime, timedelta
import re

# Nagios return codes
nagios_codes = dict(OK=0, WARNING=1, CRITICAL=2, UNKNOWN=3, DEPENDENT=4)

# Location of the state file
# this is a text file with a timestamp, nothing else...
# STATE_FILE = '/var/lib/nagios/check_authlog_state'
DEFAULT_LOOKBACK = 15
LOG_FILENAME = '/var/log/auth.log'

# IP whitelist: these IPs generate warnings only...
IP_WHITELIST = ['10.200.54.100']

# usage string
usage = """Usage:
  -l, --lookback: Takesa numeric parameters and looks back 'n' minutes. If not specified, looks back 15 minutes.
                  Use 0 to look up the whole file.
  -h, --help:     Prints this message. Ignore all other options.
"""

# def nslookup(ip):
#    try:
#        import socket
#        return socket.gethostbyaddr(ip)[0]
#    except:
#        return None
#        return 'Not able to resolve name'

def exit(status, message):
    print status + ': ' + '; '.join(message)
    sys.exit(nagios_codes[status])

def process_log(logfilename, cutoff=DEFAULT_LOOKBACK):
    # return 2 sets of IPS and UIDS with suspicious activity
    # logfilename is the log file to open, and cutoff is the number of minutes the script should look into
    IPS = set()
    WIPS = set()
    UIDS = set()
    
    now = datetime.now()
    cutoffdatetime = now - timedelta(minutes=cutoff)
    thisyear = now.year

    # matcher1 macthes root logins. Returns a (timestamp, IP) tuple
    # matcher2 matches escalations to root from normal users. Returns a (timestamp, User ID) tuple. 
    matcher1 = re.compile('^(\w{3}\s+\d{1,2}\s\d{2}\:\d{2}\:\d{2}).+Accepted password for root from ((?:\d{1,3}\.){3}\d{1,3}).+$')
    # matcher2 = re.compile('^(\w{3}\s+\d{1,2}\s\d{2}\:\d{2}\:\d{2}).+sudo.+session opened for user root by \(uid\=(\d+)\)$')
    matcher2 = re.compile('^(\w{3}\s+\d{1,2}\s\d{2}\:\d{2}\:\d{2}).+session opened for user root by \(uid\=(\d+)\)$')
    
    # with open('./t.log', 'r') as f:
    with open('/var/log/auth.log', 'r') as f:
        for line in f:
            match = matcher1.search(line)
            if match:
                # quick hack, since the auth.log line does not contain the year, so we add it ourselves...
                t = datetime.strptime("%s %s" % (thisyear, match.groups()[0]), '%Y %b %d %H:%M:%S')
                if t > cutoffdatetime or cutoff == 0:
                    ip = match.groups()[1]
                    if ip in IP_WHITELIST:
                        WIPS.add(ip)
                    else:
                        IPS.add(ip)
            match = matcher2.search(line)
            if match:
                t = datetime.strptime("%s %s" % (thisyear, match.groups()[0]), '%Y %b %d %H:%M:%S')
                if t > cutoffdatetime or cutoff == 0:
                    UIDS.add(match.groups()[1])
    
    return IPS, WIPS, UIDS, now, cutoffdatetime

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "l:h", ["lookback", "help"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print str(err)  # will print something like "option -a not recognized"
        print usage
        sys.exit(10)
    lookback = DEFAULT_LOOKBACK
    for o, a in opts:
        if o in ("-h", "--help"):
            print usage
            sys.exit()
        elif o in ("-l", "--lookback"):
            try:
                lookback = int(a)
            except:
                lookback = DEFAULT_LOOKBACK
        else:
            assert False, "unhandled option"

    try:
        IPS, WIPS, UIDS, now, then = process_log(LOG_FILENAME, lookback)
        UIDS.discard('0')  # dont want the '0' notifications...
        status = 'OK'
        if now == then:
            results = ['Processing events for entire log']
        else:
            results = ['Processing events from %s to %s' % (then.isoformat(), now.isoformat())]
        if len(WIPS) != 0:
            status = 'WARNING'
            results.append('Whitelisted Root login from the following IPs: %s' % ','.join(WIPS))
        if len(IPS) != 0:
            status = 'CRITICAL'
            results.append('Root login from the following IPs: %s' % ','.join(IPS))
        if len(UIDS) != 0:
            status = 'CRITICAL'
            results.append('Root escalation from the following UIDs: %s' % ','.join(UIDS))
        if len(results) == 1:
            results.append('No events to report !')
    except Exception as e:
        results = ['Error processing the log file (%s)' % str(e)]
        status = 'UNKNOWN'
        exit(status, results)
    
    # sdfsdfsdf

    exit(status, results)

if __name__ == "__main__":
    main()
