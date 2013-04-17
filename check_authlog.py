#!/usr/bin/env python

# This is a Nagios plugin that checks auth.log for suspicious activity.
# In particular, it looks for abnormal escalation of privileges and root logins from unauthorized locations.
# It retains the last time stamp to speedup the check process

# The script returns: UNKNOWN for state errors (cannot open or save state file), WARNING for whitelisted alerts,
# and CRITICAL for full fledged alerts.

# It needs to have a directory writeable under /var/lib/nagios, otherwise it will not be able to save the state...

import getopt
import sys
from datetime import datetime
import re

# Nagios return codes
nagios_codes = dict(OK=0, WARNING=1, CRITICAL=2, UNKNOWN=3, DEPENDENT=4)

# Location of the state file
# this is a text file with a timestamp, nothing else...
STATE_FILE = '/var/lib/nagios/check_authlog_state'
LOG_FILENAME = '/var/log/auth.log'

# IP whitelist: these IPs generate warnings only...
IP_WHITELIST = ['10.200.54.100', '10.200.54.1', '127.0.0.1']

# usage string
usage = """Usage:
  -s, --state: Uses state file. Updates upon script end for future use.
               If not present, then processes the entire log file without any timestamp evaluation.
  -h, --help:  Prints this message. Ignore all other options.
"""

# def nslookup(ip):
#    try:
#        import socket
#        return socket.gethostbyaddr(ip)[0]
#    except:
#        return None
#        return 'Not able to resolve name'

def read_state(filename):
    # return ValueError if file is not properly formatted
    # read 100 bytes only, enough to get a timestamp and safe to avoid a DOS attach by
    # providing a huge state file...
    with open(filename, 'r') as f:
        a = f.readline(100)
    return datetime.strptime(a, '%Y %b %d %H:%M:%S')

def exit(status, message):
    print status + ': ' + '; '.join(message)
    sys.exit(nagios_codes[status])

def process_log(logfilename, cutoffdate):
    # return 2 sets of IPS and UIDS with suspicious activity
    # logfilename is the log file to open, and cutoffdate is the date
    # that it should start looking into
    IPS = set()
    WIPS = set()
    UIDS = set()
    
    thisyear = datetime.now().year

    # matcher1 macthes root logins. Returns a (timestamp, IP) tuple
    # matcher2 matches escalations to root from normal users. Returns a (timestamp, User ID) tuple. 
    matcher1 = re.compile('^(\w{3}\s+\d{1,2}\s\d{2}\:\d{2}\:\d{2}).+Accepted password for root from ((?:\d{1,3}\.){3}\d{1,3}).+$')
    matcher2 = re.compile('^(\w{3}\s+\d{1,2}\s\d{2}\:\d{2}\:\d{2}).+sudo.+session opened for user root by \(uid\=(\d+)\)$')
    
    # with open('./t.log', 'r') as f:
    with open('/var/log/auth.log', 'r') as f:
        for line in f:
            match = matcher1.search(line)
            if match:
                # quick hack, since the auth.log line does not contain the year, so we add it ourselves...
                t = datetime.strptime("%s %s" % (thisyear, match.groups()[0]), '%Y %b %d %H:%M:%S')
                ip = match.groups()[1]
                if ip in IP_WHITELIST:
                    WIPS.add(ip)
                else:
                    IPS.add(ip)
            match = matcher2.search(line)
            if match:
                t = datetime.strptime("%s %s" % (thisyear, match.groups()[0]), '%Y %b %d %H:%M:%S')
                UIDS.add(match.groups()[1])
    
    return IPS, WIPS, UIDS

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "sh", ["state", "help"])
    except getopt.GetoptError as err:
        # print help information and exit:
        print str(err)  # will print something like "option -a not recognized"
        print usage
        sys.exit(10)
    use_state = False
    for o, a in opts:
        if o in ("-h", "--help"):
            print usage
            sys.exit()
        elif o in ("-s", "--state"):
            use_state = True
        else:
            assert False, "unhandled option"

    status = 'OK'
    results = ['Processing for events after %s:' % '123']
    
    try:
        cutoffdate = read_state(STATE_FILE)
    except Exception as e:
        cutoffdate = None
        results.append('Error retrieving state (%s) - Processing from the beginning of file' % str(e))

    try:
        IPS, WIPS, UIDS = process_log(LOG_FILENAME, cutoffdate)
        if len(WIPS) != 0:
            status = 'WARNING'
            results.append('Whitelisted Root login from the following IPs: %s' % ','.join(WIPS))
        if len(IPS) != 0:
            status = 'CRITICAL'
            results.append('Root login from the following IPs: %s' % ','.join(IPS))
        if len(UIDS) != 0:
            status = 'CRITICAL'
            results.append('Root escalation from the following UIDs: %s' % ','.join(UIDS))
    except Exception as e:
        results.append('Error processing the log file (%s)' % str(e))
        status = 'UNKNOWN'
        exit(status, results)
    
    # sdfsdfsdf

    exit(status, results)

if __name__ == "__main__":
    main()
