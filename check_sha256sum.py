#!/usr/bin/env python

# This is a Nagios script to check files againbst an SHA256 hash
# The files are passed on as parameters on a comma separated list.

import sys

#Nagios exit codes
nagios_codes = dict(OK=0, WARNING=1, CRITICAL=2, UNKNOWN=3, DEPENDENT=4)

def filehash(filePath):
    import hashlib
    BLOCK_SIZE = 8192
    with open(filePath, 'rb') as fh:
        h = hashlib.sha256()
        while True:
            data = fh.read(BLOCK_SIZE)
            if not data:
                break
            h.update(data)
        return h.hexdigest()

def exit(status, message):
    print status + ': ' + message
    sys.exit(nagios_codes[status])

def main():
    if len(sys.argv) < 3:
        exit('UNKNOWN', "I need at least a file+hash pair to continue...")
    
    f = sys.argv[1:]
    l = len(f)

    if l % 2 != 0:
        exit('UNKNOWN', "You need to provide a full path+sha256 pair for each file")
    
    results = []
    status = 'OK'
    for i in range(0, l, 2):
        path = f[i]
        expectedhash = f[i + 1]
        try:
            hash = filehash(path)
            if hash == expectedhash:
                results.append("%s is OK" % path)
            else:
                status = 'CRITICAL'
                results.append("%s is NOT OK (expected %s, got %s)" % (path, expectedhash, hash))
        except Exception as e:
            status = 'WARNING'
            results.append("Error on %s (%s)" % (path, str(e)))
    
    exit(status, ', '.join(results))

if __name__ == "__main__":
    main()
