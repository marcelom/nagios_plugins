#!/usr/bin/env python

# This is a Nagios script to check files againbst a hash
# Files & hashes are passed on as key-pair parameters. File and hash are separated by a ':'
# Example: check_filehash.py /etc/passwd:0123456789abcdef /etc/group:fedcba9876543210

# The script returns: UNKNOWN for parameter errors, WARNING for non-critical file
# read errors, and WARNING if the check fails.

import sys

nagios_codes = dict(OK=0, WARNING=1, CRITICAL=2, UNKNOWN=3, DEPENDENT=4)

def filehash(filePath):
    import hashlib
    BLOCK_SIZE = 8192
    h = hashlib.md5()
    with open(filePath, 'rb') as fh:
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
    if len(sys.argv) < 2:
        exit('UNKNOWN', "I need at least one file:hash pair to continue...")
    
    args = sys.argv[1:]
    
    results = ['Using MD5']
    status = 'OK'
    for keypair in args:
        try:
            path, expectedhash = keypair.split(':')
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
