#!/bin/bash

# This is a Nagios script to check files against a hash
# The script returns: WARNING for cfg errors, CRITICAL for everything else...

NAGIOS_RETURN_OK=0
NAGIOS_RETURN_WARNING=1
NAGIOS_RETURN_CRITICAL=2
NAGIOS_RETURN_UNKNOWN=3
NAGIOS_RETURN_DEPENDENT=4

MD5CMD='/usr/bin/md5sum'
MD5CFG='/etc/check_filehash.conf'

if [[ ! -r "$MD5CFG" ]]
then
  echo "WARNING: Config file cannot be read ($MD5CFG)"
  exit $NAGIOS_RETURN_WARNING
fi

MD5OUTPUT=`md5sum -c $MD5CFG 2>&1`
#MD5OUTPUT=`md5sum -c $MD5CFG --quiet`
MD5EXITCODE=$?

echo $MD5EXITCODE

if [[ $MD5EXITCODE -eq 0 ]]
then
  echo "OK: All checksums fine"
  echo "$MD5OUTPUT"
  exit $NAGIOS_RETURN_OK
else
  echo "CRITICAL: Some (or all) checksums failed"
  echo "$MD5OUTPUT"
  exit $NAGIOS_RETURN_CRITICAL
fi
