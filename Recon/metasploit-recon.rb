;;;

RHOSTS='192.168.33.200-254'

db_nmap -sS -vvv -O $RHOSTS
use auxiliary/scanner/ftp/
run
use auxiliary/scanner/ssh/ssh_version
run
use auxiliary/scanner/rdp/ms12_020_check
run
