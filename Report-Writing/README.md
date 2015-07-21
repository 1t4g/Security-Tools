# Nessus Reporter
Python script to read a .nessus file and output a .csv file for mailmerging into our template.

v1.0 released
 - This is the first proper working version that will simply import into our reporting template.

To list all targets within a .nessus file: 
root@kali:~/nfiler# ./nfiler.py -i OSCP_SCan_2_claxir.nessus -t
  192.168.33.201
  [...]
  192.168.33.252
