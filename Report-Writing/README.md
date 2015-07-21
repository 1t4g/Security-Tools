# Nessus Reporter
Python script to read a .nessus file and output a .csv file for mailmerging into our template.

v1.0 released
 - This is the first proper working version that will simply import into our reporting template.

To list all targets within a .nessus file: 

```root@kali:~/nfiler# ./nfiler.py -i OSCP_SCan_2_claxir.nessus -t
  192.168.33.201
  [...]
  192.168.33.252```

To return a summary of the findings within a .nessus file:
root@kali:~/nfiler# ./nfiler.py -i OSCP_SCan_2_claxir.nessus -s

 ########  STATISTICS  ########
 Total targets,41
 Total vulns,2552
 High vulns,217
 Medium vulns,392
 Low vulns,84
 Info vulns,1859
 Available exploits,255

 ########    TARGETS   ########
 192.168.33.236,29,1,1,2,25,0
 192.168.33.249,20,0,0,2,18,0
 [...]
 192.168.33.218,30,1,1,0,28,1
 192.168.33.219,10,0,0,2,8,0
