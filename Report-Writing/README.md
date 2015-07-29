# Nessus Reporter
Python script to read a .nessus file and output a .csv file for mailmerging into our template.

FIXES
 - Risk Rating of 10.0 was coming out as Low, now fixed
 - Detection of published exploits now fixed and reporting correctly where there is a public exploit available
 
FEATURES
 - Added vulnerability publish date
 - Added output synopsis
 - Added validation of "futher info" (only works when online)

v1.0 released
 - This is the first proper working version that will simply import into our reporting template.

To list all targets within a .nessus file: 

     root@kali:~/nfiler# ./nfiler.py -i OSCP_SCan_2_claxir.nessus -t
     192.168.33.201
     [...]
     192.168.33.252

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

In the targets, you have: IP Address, Num of Vulns, Num of High, Num of Med, Num of Low, Num of Info, Num of Exploits.

To generate the CSV file:

    root@kali:~/nfiler# ./nfiler.py -i OSCP_SCan_2_claxir.nessus --csv r2.csv
    [*] Information extracted from:
            [+] OSCP_SCan_2_claxir.nessus
    [*] CSV delimiter used:                 ','
    [*] Total targets parsed:               41
    [*] Min CVSS filter applied:            4.0
    [*] Max CVSS filter applied:            10.0
    [*] Local vulnerabilities:              53
    [*] Remote vulnerabilities:             556
    [*] Total considered vulnerabilities:   2552

This will generate the CSV file of the name you specified with the "--CSV filename". The first row is the column headings.
