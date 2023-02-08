# bruteforce_defense
Defending against select bruteforce attacks.

Situation:
    Linux machine on the perimeter
    Services involving auth are enabled

Requirements:
    syslog-ng/rsyslogd logging everything (or at least the bits you want to fire on)
    sudo access
    iptables/ebtables installed
    SEC (https://simple-evcorr.github.io/) installed

SEC monitors log files like so:
~~~
    /opt/bin/sec --conf=/etc/sec.conf --input=/var/log/messages --detach --pid=/run/sec.pid
~~~
For dropping ssh brute force attempts:
~~~
    sec.conf:
        type=Single
        ptype=RegExp
        pattern=Failed password for invalid user \S+ from ([\d.]+) port \d+ ssh2
        desc=ssh brute for user from $1
        action=shellcmd /opt/bin/blockssh $1

        type=Single
        ptype=RegExp
        pattern=Failed password for root from ([\d.]+) port \d+ ssh2
        desc=ssh brute for root from $1
        action=shellcmd /opt/bin/blockssh $1

    blockssh script:
        #!/bin/bash
        IPTABLES=/usr/sbin/iptables 
        EXTIF="<your_network_interface>"
        sudo $IPTABLES -I INPUT -i $EXTIF -m comment --comment "SSH Block" -s $1 -j DROP 
~~~
    example:
        Feb  8 10:37:23 sshd[2478723]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.227.194.176  user=root
        Feb  8 10:37:24 sshd[2478723]: Failed password for root from 192.227.194.176 port 42462 ssh2
        Feb  8 10:37:25 sudo:     root : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/iptables -I INPUT -i <your_network_interface> -m comment --comment SSH Block -s 192.227.194.176 -j DROP


For dropping smtp auth brute force attempts:
~~~
    sec.conf:
        type=SingleWithThreshold
        ptype=RegExp
        pattern=lost connection after AUTH from \S+\[([\d.]+)\]
        desc=Lost connection after connect 1m from $1
        action=shellcmd /opt/bin/blockemail $1
        window=3600
        thresh=1

    blockemail script:
        #!/bin/bash
        IPTABLES=/usr/sbin/iptables
        EXTIF="<your_network_interface>"
        sudo $IPTABLES -I INPUT -i $EXTIF -m comment --comment "Email Block" -s $1 -p tcp --dport 25 -j DROP

    example:
        Feb  8 15:07:58 postfix/smtpd[2522254]: connect from unknown[59.60.121.38]
        Feb  8 15:08:00 postfix/smtpd[2522254]: Anonymous TLS connection established from unknown[59.60.121.38]: TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits)
        Feb  8 15:08:01 postfix/smtpd[2522254]: lost connection after AUTH from unknown[59.60.121.38]
        Feb  8 15:08:01 postfix/smtpd[2522254]: disconnect from unknown[59.60.121.38] ehlo=2 starttls=1 auth=0/1 commands=3/4
        Feb  8 15:08:01 sudo:     root : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/iptables -I INPUT -i <your_network_interface> -m comment --comment Email Block -s 59.60.121.38 -p tcp --dport 25 -j DROP
~~~

For dropping quick, large TCP portscans:
~~~
    sec.conf:
        type=SingleWithThreshold
        ptype=RegExp
        pattern=IN=[a-zA-Z0-9]+ OUT= MAC=[:a-zA-Z0-9]+ SRC=([.a-zA-Z0-9]+) DST=[.a-zA-Z0-9]+ LEN=[0-9]+ TOS=.x.. PREC=.x.. TTL=[0-9]+ ID=[0-9]+ PROTO=TCP SPT=[0-9]+ DPT=[0-9]+ WINDOW=[0-9]+ RES=0x00 SYN URGP=0
        desc=5 NEW SYN from any host $1
        action=shellcmd /opt/bin/blocksyn $1
        window=60
        thresh=5

        type=SingleWithThreshold
        ptype=RegExp
        pattern=IN=[a-zA-Z0-9]+ OUT= MAC=[:a-zA-Z0-9]+ SRC=([.a-zA-Z0-9]+) DST=[.a-zA-Z0-9]+ LEN=[0-9]+ TOS=.x.. PREC=.x.. TTL=[0-9]+ ID=[0-9]+ DF PROTO=TCP SPT=[0-9]+ DPT=[0-9]+ WINDOW=[0-9]+ RES=0x00 SYN URGP=0
        desc=5 NEW SYN DF from any host $1
        action=shellcmd /opt/bin/blocksyn $1
        window=60
        thresh=5

        type=SingleWithThreshold
        ptype=RegExp
        pattern=IN=[a-zA-Z0-9]+ OUT= MAC=[:a-zA-Z0-9]+ SRC=([.a-zA-Z0-9]+) DST=[.a-zA-Z0-9]+ LEN=[0-9]+ TOS=.x.. PREC=.x.. TTL=[0-9]+ ID=[0-9]+ DF PROTO=TCP SPT=[0-9]+ DPT=[0-9]+ WINDOW=[0-9]+ RES=0x00 CWR ECE SYN URGP=0
        desc=5 NEW CWR ECE SYN DF from any host $1
        action=shellcmd /opt/bin/blocksyn $1
        window=60
        thresh=5

    blocksyn script:
        #!/bin/bash
        IPTABLES=/usr/sbin/iptables 
        EXTIF="<your_network_interface>"
        sudo $IPTABLES -I INPUT -i $EXTIF -m comment --comment "SYN Block" -s $1 -j DROP 

    example:
        Feb  8 05:54:12 kernel: [949959.965835] NEW IN=<your_network_interface> OUT= MAC=<MAC> SRC=35.208.135.43 DST=<your_external_IP> LEN=60 TOS=0x08 PREC=0x00 TTL=119 ID=54158 DF PROTO=TCP SPT=62848 DPT=80 WINDOW=65320 RES=0x00 SYN URGP=0 
        Feb  8 05:54:13 kernel: [949960.966279] NEW IN=<your_network_interface> OUT= MAC=<MAC> SRC=35.208.135.43 DST=<your_external_IP> LEN=60 TOS=0x08 PREC=0x00 TTL=121 ID=41022 DF PROTO=TCP SPT=62846 DPT=80 WINDOW=65320 RES=0x00 SYN URGP=0 
        Feb  8 05:54:13 kernel: [949960.970016] NEW IN=<your_network_interface> OUT= MAC=<MAC> SRC=35.208.135.43 DST=<your_external_IP> LEN=60 TOS=0x08 PREC=0x00 TTL=119 ID=54159 DF PROTO=TCP SPT=62848 DPT=80 WINDOW=65320 RES=0x00 SYN URGP=0 
        Feb  8 05:54:15 kernel: [949963.015638] NEW IN=<your_network_interface> OUT= MAC=<MAC> SRC=35.208.135.43 DST=<your_external_IP> LEN=60 TOS=0x08 PREC=0x00 TTL=121 ID=41023 DF PROTO=TCP SPT=62846 DPT=80 WINDOW=65320 RES=0x00 SYN URGP=0 
        Feb  8 05:54:15 kernel: [949963.019301] NEW IN=<your_network_interface> OUT= MAC=<MAC> SRC=35.208.135.43 DST=<your_external_IP> LEN=60 TOS=0x08 PREC=0x00 TTL=119 ID=54160 DF PROTO=TCP SPT=62848 DPT=80 WINDOW=65320 RES=0x00 SYN URGP=0 
        Feb  8 05:54:15 sudo:     root : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/usr/sbin/iptables -I INPUT -i <your_network_interface> -m comment --comment SYN Block -s 35.208.135.43 -j DROP
~~~
