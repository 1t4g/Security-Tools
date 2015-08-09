#!/bin/bash
#
# Documentation: Redteam Laptop Build
# Author: Peter Bassill
# Version 1.1

HOSTNAME = "red"

clear
i=0

echo "[$i] Setting up the system."

hostname $HOSTNAME
echo $HOSTNAME > /etc/hostname
domainname pb.hedgehogsecurity.co.uk
echo 127.0.0.1 $HOSTNAME $HOSTNAME.pb.hedgehogsecurity.co.uk >> /etc/hosts
echo hedgehogsecurity.co.uk > /etc/domainname
((i++))


# Update the system
echo "[$i] Updating the core system."
apt-get update && apt-get upgrade -y
apt-get install unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades
((i++))

# Adding core packages
echo "[$i] Adding core packages."
apt-get install mono-complete keepass2 openvpn build-essential libreadline-dev libssl-dev libpq5 libpq-dev libreadline5 libsqlite3-dev libpcap-dev openjdk-7-jre git-core autoconf postgresql pgadmin3 curl zlib1g-dev libxml2-dev libxslt1-dev vncviewer libyaml-dev curl zlib1g-dev
(($i++))

# Add banner
echo "[$i] Adding Banners."
echo " _____           _       ___   __  __    ____            _   _ " > /etc/banner
echo "|  ___|   _  ___| | __  / _ \ / _|/ _|  / ___|   _ _ __ | |_| |" >> /etc/banner
echo "| |_ | | | |/ __| |/ / | | | | |_| |_  | |  | | | | '_ \| __| |" >> /etc/banner
echo "|  _|| |_| | (__|   <  | |_| |  _|  _| | |__| |_| | | | | |_|_|" >> /etc/banner
echo "|_|   \__,_|\___|_|\_\  \___/|_| |_|    \____\__,_|_| |_|\__(_)" >> /etc/banner
echo "                                                               " >> /etc/banner
echo "This system is monitored, there is no anonymity here" >> /etc/banner
echo "No unauthorised users. Now, if you are not supposed to be here..." >> /etc/banner
echo "Fuck Off!" >> /etc/banner
echo "" >> /etc/banner
cp /etc/banner /etc/motd /etc/issue.net
(($i++))

# Sort the DNS servers
echo "[$i] Configure DNS"
cat /dev/null > /etc/resolvconf/resolv.conf.d/head
cat /dev/null > /etc/resolvconf/resolv.conf.d/base
cat /dev/null > /etc/resolvconf/resolv.conf.d/tail
echo "nameserver 8.8.8.8" >> /etc/resolvconf/resolv.conf.d/base
echo "nameserver 8.8.4.4" >> /etc/resolvconf/resolv.conf.d/base
resolvconf -u
(($i++))

# Sort SSH
echo "[$i] /etc/ssh/sshd_config"
bash -c "echo $'\n'## Groups allowed to connect$'\n'AllowGroups admins >> /etc/ssh/sshd_config"
sed -i 's/^LoginGraceTime 120/LoginGraceTime 20/' /etc/ssh/sshd_config
sed -i 's/^PermitRootLogin without-password/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
bash -c "echo ClientAliveInterval 900 >> /etc/ssh/sshd_config"
bash -c "echo ClientAliveCountMax 0 >> /etc/ssh/sshd_config"
bash -c "echo PermitUserEnvironment no >> /etc/ssh/sshd_config"
bash -c "echo Ciphers aes128-ctr,aes192-ctr,aes256-ctr >> /etc/ssh/sshd_config"
bash -c "echo MACs hmac-sha1,hmac-ripemd160 >> /etc/ssh/sshd_config"
bash -c "Banner /etc/issue.net >> /etc/ssh/sshd_config"
bash -c "echo AllowTcpForwarding no >> /etc/ssh/sshd_config"
/etc/init.d/ssh restart
service ssh restart
((i++))

# Install Metasploit
echo "[$i] Installing Metasploit."
git clone git://github.com/sstephenson/rbenv.git .rbenv
echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(rbenv init -)"' >> ~/.bashrc
exec $SHELL

git clone git://github.com/sstephenson/ruby-build.git ~/.rbenv/plugins/ruby-build
echo 'export PATH="$HOME/.rbenv/plugins/ruby-build/bin:$PATH"' >> ~/.bashrc

# sudo plugin so we can run Metasploit as root with "rbenv sudo msfconsole" 
git clone git://github.com/dcarley/rbenv-sudo.git ~/.rbenv/plugins/rbenv-sudo

exec $SHELL

rbenv install 2.1.6
rbenv global 2.1.6
ruby -v

mkdir ~/Development
cd ~/Development
svn co https://svn.nmap.org/nmap
cd nmap
./configure
make
sudo make install
make clean

