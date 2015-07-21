#!/bin/bash
#
# Documentation: Secure build script
# Author: Peter Bassill
# Version: 1.8.1

SSH_GRPS="sudo"
VERBOSE="N"
CHANGEME=""		# Sanity check that stupid isnt at the keyboard
EVASIVE="https://raw.githubusercontent.com/pbassill/secure-ubuntu/master/evasive.conf"
SECURITY="https://raw.githubusercontent.com/pbassill/secure-ubuntu/master/apache-security.conf"

clear

RINPUT=`openssl rand -hex 3`

if [[ $VERBOSE == "Y" ]];
	then
		APTFLAGS="--assume-yes"
	else
		APTFLAGS="--quiet=2 --assume-yes"
fi

APT="apt-get $APTFLAGS"

if [[ $CHANGEME == "" ]];
	then
		echo "Please read the code".
		echo
		exit
fi

if ! [[ `id | grep sudo` || `id -u` = '0' ]]; 
	then
		echo "Not root and not in the sudo group. Exiting." 
		echo
		exit
fi

if [[ `id -u` = '0' ]];
	then
		SUDO=''
	else 
		SUDO='sudo'
fi

if ! [[ `lsb_release -i |grep 'Ubuntu'` ]];
	then
		echo "Ubuntu only. Exiting."
		echo
		exit
fi

echo -n "If you understand what this script will do, please write $RINPUT here: "
read INPUT

if ! [[ "$INPUT" == "$RINPUT" ]];
	then
		echo "Turing test failed. Exiting."
		echo
		exit
	else
		echo "Let it begin."
fi

i="0"

echo "[$i] Adding Apache & PHP packages."
$SUDO $APT install apache2 php5 php5-cli libapache2-mod-security2 libapache2-mod-evasive

echo "[$i] Configuring Mod-Security."
$SUDO cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
$SUDO sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
$SUDO sed -i 's/SecRequestBodyAccess On/SecRequestBodyAccess Off/' /etc/modsecurity/modsecurity.conf
$SUDO ln -s /usr/share/modsecurity-crs/base_rules/modsecurity_crs_23_request_limits.conf /usr/share/modsecurity-crs/activated_rules
$SUDO ln -s /usr/share/modsecurity-crs/base_rules/modsecurity_crs_35_bad_robots.conf /usr/share/modsecurity-crs/activated_rules
$SUDO ln -s /usr/share/modsecurity-crs/base_rules/modsecurity_crs_42_tight_security.conf /usr/share/modsecurity-crs/activated_rules
$SUDO ln -s /usr/share/modsecurity-crs/base_rules/modsecurity_crs_45_trojans.conf /usr/share/modsecurity-crs/activated_rules
$SUDO echo "<IfModule security2_module>" >> /etc/apache2/conf-available/security.conf
$SUDO echo "Include /usr/share/modsecurity-crs/*.conf" >> /etc/apache2/conf-available/security.conf
$SUDO echo "Include /usr/share/modsecurity-crs/activated_rules/*.conf" >> /etc/apache2/conf-available/security.conf
$SUDO a2enmod headers
$SUDO a2enmod security2
((i++))

echo "[$i] Configuring Mod-Evasive."
$SUDO mkdir /var/log/apache2/mod_evasive && chmod 777 /var/log/apache2/mod_evasive
$SUDO bash -c "curl -s $EVASIVE > /etc/apache2/mods-available/evasive.conf"
((i++))

echo "[$i] Hardening Apache & PHP."
$SUDO bash -c "curl -s $SECURITY > /etc/apache2/conf-available/security.conf"
$SUDO sed -i 's/expose_php = On/expose_php = Off/' /etc/php5/apache2/php.ini
$SUDO sed -i 's/mail.add_x_header = On/mail.add_x_header = Off/' /etc/php5/apache2/php.ini
$SUDO sed -i 's/session.name = PHPSESSID/session.name = H2SESSID/' /etc/php5/apache2/php.ini
((i++))
