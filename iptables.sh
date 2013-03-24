#!/bin/bash

IPTABLES=$(which iptables)
MODPROBE=$(which modprobe)
ME=123.123.123.123
SSHPORT=22
#FTPPORT=21
#OVPNPORT=1194

$MODPROBE ip_conntrack
#$MODPROBE ip_conntrack_ftp
#$MODPROBE ip_nat_ftp
$MODPROBE ipt_connlimit
$MODPROBE ipt_recent

$IPTABLES -F
$IPTABLES -P INPUT DROP
$IPTABLES -P OUTPUT DROP
$IPTABLES -P FORWARD DROP

$IPTABLES -A INPUT -m state --state INVALID -j DROP
$IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -A OUTPUT -m state --state INVALID -j DROP
$IPTABLES -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

$IPTABLES -A INPUT -i lo -j ACCEPT
$IPTABLES -A OUTPUT -o lo -j ACCEPT

$IPTABLES -A INPUT -p tcp --dport $SSHPORT -m state --state NEW --syn -j ACCEPT
#$IPTABLES -A INPUT -p tcp --dport $FTPPORT -m state --state NEW --syn -j ACCEPT
#$IPTABLES -A INPUT -p tcp --dport $OVPNPORT -m state --state NEW --syn -j ACCEPT
$IPTABLES -A INPUT -p tcp --dport 80 -m state --state NEW --syn -j ACCEPT
$IPTABLES -A INPUT -p icmp --icmp-type echo-request -m limit --limit 60/minute --limit-burst 100 -j ACCEPT
$IPTABLES -A INPUT -p icmp --icmp-type echo-request -j DROP
$IPTABLES -A OUTPUT -p tcp --dport 22 -m state --state NEW --syn -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 80 -m state --state NEW --syn -j ACCEPT
$IPTABLES -A OUTPUT -p tcp --dport 443 -m state --state NEW --syn -j ACCEPT
$IPTABLES -A OUTPUT -p udp --dport 53 -m state --state NEW -j ACCEPT
$IPTABLES -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT

#$IPTABLES -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
#$IPTABLES -A INPUT -i tun+ -j ACCEPT
#$IPTABLES -A OUTPUT -o tun+ -j ACCEPT
#$IPTABLES -A FORWARD -i tun+ -o eth0 -j ACCEPT
#$IPTABLES -A FORWARD -i eth0 -o tun+ -j ACCEPT

$IPTABLES -I INPUT 1 -p tcp --dport 80 -m state --state NEW -m recent --name HTTPUSER --set
$IPTABLES -I INPUT 2 -p tcp --dport 80 -m state --state NEW -m recent --name HTTPUSER --update --seconds 5 --hitcount 16 -j DROP
$IPTABLES -I INPUT 1 -p tcp --dport 80 -m connlimit --connlimit-above 5 -j DROP
