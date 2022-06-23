#!/bin/bash

########/nom interface ssid SECURE [channel] [interface2] #################
### you can also modify hostapd conf to use a bssid you want (under certain condition)
RED='\033[0;31m'
YEL='\033[1;33m'
NC='\033[0m'

iface2=0
usage="$YEL \nUsage : ./$(basename "$0") INTERFACE SSID ENCRYPTION CHANNEL [interface2] $NC\n
INTERFACE: network interface to use
SSID: name of your access point
ENCRYPTION: type of encryption
\t Allowed encryption:
\t\t -WPA : for wpa network
\t\t -WPA2: for wpa2 network
\t\t -OPN : for open network(no password)
CHANNEL: channel (between 1 to 13, default is 6)\n"

if [[ $# -lt 4 ]]; then
    echo -e "$usage"
    exit 2
fi

if [[ -n "$4" ]]; then
	if [[ "$4" -lt 1 ||  "$4" -gt 13 ]]; then
		echo -e "$RED Error: channel should be between 1..13\n $NC">&2
		exit 2
	fi
	channel="$4"
fi

if [[ ! $EUID -eq 0 ]]; then 
	echo -e "\n $RED Permission denied, You need to run as root $NC\n" >&2
	exit 2
fi

if [[ -n "$5" ]]; then
	if [[ "$5" == "$1" ]]; then
		echo -e "$RED Error: interface1 et interfae 2 must be different \n $NC">&2
		exit 2
	fi
	iface2="$5"
fi

ifaces=($(ls /sys/class/net/))
declare -p ifaces > /dev/null
iface="$1"
check=0
check2=0


#Check if right interface
for i in "${ifaces[@]}";do
	[[ "$i" == "$iface" ]] && check=1 && break
done
if [[ -n "$5" ]]; then
	for i in "${ifaces[@]}";do
		[[ "$i" == "$iface2" ]] && check2=1 && break
	done
fi
if [[ check -eq 0 ]]; then
	echo -e "$RED Error: Interface '$1' doesnt exist. Choose right the right one between $NC" >&2
	echo -e "$RED ${ifaces[*]} $NC" >&2
	echo -e ""
	exit 2
fi
if [[ -n "$5"  && check2 -eq 0 ]]; then
	echo -e "$RED Error: Interface '$5' doesnt exist. Choose right the right one between $NC" >&2
	echo -e "$RED ${ifaces[*]} $NC" >&2
	echo -e ""
	exit 2
fi

#check if dnsmasq, hostapd and iptables is installed, install if not
echo "[+] check if dnsmasq, hostapd and iptables are installed, install if not"
sleep 1
command -v hostapd > /dev/null 2>&1 || apt-get --yes install hostapd --fix-missing > /dev/null 
command -v dnsmasq > /dev/null 2>&1 || apt-get --yes install dnsmasq --fix-missing > /dev/null 
command -v iptables > /dev/null 2>&1 || apt-get --yes install iptables --fix-missing > /dev/null 

#kill any hostapd and dnsmasq process if run
sleep 0.5
pid_dnsmasq=$(ps -aux | grep dnsmasq  | cut -f1 -d"." | awk '{print $2}'| head -n1)
pid_hostapd=$(ps -aux | grep hostapd  | cut -f1 -d"." | awk '{print $2}'| head -n1)
sleep 0.5
kill "$pid_hostapd" 2> /dev/null
kill "$pid_dnsmasq" 2> /dev/null

#configure hostapd config file
echo "[+] Build hostapd config file"
sleep 1
hostapdConf="interface=$iface"
hostapdConf="$hostapdConf\ndriver=nl80211\nssid=$2\nhw_mode=g"
hostapdConf="$hostapdConf\nchannel=$channel\nmacaddr_acl=0\nignore_broadcast_ssid=0"

if [[ "$3" == "WPA" ]]; then 
	hostapdConf="$hostapdConf\nwpa=1"
	read -sp 'Wifi Password(more than 8 character): ' password   #silent or not ???-s
	while [[ ${#password} -lt 8 ]]; do
	echo ""
	read -sp 'BAd length, input wifi password(more than 8 character): ' password
	done
	hostapdConf="$hostapdConf\nwpa_passphrase=$password"
	hostapdConf="$hostapdConf\nwpa_key_mgmt=WPA-PSK\nwpa_pairwise=TKIP CCMP\nauth_algs=3"
	echo -e $hostapdConf > hostapd.conf
	echo ""
	echo "[+] Successful build hostapd config file(hostapd.conf)"                 
elif [[ "$3" == "WPA2" ]]; then 
	hostapdConf="$hostapdConf\nwpa=2"
	read -sp 'Wifi Password(more than 8 character): ' password   #silent or not ???-s
	while [[ ${#password} -lt 8 ]]; do
	echo ""
	read -sp 'BAd length, input wifi password(more than 8 character): ' password
	done
	hostapdConf="$hostapdConf\nwpa_passphrase=$password"
	hostapdConf="$hostapdConf\nwpa_key_mgmt=WPA-PSK\nwpa_pairwise=TKIP\nrsn_pairwise=CCMP\nauth_algs=3\n"
	echo -e $hostapdConf > hostapd.conf
	echo ""
	echo "[+] Successful build hostapd config file(hostapd.conf)" 
else
	hostapdConf="$hostapdConf\nauth_algs=1"
	echo -e $hostapdConf > hostapd.conf
	echo ""
	echo "[+] Successful build hostapd config file(hostapd.conf)"
fi

#configure dnsmasq config file
echo "[+] Build dnsmasq config file"
sleep 1
dnsConf="interface=$iface"
dnsConf="$dnsConf\ndhcp-range=10.0.0.10,10.0.0.250,255.255.255.0,12h\ndhcp-option=3,10.0.0.1"
dnsConf="$dnsConf\ndhcp-option=6,10.0.0.1"
#address=/#/10.0.0.1\naddress=/www.google.com/216.58.209.68"
echo -e $dnsConf > dnsmasq.conf
echo "[+] Successful build dnsmasqconfig file(dnsmasq.conf)"

#configure host file
echo '10.0.0.1 wifiportal' > hosts


#Flush iptables and configure nat for routing
echo "[+] Flush iptables"
sleep 1
iptables -F
iptables -t nat -F
if [[ -n "$5" ]];then
	echo "[+] Configure NAT and ip forwading"
	iptables -t nat -A POSTROUTING -o "$iface2" -j MASQUERADE
	iptables -A FORWARD -i "$iface2" -o "$iface" -m state --state RELATED,ESTABLISHED -j ACCEPT 
	iptables -A FORWARD -i "$iface" -o "$iface2" -j ACCEPT
	sysctl -w net.ipv4.ip_forward=1
fi

# give an adress for interface (to specify it as router)
echo "[+] Configure $iface adress"
sleep 1
ifconfig "$iface" 10.0.0.1


#prepare for lauchn dnsmasq
echo "[+] Prepare dnsmasq lauching"
sleep 1
service dnsmasq stop > /dev/null 2>&1
#kill dnsmasq or any service on port 53
pid=$(ss -lp "sport = :domain" | cut -f 2 -d, | grep -m1 pid | cut -f 2 -d=)  # cut -f for part et -d delimeter
pid2=$(sudo netstat -lntp | grep -w ':53' | cut -f1 -d "/" | cut -f2 -d "N" | cut -f2)
if [[ -n $pid ]]; then
	kill "$pid" 2> /dev/null
fi

if [[ -n $pid2 ]]; then
	kill "$pid2" 2> /dev/null
fi


#Now lauch service 
echo "[+] Launch dnsmasq"
sleep 1
lxterminal -e 'dnsmasq --no-daemon -C dnsmasq.conf -H hosts' &
pid_lx1="$!"
echo "[+] dnsmasq launched, pid=pid_dnsmasq"
sleep 0.5

echo "[+] Launch hostapd"
sleep 1
lxterminal -e  'hostapd hostapd.conf' &
pid_lx2="$!"
echo "[+] hostapd, launched, pid=pid_hostapd"
sleep 0.5
echo $pid_dnsmasq
echo $pid_hostapd

##exit function , run when cath SIGINT signal
function exitcorrect()
{
	#pid_dnsmasq=$(ps -aux | grep dnsmasq  | cut -f1 -d"." | awk '{print $2}'| head -n1)
	#pid_hostapd=$(ps -aux | grep hostapd  | cut -f1 -d"." | awk '{print $2}'| head -n1)
	sleep 0.5
	kill "$pid_lx1" 2> /dev/null
	sleep 0.5
	kill "$pid_lx2" 2> /dev/null
	sleep 1
	killall dnsmasq hostapd 2> /dev/null
	if [[ -n "$5" ]];then
		sysctl -w net.ipv4.ip_forward=0
	fi
	exit 0
	}

trap exitcorrect SIGINT
sleep 5d

