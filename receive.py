from scapy.all import *

'''Sniff packets on particular port'''
p1=sniff(iface = "veth6", prn = lambda x: hexdump(x))

