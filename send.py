from scapy.all import *

p1 = Ether(dst="aa:bb:cc:dd:ee:ff", src="aa:bb:cc:dd:ee:ff") / IP(src="10.0.1.1", dst="10.0.1.10") / TCP() / "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
p2 = Ether(dst="aa:bb:cc:dd:ee:ff", src="aa:bb:cc:dd:ee:ff") / IP(src="10.0.1.1", dst="10.0.1.20") / TCP() / "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
p3 = Ether(dst="aa:bb:cc:dd:ee:ff", src="aa:bb:cc:dd:ee:ff") / IP(src="10.0.1.1", dst="10.0.1.30") / TCP() / "cccccccccccccccccccccccccccccccccccccc"

for i in range(0, 9):
	sendp(p1, iface = "veth4")
	
for i in range(0, 1):
	sendp(p2, iface = "veth4")

for i in range(0, 13):
	sendp(p2, iface = "veth4")
	
for i in range(0, 7):
	sendp(p3, iface = "veth4")
	

for i in range(0, 10):
	sendp(p3, iface = "veth4")
