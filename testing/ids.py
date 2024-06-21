from scapy.all import *
import threading

incoming_interface = "eth0"

def ids(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 0:
            if packet[ICMP].id == 10 and packet[Raw].load:
                if packet[Raw].load != "abcdefghijklmnopqrstuvwxyz":
                    print(f"Malicious ICMP Packet Detected!")
                    print(f"Source IP: {packet[IP].src}")
                    print(f"Destination IP: {packet[IP].dst}")
                    print(f"Data attribute containing command: {packet[Raw].load}")

def main():
    sniff(prn=ids, iface=incoming_interface, filter=inbound)
    

if __name__ == "__main__":
    shell()
