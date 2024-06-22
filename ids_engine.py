from scapy.all import *
import threading

incoming_interface = "eth0"

icmp_type = []

def check_duplicate(lst):
    for i in range(1, len(lst)):
        if lst[i] == lst[i - 1]:
            return True
    return False


def ids(packet):
    if packet.haslayer(ICMP):
        if packet.haslayer(Raw):
            icmp_type.append(packet[ICMP].type)
            if check_duplicate(icmp_type) == True:
                    print(f"Malicious ICMP Behaviour Detected!")
                    print(f"ICMP Packet:")
                    print(f"Source IP: {packet[IP].src}")
                    print(f"Destination IP: {packet[IP].dst}")
                    print(f"Signature Detected: There are duplicate replies/request for this ICMP connection.")
                    print(f"Data attribute containing command: {packet[Raw].load}\n")
                    icmp_type.clear()
       

def main():
    sniff(prn=ids, iface=incoming_interface, filter="inbound")
    

if __name__ == "__main__":
    main()
