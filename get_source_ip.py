from scapy.all import *

#ICMP id 10 = 0xa
def get_src_ip(packet):
    if packet.haslayer(ICMP):
        packet.show()
        src_ip = packet[IP].src
        print(f"Source IP for incoming ping is {src_ip}")
    

def main():
    sniff(prn=get_src_ip)


if __name__ == "__main__":
    main()
