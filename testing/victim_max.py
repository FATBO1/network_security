from scapy.all import *


# ICMP id 10 = 0xa
def check_packet(packet):
    if packet.haslayer(ICMP):
        packet.show()
        if packet[ICMP].id == 10:
            print("yes")


def main():
    sniff(prn=check_packet, iface='eth0')
    pass


if __name__ == "__main__":
    main()
