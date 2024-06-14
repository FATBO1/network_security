from scapy.all import *
import subprocess


# ICMP id 10 = 0xa
def check_packet(packet):
    if packet.haslayer(ICMP):
        packet.show()
        if packet[ICMP].id == 10:
            print("yes")
            if packet[Raw] == 'ipconfig':
                result = subprocess.run('ipconfig', shell=True, capture_output=True, text=True)



def main():
    sniff(prn=check_packet, iface=conf.loopback_name)
    pass


if __name__ == "__main__":
    main()
