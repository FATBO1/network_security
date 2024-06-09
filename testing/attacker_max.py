from scapy.all import *

#ICMP id 10 = 0xa
def send_packet():
    ip_packet = IP(dst="192.168.100.1")/ICMP(id=10)
    ip_packet.show()
    respone = sr(ip_packet, verbose=1)
    

def main():
    send_packet()
    pass


if __name__ == "__main__":
    main()
