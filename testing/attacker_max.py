from scapy.all import *

#ICMP id 10 = 0xa
def send_packet():

    ip_packet = IP(dst="127.0.0.1")/ICMP(id=10)/Raw('ifconfig')
    ip_packet.show()
    sr(ip_packet)

    

def main():
    send_packet()
    pass


if __name__ == "__main__":
    main()
