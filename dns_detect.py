from scapy.all import *
import datetime
import argparse
import netifaces

from scapy.layers.dns import DNS, DNSQR

conf.sniff_promisc = True  # Set promiscuous mode to true

detector_list = {}


def spoof_packet(sniffed_packet):
    """
    This function analyses the sniffed packet and verifies if a dns injection attack has been performed
    :param sniffed_packet: The sniffed packet
    :return:
    """

    # We check if the captured packet is indeed a DNS packet and if it is a type A DNS packet
    if sniffed_packet.haslayer(DNS) \
            and sniffed_packet.haslayer(DNSQR) \
            and sniffed_packet[DNS].qd.qtype \
            and sniffed_packet[DNS].qd.qtype == 1:

        # If the DNS packet has ancount = 0, the packet must be a request packet. Add this packet to
        # dictionary based on the transaction id
        if sniffed_packet[DNS].ancount == 0:
            current_time = datetime.datetime.now().time()
            existing_value = detector_list.get(sniffed_packet[DNS].id)
            if existing_value:
                existing_value[0] = sniffed_packet
                existing_value[1] = current_time
            else:
                detector_list[sniffed_packet[DNS].id] = [sniffed_packet, current_time]

        # The else case is for the DNS responses
        else:
            # We check if the corresponding request for the response is present in the dictionary. If not, this might
            # just be some random responses that we don't need to care.
            existing_value = detector_list.get(sniffed_packet[DNS].id)
            if not existing_value:
                print "No request in dictionary"
                return

            # If there is an entry in the dictionary and the length of the entry is greater than 2
            # ie, a response for this packet was recorded earlier.
            if existing_value and (len(existing_value) > 2):
                ttl = sniffed_packet[DNS].an.ttl
                old_packet = existing_value[2]
                old_ttl = old_packet[DNS].an.ttl

                # If the ttl values of the two responses are different, this could be an attack
                if old_ttl != ttl:
                    print datetime.datetime.now().time(), " !!!!!DNS poisoning attempt!!!!!"
                    print "TXID ", sniffed_packet[DNS].id, " Request", sniffed_packet[DNS].an.rrname

                    ipaddress = ""
                    for i in range(0, sniffed_packet[DNS].ancount):
                        ipaddress = ipaddress + " " + sniffed_packet[DNS].an[i].rdata
                    print "IP Address", ipaddress
                    ipaddress = ""
                    for i in range(0, old_packet[DNS].ancount):
                        ipaddress = ipaddress + " " + old_packet[DNS].an[i].rdata
                    print "IP Address: ", ipaddress

            # If the length of the existing value is 2, that means no response has been added yet.
            # Add the response to the dictionary
            elif existing_value and (len(existing_value) == 2):
                # No response present for the request
                current_time = datetime.datetime.now().time()
                existing_value.append(sniffed_packet)
                existing_value.append(current_time)


# Parse the arguments provided in command line
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("-i", help="Network Interface Device")
parser.add_argument("-r", help="Name of tracefile for offline mode")
parser.add_argument("expression", help="bpf filter for the traffic to monitor")
args = parser.parse_args()

# Get default device
device = netifaces.gateways()['default'][netifaces.AF_INET][1]

if args.i:
    device = args.i

# Default BPF filter for DNS packets
bpf_filter = "udp port 53"
if args.expression != "":
    bpf_filter = bpf_filter + " and " + args.expression

if args.r:
    sniff(filter=bpf_filter, prn=spoof_packet, store=0, iface=device, offline=args.r)
else:
    sniff(filter=bpf_filter, prn=spoof_packet, store=0, iface=str(device))
