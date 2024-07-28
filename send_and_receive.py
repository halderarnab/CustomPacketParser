#!/usr/bin/env python3
from scapy.all import *
import sys
import threading
import os
import struct

big_lock = threading.Lock()

iface_name = "veth0"

def int_to_ascii_bytes(n):
    bytes_data = struct.pack('!I', n)
    ascii_str = ''.join(chr(byte) for byte in bytes_data)
    return ascii_str[0:4]

def App(x, y):
    return ((chr(0) * 8) +
            int_to_ascii_bytes(x) +
            int_to_ascii_bytes(y))

class Receiver(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
        self.received_count = 0

    def received(self, p):
        self.received_count += 1
        big_lock.acquire()
        print("Received a packet (total %d): %s" % (
            self.received_count, str(p.summary())))
        big_lock.release()

    def run(self):
        sniff(iface=iface_name, filter="inbound",
              prn=lambda x: self.received(x))

def main():
    try:
        packet_per_second = int(sys.argv[1])
        print("Sending packet at rate ", packet_per_second, " packets per second")
    except:
        print("Usage: sudo python send_and_receive.py <packet_rate (pkt/sec)>")
        sys.exit(1)
    packet_interval = 1.0/float(packet_per_second)    

    Receiver().start()

    # An example set of inputs to the Xor application
    x = int(65537)
    y = int(65539 | (65536 << 1))
    p = Ether(src="82:a7:6f:df:69:34", dst="02:f1:a3:7c:86:d0") / IPv6(src="aabb:ed11:face:4::1", dst="fc00:dead:cafe:1::2") / UDP(sport=100, dport=200) / App(x,y)
    # Some more examples: parameters with IPv4:
    # p = Ether(src="82:a7:6f:df:69:34", dst="02:f1:a3:7c:86:d0") / IP(src="10.0.0.1",dst="192.168.0.1") / UDP(sport=100, dport=200) / App(x,y)    
    # ICMPv6 echo request
    # p = Ether(dst="02:f1:a3:7c:86:d0") / IPv6(dst="fc00:dead:cafe:1::1") / ICMPv6EchoRequest()

    sent_count = 1
    while True:
        sendp(p, iface=iface_name, verbose=0)
        big_lock.acquire()
        print("Sent a packet (total %d): %s" % (
            sent_count, str(p.summary())))
        big_lock.release()
        sent_count += 1        
        time.sleep(packet_interval)


if __name__ == '__main__':
    main()
