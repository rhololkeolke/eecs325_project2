#!/usr/bin/python

from main import *
import random

if __name__ == '__main__':
  src = '129.22.56.238'

  dst = socket.gethostbyname('yahoo.com')

  max_hops = 30

  dport = 33434

  payload = '@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_'

  # create the sending socket
  try:
    # no need to set IP_HDRINCL option because it is on by default with RAW sockets
    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
  except:
    print "sending socket could not be created"
    sys.exit()
    
  # create the listening socket
  try:
    listener = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    listener.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
  except:
    print "Listening socket could not be created"
    sender.close()
  
  print "Running trace to " + dst
  for i in range(1, 30):
    print i
    for j in range(0,3):
      ip_header, pkt_id = construct_ip_header(src, dst, i)
      sport = random.randint(1024, 2**16-1)
      udp_datagram = construct_udp_datagram(src, dst, sport, dport+(i-1), payload=payload)
      packet = ip_header + udp_datagram

      sender.sendto(packet, (dst, 0))
      response, rtt = listen_for_icmp(listener, 5, time.time(), pkt_id)

      print "\t %i, %f" % (response, rtt)
                            

