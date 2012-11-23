#!/usr/bin/python
"""
This module contains the code for the EECS 325 Networks second project.

It is similar to a UDP traceroute and is designed to investigate the
dependency between hop count and RTT

Devin Schwab (dts34)
"""

import sys
import socket
import time
import struct
import select
import random
import urllib2

# These are used when the TTL is too low
ICMP_TIME_EXCEEDED = 11
ICMP_HOP_COUNT_EXCEEDED = 0

# These are used when the TTL is too high or just right
ICMP_DESTINATION_UNREACHABLE = 3
ICMP_PORT_UNREACHABLE = 3

# this is used in the socket constructor call
ICMP_CODE = socket.getprotobyname('icmp')

def construct_ip_header(src, dst, ttl, proto=socket.IPPROTO_UDP, pkt_id=None, src_aton=True, dst_aton=True):
    """
    This function creates an ip header using the
    information specified.

    By default it will generate a random id and assume the packet
    will be carrying a UDP datagram

    The IP header consists of the following basic fields
    -----------------------------------------------------

    - version(4 bits): This is the version of the IP protocol being used (e.g. 4)

    - internet header length(4 bits): The length in 32 bit groups of the header
                                      (for a no options header this is 5)

    - type of service
      and explicit congestion notification(8 bits): Not used by this program so set to 0

    - total length(16 bits): the total length of the header in bytes (20 for a no options header).
                             However, the kernel will automatically take care of this

    - packet id(16 bits): The identification number of the packet.
                          If not provided one will be randomly generated.
                          This is the main field that will be used in identifying
                          reply packets. This is one reason why the packet header
                          needs to be explicitly built

    - flags and fragment offset (16 bits): No special flags are needed and there is
                                           no fragmentation in this program so 0

    - ttl (8 bits): The Time To Live of the packet. Needed for this program to accomplish
                    its goals. This field is one of the reasons why the program
                    has to construct the header from scratch

    - protocol(8 bits): Specifies the protocol encapsulated by the IP packet

    - checksum(16 bits): The ones complement of the sum of all 16 bit groups in the header.
                         The kernel will fill this in so this can be set to 0 when constructing
                         the packet header

    - source IP address(32 bits): This is the source of the IP packet (i.e. this computer)

    - destination IP address(32 bits): This is the destination of the IP packet
                                       (i.e. the server being contacted)
    """
    
    
    ip_ihl = 5 # this is the lenght in 32 bytes. 5 is the length for a header with no options
    ip_ver = 4 # this is an IPv4 packet
    ip_tos = 0 # No special services are desired
    ip_tot_len = 0 # this will be filled in by the kernel so no sense computing it here

    if pkt_id is None:
        pkt_id = random.randint(0, 2**16) # pkt id is 16 bits so this number can be between 0 and 2^16
    ip_id = pkt_id
    ip_frag_off = 0 # not fragmented so 0
    ip_ttl = ttl
    ip_proto = proto
    ip_chksum = 0 # kernel will compute the checksum so no need to waste time doing it here
    if src_aton:
        ip_src = socket.inet_aton(src)
    if dst_aton:
        ip_dst = socket.inet_aton(dst)

    # merge the internet header length and version field so that struct can pack them
    ip_ihl_ver = (ip_ver << 4) + ip_ihl # simply bit shift the ip version to the upper 4 bits

    # now using the struct library pack all of the data fields above using the proper bit lengths
    # B signifies a single byte.
    # H signifies 2 bytes
    # 4s signifies 4 bytes
    # ! signifies that network order is desired
    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id,
                            ip_frag_off, ip_ttl, ip_proto, ip_chksum, ip_src, ip_dst)

    return (ip_header, pkt_id)

def construct_udp_pseduo_header(src, dst, udp_len, src_aton=True, dst_aton=True):
    """
    This function takes in the information necessary
    to construct a pseudo header for a UDP datagram.

    src_aton and dst_aton determine whether the aton function
    is run on source and destination IP respectively

    The information required is:

    - source IP address
    - destination IP address
    - protocol (in this case UDP)
    - length of UDP datagram

    For more information see RFC 768
    """

    if src_aton:
        ip_src = socket.inet_aton(src)
    if dst_aton:
        ip_dst = socket.inet_aton(dst)

    return struct.pack('!4s4sBBH', ip_src, ip_dst, 0, socket.IPPROTO_UDP, udp_len)

def calculate_udp_checksum(pseudo_header, udp_header, udp_data):
    """
    This function takes in the pseudo-header for a UDP datagram,
    a UDP header and UDP payload data.

    It then calculates the checksum for the UDP datagram.

    The basic procedure is to sum up all 16 bit groups (cycling carry outs)
    and then take the ones complement of the answer. (According to the spec
    if the checksum turns out to be 0 then all 1's should be used because
    all 0's means ignore the checksum)

    The algorithm is based off of the code in ping.c's in_cksum function

    For more information see RFC 768
    """

    # first concatenate everything together
    msg = pseudo_header + udp_header + udp_data

    # then add up all 16 bit groups (ignore carryouts until the very end
    s = 0 # this is the sum (sum is a built in function in python so I called it s)

    # take two characters every loop
    for i in range(0, len(msg), 2):
        # unfortunately these are treated as strings so to make
        # sure everything goes alright they need to be converted
        # back to their binary representation via the
        # ord function
        w = ord(msg[i]) + (ord(msg[i+1]) << 8) # a word of data
        s = s + w

    # now bit shift the upper 16 bits and add to the lower 16
    # the 0xffff masks off the lower bits so that the carry out of the
    # sum is correct
    s = (s >> 16) + (s & 0xffff)

    # finally take the compliment and mask off any bits over 16
    #
    # Not sure if it will ever come out to 0, but the RFC says
    # that if it does it should be all 1's so just to be safe
    # I am checking
    if (~s & 0xffff) != 0:
        s = ~s & 0xffff

    return s

def construct_udp_datagram(src, dst, sport, dport, payload='Hello World!'):
    """
    This function takes in the information required to construct an UDP datagram.

    While the UDP header only explicitly requires the source and destination port
    to be specified in order to compute the checksum a UDP pseudo-header must be
    constructed. This pseudo header also includes IP source and destination address.

    The payload data is also required because the UDP header length field includes
    the length of the data

    UDP header fields
    -----------------
    source port(16 bits): The source port of the datagram
    destination port(16 bits): The destination port of the datagram
    length(16 bits): Length of the header plus payload data
    checksum(16 bits): A checksum of the pseudo-header (see RFC 768)
    """

    # udp header fields
    udp_sport = sport
    udp_dport = dport
    udp_data = payload
    udp_len = 8 + len(udp_data) # 8 is the length of all of the UDP header fields
    udp_chksum = 0 # temporary

    # construct the header
    udp_header = struct.pack('!HHHH', udp_sport, udp_dport, udp_len, udp_chksum)
    
    pseudo_header = construct_udp_pseduo_header(src, dst, udp_len)
    udp_chksum = calculate_udp_checksum(pseudo_header, udp_header, udp_data)

    udp_chksum = struct.pack('H', udp_chksum) # checksum should not be in network byte order
    return  struct.pack('!HHH', udp_sport, udp_dport, udp_len) + udp_chksum  + udp_data

def listen_for_icmp(sock, timeout, time_sent, packet_id):
    """
    This function will listen on the given socket until the timeout.

    The packet will be matched based on the following criteria:

        - packet id

    This function returns a tuple. The first item in the tuple
    is the response type. They are specified as follows:
    
    If a timeout occurs this function returns 0
    If a destination port unreachable (type 3, code 3) occurs this function return 1
    If a hop count exceeded (type 11, code 0) occurs this function returns 2
    If none of these match then -2 is returned

    The second item is the time it took to receive the reply in seconds
    """
    time_left = timeout
    while True:
        started_select = time.time()
        ready = select.select([sock], [], [], time_left)
        how_long_waited = time.time() - started_select
        if ready[0] == []: # no new data means timeout
            return (0, timeout)
        time_received = time.time()
        # I believe 1508 bytes is the biggest size I will see in practice
        rec_packet, addr = sock.recvfrom(1508)
        icmp_header = rec_packet[20:22]
        type, code = struct.unpack('bb', icmp_header)
        p_id = struct.unpack('!H', rec_packet[32:34])
        if p_id[0] == packet_id:
            rtt = time_received - time_sent
            if type == 3 and code == 3:
                return (1, rtt)
            elif type == 11 and code == 0:
                return (2, rtt)
            else:
                return (-2, rtt)

        # not the right packet :(
        time_left -= time_received - time_sent
        if time_left <= 0:
            return (0, timeout)
            
        

if __name__ == '__main__':
    # what's my ip provides an easy to use
    # service for getting the public IP address
    # of this computer
    #pub_ip = urllib2.urlopen('http://automation.whatismyip.com/n09230945.asp').read()
    
    #src = '127.0.01'
    #src = pub_ip
    src = '129.22.56.238'
    #dst = '127.0.0.1'
    dst = socket.gethostbyname('www.google.com')
    sport = 5666
    dport = 5666

    print "Constructing IP packet from %s to %s" % (src, dst)
    ip_header, pkt_id = construct_ip_header(src, dst, 128)
    print "Packet id: %x" % pkt_id
    print
    print "Constructing UDP datagram from %i to %i" % (sport, dport)
    payload = '@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_'
    udp_datagram = construct_udp_datagram(src, dst, sport, dport, payload=payload)
    print
    print "Sending packet"

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
        
    packet = ip_header + udp_datagram

    sender.sendto(packet, (dst, 0))
    response, rtt = listen_for_icmp(listener, 5, time.time(), pkt_id)

    print "Response: %i" % response
    print "RTT: %f" % rtt

    
    

