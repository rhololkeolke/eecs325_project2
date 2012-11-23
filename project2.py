#!/usr/bin/python
"""
This module contains the code for the second EECS 325 Networks project.

It is similar to a UDP traceroute and is designed to investigate the
dependency between hop count and RTT

Devin Schwab (dts34)
"""

import sys
import socket
import urllib2
import random

from packet_builder import *

from math import ceil

import pdb

def calculate_distance(p1, p2):
    """
    This method takes in a latitude and
    longitude tuple for two different
    points and using the
    haversine formula calculates the distance between the
    two
    """
    from math import pi, sin, cos, atan2, sqrt

    R = 6371
    dLat = (p2[0]-p1[0])*pi/180
    dLon = (p2[1]-p1[1])*pi/180
    lat1 = p1[0]*pi/180
    lat2 = p2[0]*pi/180

    a = sin(dLat/2)*sin(dLat/2) + sin(dLon/2)*sin(dLon/2)*cos(lat1)*cos(lat2)
    c = 2*atan2(sqrt(a), sqrt(1-a))
    return R*c

def get_lat_lon(ip):
    """
    Given an IP address this function makes a request
    to http://freegeoip.net/xml/ and then parses the xml
    to get the latitude and longitude of this IP address
    """
    import xml.etree.ElementTree as ET
    base_url = 'http://freegeoip.net/xml/'

    url = base_url + ip
    xml_string = urllib2.urlopen(url).read()

    root = ET.fromstring(xml_string)

    try:
        latitude = float(root.find('Latitude').text)
        longitude = float(root.find('Longitude').text)
        return (latitude, longitude)
    except AttributeError:
        return
    
        

def calculate_ip_distance(ip1, ip2):
    """
    Given two IP's this function finds the latitude
    and longitude and returns the distance between them.
    """
    p1 = get_lat_lon(ip1)
    p2 = get_lat_lon(ip2)
    return calculate_distance(p1, p2)

if __name__ == '__main__':

    # get the public IP of this machine
    # this is a free service provided by whatismyip.com
    src = urllib2.urlopen('http://automation.whatismyip.com/n09230945.asp').read()

    # how many times each ttl should be tried
    # (this is to mitigate unfortunate events like dropped packets)
    num_tries = 3

    dport = 33434

    payload = 'Testing the correlation between RTT and Hop Count for a school \
               project. If you have questions please email dts34@case.edu'

    timeout = 5 # in seconds. This is the same default timeout used by traceroute

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

    #sites = ['yahoo.com.','alipay.com.','adultfriendfinder.com.','thefreedictionary.com.',
    #         'bluehost.com.','nokia.com.','google.sk.','hidemyass.com.','nudevista.com.',
    #         'nikkansports.com.','egotastic.com.']
    sites = ['google.sk.']


    for site in sites:
        dst = socket.gethostbyname(site)
        lower_ttl = 0 # the lower bound on the search space of the ttl
        upper_ttl = 32 # the upper bound and maximum ttl of the search space

        print "Running trace from %s to %s(%s)" % (src, site, dst)

        rtt = 0
        code = 0
        while True: # loop forever. The code inside will break out when necessary

            lowest_resp_rtt = 0
            lowest_resp_ttl = upper_ttl+1
            ttl = int(ceil((upper_ttl - lower_ttl)/2.0)) + lower_ttl
            for i in range(0,num_tries):
                print "Trying ttl %i" % ttl
                ip_header, pkt_id = construct_ip_header(src, dst, ttl)
                sport = random.randint(1024, 2**16-1) # get a random source port
                udp_datagram = construct_udp_datagram(src, dst, sport, dport, payload=payload)
                packet = ip_header + udp_datagram

                sender.sendto(packet, (dst, 0))
                code, rtt = listen_for_icmp(listener, timeout, time.time(), pkt_id)
                
                if code == 1:
                    lowest_resp_rtt = rtt
                    lowest_resp_ttl = ttl 
                    break
                elif code == 2:
                    break

            if (upper_ttl - lower_ttl) <= 1:
                if lowest_resp_ttl <= upper_ttl and lowest_resp_ttl >= lower_ttl:
                    print "RTT: %f" % lowest_resp_rtt
                    print "TTL: %i" % lowest_resp_ttl
                    print "Distance: %f" % calculate_ip_distance(src, dst)
                    break
                else:
                    print "No response"
                    break
            else:
                if code == 1:
                    print "Lower ttl upper bound"
                    upper_ttl = ttl
                    print "\t (%i, %i)" % (lower_ttl, upper_ttl)
                else:
                    print "Raising ttl lower bound"
                    lower_ttl = ttl
                    print "\t (%i, %i)" % (lower_ttl, upper_ttl)
                    