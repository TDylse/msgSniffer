# -*- coding: utf-8 -*-
"""
Created on Tue Mar 24 12:26:25 2015

@author: tristan.gibson
"""

import socket
import struct
import sys
import binascii
import threading
import Queue
import platform


class Sniffer(threading.Thread):
#'''UDP Packet Sniffer for a ip address and port '''
    
    def __init__(self,address,msgQueue):

        self.ipHeaderBuffer = []
        self.packetBuffer   = []
        self.idBuffer       = []
        self.msgBuffer      = []
        self.msgQueue       = msgQueue
        self.address        = address    #ip and port

        
        #init for threading.Thread
        super(Sniffer,self).__init__()

        #put NIC in promiscuous mode to see all packets (including IP headers)
        if platform.system() == 'Windows':
            HOST = socket.gethostbyname(socket.gethostname())
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((HOST,0))
            sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            
        elif platform.system() == 'Linux':
            #TODO: make interface configurable
            ETH_P_ALL = 0x0003
            interface = 'eth0'
            sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
            sniffer.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,2**30)
            sniffer.bind((interface,ETH_P_ALL))
            
        elif platform.system() == 'Darwin':
            #TODO: This doesn't seem to work;  Runs but never sees any packest
            HOST = socket.gethostbyname(socket.gethostname())
            sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sniffer.bind((HOST,0))
            sniffer.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,2**20)
            
        self.sniffer = sniffer

    def run(self):
        isRunning = True
        while isRunning:
            self.sniff()

    def clearBuffers(self):
        self.msgBuffer = []
        self.packetBuffer = []
        self.ipHeaderBuffer = []
        self.idBuffer = []
        
    
    def sniff(self):
        #gets data from socket, compares to the IP we are looking for, and puts complete UDP message on a Queue
        
        #TODO: add a cleanup process that removes packets from buffers that are old ( droppped packets?)
        
        #put socket data in raw_buffer, for each packet coming in
        raw_buffer,addr = self.sniffer.recvfrom(65565)
        #print raw_buffer
        #on Linux, remove the Ethernet header
        if platform.system() == 'Linux':
            raw_buffer = raw_buffer[14:]
        self.raw_buffer = raw_buffer

        self.IPheader = self.decodeIPHeader(raw_buffer[0:20])
        
        
        # Looking for UDP packets
        if self.IPheader['protocol'] == 17:
            
            self.UDPheader = self.decodeUDPHeader(raw_buffer)
            
            if self.IPheader['dest'] == self.address[0]: 
              
                self.packetBuffer.append(raw_buffer)
                
                if self.IPheader['flags']==1:
                    #if the flags field is set, then more fragments are coming
                    self.ipHeaderBuffer.append(self.IPheader)
                    self.idBuffer.append(self.IPheader['identification'])
                else:
                    #if flags is not set, then either this is the last frag or their is only one packet

                    if self.IPheader['identification'] in self.idBuffer:
                        #check the IDbuffer to see if we have a fragment saved off;

                        #use list comprehension to return the index of the ID in the buffer
                        index = [x for x,val in enumerate(self.idBuffer) if val == self.IPheader['identification']]

                        #remove from incoming packet buffer and put complete messages on the Queue to be processed
                        for x in range(len(index)):
                            
                            #keep the IP/UDP header from the first packet, and just the data from the rest
                            if x == 0:
                                self.msgBuffer.append(self.packetBuffer[index[x]])
                            else:
                                self.msgBuffer.append(self.packetBuffer[index[x]][20:])
                            

                        #this should be the guy we just got    
                        self.msgBuffer.append(self.packetBuffer.pop()[20:])
                            
                        #turn list back to string and clear our buffers    
                        self.msgQueue.put(''.join(self.msgBuffer),True)
                        self.clearBuffers()
                        
                    else:
                        #we only had one fragment/packet; take it off the incoming packet buffer and put on the queue
                        self.msgQueue.put(self.packetBuffer.pop())
                        self.clearBuffers()
            
        sys.stdout.flush()
            
    def decodeIPHeader(self,raw_buffer):
        #parse IP header
        
        ip_header = raw_buffer[0:20]
        IPHeader = {'protocol':-1, 'flags':-1, 'offset':-1} 
        iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
    
        # Create our IP structure
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4
        ttl = iph[5]
        protocol = iph[6]                               #17 is UDP
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        totalLength = iph[2]
        flags  = (iph[4] >> 13)
        offset = (iph[4] & 0x1FFF)

        IPHeader.update(protocol = protocol)
        IPHeader.update(flags    = flags)
        IPHeader.update(offset   = offset)
        IPHeader.update(dest     = d_addr)
        IPHeader.update(identification = iph[3])
        
        return IPHeader
        

    def decodeUDPHeader(self,packet):
        #parse UDP header

        udp_header = packet[20:28]

        UDPHeader  = {'dest_port':-1, 'udp_length':-1 }
        udph       = struct.unpack('!HHHH',udp_header)
        dest_port  = udph[1]
        udp_length = udph[2]
        
        #print 'UDP Dest Port:' +  str(dest_port) + ', UDP Length:', str(udp_length)
        UDPHeader.update(dest_port  = dest_port)
        UDPHeader.update(udp_length = udp_length)     
        
        return UDPHeader


    def getMessageData(self,packet):
        return packet[28: ]

    def parseMsg(self,packet):
        message = {}
        
        message['IPheader']  = self.decodeIPHeader(packet)
        message['UDPheader'] = self.decodeUDPHeader(packet)
        message['Data']      = self.getMessageData(packet)
        return message
        
        
    
    
    
def searchDict(book,value):
    #search dictionary for a value and return the key
    index = -1
    for k in book.iterkeys():
        if book[k][0] == value:
           index = k
           return index


def readData(fmt,packetBuffer,start):
    #unpack data from string (used for reading binary message data)

    end = start + struct.calcsize(fmt)
    data = struct.unpack(fmt,packetBuffer[start:end])
        
    return (data,end)
    


 