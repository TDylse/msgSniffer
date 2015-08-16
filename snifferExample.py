# -*- coding: utf-8 -*-
"""
Created on Tue Mar 24 12:26:25 2015

@author: tristan.gibson
"""
import Queue
from Sniffer import *


    
def decodeDATE_MSG(packetBuffer):
   
    start = 0
    fmt = '!7I'
    msg,start = readData(fmt,packetBuffer,start)
    print "Date and Time:  {0}/{1}/{2}  {3}:{4}:{5}".format(msg[0],msg[1],msg[2],msg[3],msg[4],msg[5]+msg[6]*1e-6)



def main():
    if len(sys.argv) < 2:
   
        print
        print '-----------------------------------------------------'
        print '                Message Sniffer                  '
        print '-----------------------------------------------------'
        print 'Syntax: python snifferExample.py {messageNumber(s)} '
        print 'The message(s) are:'
        for x in range(len(address)):
            print '{0}.  {1}'.format(x,address.keys()[x])
        print
        sys.exit(0)


    #where the sniffer will place message
    msgQueue = Queue.Queue()

    #start a sniffer for all messages requested
    sniffers = [Sniffer(address.values()[int(x)],msgQueue)  for x in sys.argv[1::]]
    for sniffer in sniffers:
        print sniffer
        sniffer.start()
    

    while 1:
        
        packet = msgQueue.get()
            
        try:
            message = sniffer.parseMsg(packet)
        except Exception,e:
            print str(e)

  
        msg = searchDict(address,message['IPheader']['dest'])
        

        if (msg == 'DATE_MSG'):
           try:
               decodeDATE_MSG(message['Data'])
           except Exception,e:
               print str(e)


        sys.stdout.flush()


if __name__ == "__main__":


    address = {'DATE_MSG':         ['239.0.0.1',2391]
              }
    main()

   