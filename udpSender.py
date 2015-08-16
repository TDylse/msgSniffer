
import socket
import datetime
import struct
import time



def getTime():
    timestamp = datetime.datetime.now()
    
    data = struct.pack('!7I',timestamp.month,
                         timestamp.day,
                         timestamp.year,
                         timestamp.hour,
                         timestamp.minute,
                         timestamp.second,
                         timestamp.microsecond
                  )

    return data


def main():
    IP = '239.0.0.1'
    port = 2391
    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)


    while True:
        data = getTime()
        sock.sendto(data,(IP,port))
        time.sleep(1)

    
if __name__ == '__main__':
    main()
    
    
    

