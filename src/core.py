# -*- coding: utf-8 -*-
from util import getIpAddress,getPort, isSrc
from tcp_packet import tcp_packet
from udp_packet import udp_packet
from rule_engine import rule_engine

def main(f):
    #f = open('../packets/tcp.txt','r')
    while(True):
        f.readline()
        f.readline()
        s = f.readline()  

        # --- FIX 1: Check for end of file ---
        # If 's' is an empty string, we've read the whole file.
        if not s:
            print("End of packet file reached.")
            break 

        s = s[6:len(s)-2].split("|")

        # --- FIX 2: Check for malformed lines ---
        # The code needs to access up to s[37] (for getPort).
        # If the list is shorter, it's a bad line, so we skip it.
        if len(s) < 38:
            print("Skipping malformed or incomplete packet line.")
            continue
        # --- END OF FIXES ---


        #print("Is coming in: ", end='')
        #print(isIncoming(['f8','34','41','21','87','7a'],s[6:12]))

        MACaddress =s[6]+":"+s[7]+":"+s[8]+":"+s[9]+":"+s[10]+":"+s[11] 

        
        try:
            if(s[23]== "06"):
                packet = tcp_packet(MACaddress,\
                                  getIpAddress(s[26:30]), \
                                  getIpAddress(s[30:34]),\
                                  getPort(s[34:36]), \
                                  getPort(s[36:38]) )
            
            # Use 'elif' to avoid errors
            elif(s[23]== "11"):
                packet = udp_packet(MACaddress,\
                                  getIpAddress(s[26:30]), \
                                  getIpAddress(s[30:34]),\
                                  getPort(s[34:36]), \
                                  getPort(s[36:38]) )
            else:
                # If protocol is not TCP or UDP, skip this loop
                print(f"Skipping unknown protocol: {s[23]}")
                continue

        except Exception as e:
            print(f"Error creating packet object: {e}. Skipping line.")
            continue


        print(packet.String())
        f.readline()

        r = rule_engine()
        

        
        #Check if the src of the packet is my device
        #Then the packet is travelling outside my network
        isSuccess = False
        if(isSrc(['f8','34','41','21','87','7a'],s[6:12])):
            print("packet going out of our server..")
            print("source ip:{} and port:{} will {}".format(packet.getSrcIP(),\
                                                                  packet.getSrcPort(),\
                                                                  r.checkOutboundRules(packet.getSrcIP(), packet.getSrcPort())))
            print("Destination ip:{} and port:{} will {}".format(packet.getDstIP(),\
                                                                        packet.getDstPort(),\
                                                                        r.checkOutboundRules(packet.getDstIP(), packet.getDstPort())))

            
            isSuccess = r.checkOutboundRules(packet.getSrcIP(), packet.getSrcPort()) == 'Accept' and \
                        r.checkOutboundRules(packet.getDstIP(), packet.getDstPort()) == 'Accept'


        else:
            print("packet comes to our server..")
            print("source ip:{} and port:{} will {}".format(packet.getSrcIP(),\
                                                                  packet.getSrcPort(),\
                                                                  r.checkInboundRules(packet.getSrcIP(), packet.getSrcPort())))
            print("Destination ip:{} and port:{} will {}".format(packet.getDstIP(),\
                                                                        packet.getDstPort(),\
                                                                        r.checkInboundRules(packet.getDstIP(), packet.getDstPort())))
            isSuccess = r.checkInboundRules(packet.getSrcIP(), packet.getSrcPort()) == 'Accept' and \
                        r.checkInboundRules(packet.getDstIP(), packet.getDstPort()) == 'Accept'



        if(isSuccess):
            print("Packet transmission successfull")
        else:
            print("Packet transmission unsuccessfull!!! Packet Dropped")

        print("\n\n")
            
        
    
'''
f = open('../packets/tcp.txt','r')
g = open('../packets/udp.txt','r')  
main(f)

'''