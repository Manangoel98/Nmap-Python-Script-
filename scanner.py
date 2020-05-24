#!/usr/bin/python3

import nmap
import socket
import re


print("Your Nmap Script Starts Here")
print("============================")



regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'''

option = '0'
ip_addr = '127.0.0.1'


def scancall():
    
    global option
    option  = input ("""Enter option which you want to use 
                    1) SYN ACK SCAN
                    2) UDP SCAN
                    3) Intense Scan
                    4) To Check Only Port Number Available
                    """)


def enterip():
    global ip_addr
    ip_addr = input("Enter IP You want to scan !")
    # ip_addr = '192.168.43.41'
    print("Your IP Address is " , ip_addr)
    checkip(ip_addr)



def checkip(ip_addr):
    if re.search(regex,ip_addr):
        print("Valid IP")
        scancall()
    else:
        print("Inavalid IP Enter Again : ")
        enterip()


nm = nmap.PortScanner()


hostna = socket.gethostname()    
IPAddr = socket.gethostbyname(hostna)    
print("Your Computer Name is:" , hostna)    
print("Your Computer IP Address is:" , IPAddr)
enterip()






if option == '1' :
    print("Starting")
    print("Nmap Version : " , nm.nmap_version() )
    print("\n")
    print("Host : {} :".format(ip_addr))
    print("============================")
    nm.scan(ip_addr,'1-1023','-v -sS')
    print("IP Status : " , nm[ip_addr].state())
    print("All Available Ports : " , nm[ip_addr].all_tcp())
    for proto in nm[ip_addr].all_protocols():
         print("============================")
         print("Protocol : {}".format(proto))
 
         lport = nm[ip_addr][proto].keys()
         #lport.sort()
         for port in lport:
             print ("port : {}  state : {}".format(port,nm[ip_addr][proto][port]['state']))
    print("Does Port 22 exists : " , nm[ip_addr].has_tcp(22) )
    print("Does Port 80 exists : " , nm[ip_addr].has_tcp(80) )
    print("Finished Scanning")



if option == '2' :
    print("Starting")
    print("Nmap Version : " , nm.nmap_version() )
    print("Host : {} :".format(ip_addr))
    print("============================")
    nm.scan(ip_addr,'1-1023','-v -sU')
    print("IP Status : " , nm[ip_addr].state())
    print("All Available Ports : " , nm[ip_addr].all_udp())
    for proto in nm[ip_addr].all_protocols():
         print("============================")
         print("Protocol : {}".format(proto))
 
         lport = nm[ip_addr][proto].keys()
         #lport.sort()
         for port in lport:
             print ("port : {}  state : {}".format(port,nm[ip_addr][proto][port]['state']))
    print("Finished Scanning")


if option == '3' :
    print("Starting")
    print("Nmap Version : " , nm.nmap_version() )
    print("Host : {} :".format(ip_addr))
    print("============================")
    nm.scan(ip_addr,'1-1023','-v -sC -sV -sS -Pn -A -O')
    print("IP Status : " , nm[ip_addr].state())
    print("All Available Ports : " , nm[ip_addr].all_tcp())
    for proto in nm[ip_addr].all_protocols():
         print("============================")
         print("Protocol : {}".format(proto))
 
         lport = nm[ip_addr][proto].keys()
         #lport.sort()
         for port in lport:
             print ("port : {}  state : {}".format(port,nm[ip_addr][proto][port]['state']))
    print("Does Port 22 exists : " , nm[ip_addr].has_tcp(22) )
    print("Does Port 80 exists : " , nm[ip_addr].has_tcp(80) )
    print("Finished Scanning")


if option == '4' :
    print("Starting")
    print("Nmap Version : " , nm.nmap_version() )
    print("Host : {} :".format(ip_addr))
    print("============================")
    nm.scan(ip_addr,'0-65535')
    for proto in nm[ip_addr].all_protocols():
        print("============================")
        print("Protocol : {}".format(proto))

        lport = nm[ip_addr][proto].keys()
        for port in lport:
             print ("port : {}  state : {}".format(port,nm[ip_addr][proto][port]['state']))
    print("IP Status : " , nm[ip_addr].state())
    print("Finished Scanning")

if option == '5' :
    print("Select Valid Option To Scan : ")
    scancall()

