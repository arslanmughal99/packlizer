#!/usr/bin/python
import scapy.all as scapy
import scapy_http.http as http
from colorama import Fore, Style
import argparse
import subprocess


subprocess.call("clear")
print(Fore.BLUE + Style.BRIGHT +
      """         _    _ _              
 _ __   __ _  ___| | _| (_)_______ _ __ 
| '_ \ / _` |/ __| |/ / | |_  / _ \ '__|
| |_) | (_| | (__|   <| | |/ /  __/ |   
| .__/ \__,_|\___|_|\_\_|_/___\___|_|   
|_|                                  
_______________________________________________________""")
print(Fore.CYAN + Style.BRIGHT + "Author : Arslan     |   arslanmughal5566@protonmail.com\n")


try:
    # adding cli args
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", dest="interface", help="Interface on which packets need to be sniffed")
    arg = parser.parse_args()


    # verify if the the given iface is valid
    def iface_validator(iface_name):
        ifaces = subprocess.check_output("ifconfig")
        if iface_name in ifaces:
            return True

    # Validating args

    if arg.interface:
        temp_interface = arg.interface
    else:
        temp_interface = raw_input(Fore.RED + Style.BRIGHT + "Please enter interface Name : ")


    if iface_validator(temp_interface):
        interface = temp_interface
    else:
        print(Fore.RED + Style.BRIGHT + "Please Enter a Valid InterFace \n Exiting ....")
        exit(1)

    # Main sniffer
    def sniff(interface_name):
        print(Fore.BLUE + Style.BRIGHT + "[+]" + Fore.RED + Style.BRIGHT + "    sniffer started...\n \n")
        scapy.sniff(iface=interface_name, store=False, prn=sniff_callback)

    def sniff_callback(packet):
        if packet.haslayer(http.HTTPRequest or http.HTTPResponse): # http.HTTPRequest or http.HTTPResponse
            print(Fore.BLUE + Style.BRIGHT + "Source IP               : " + Fore.RED + Style.BRIGHT + str(packet[1].src))
            print(Fore.BLUE + Style.BRIGHT + "Source mac_address      : " + Fore.RED + Style.BRIGHT + str(packet[0].src))
            print(Fore.BLUE + Style.BRIGHT + "Destination IP          : " + Fore.RED + Style.BRIGHT + str(packet[1].dst))
            print(Fore.BLUE + Style.BRIGHT + "Destination mac_address : " + Fore.RED + Style.BRIGHT + str(packet[0].dst))
            print(Fore.BLUE + Style.BRIGHT + "Destination PORT        : " + Fore.RED + Style.BRIGHT + str(packet[2].dport))
            print(Fore.BLUE + Style.BRIGHT + "HTTP Packet             : " + Fore.RED + Style.BRIGHT + str(packet[3]))
            print(Fore.CYAN + "-------------------------------------------------------------------------------\n")

        # print(packet)


    sniff(interface)
except KeyboardInterrupt:
    print("\nExiting ....!")
    print("Bye!")