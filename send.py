#author: Cullen Walsh
#soruce file for the send functionality
import os
import socket
import contact_search
from contact_search import server


def send_file():
    """
    choose from available online contacts
    choose file to send
    send file to port associated with that contact
    """
    contact_search.list_online_contacts()
    receiver_email = input("please enter the email you would like to send to: ").strip().lower()
    while receiver_email not in contact_search.online_contacts.keys():
        receiver_email = input("sorry that is not a recognized email of an online ")
"""
    #get list of online contacts
    #list_online_contacts()
    #display the online contacts
    #print("who would you like to send to?")
    please enter the name of the file you would like to squirt:
    while invalid filename:
        print("sorry that filename is invalid, enter a valid file name:")
    get socket of specified contact
    transmit file to receiver
"""

