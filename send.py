#author: Cullen Walsh
#soruce file for the send functionality
import os
import socket
import contact_search
from user_login import session
from contact_search import server


def send_file():
    """
    choose from available online contacts
    choose file to send
    send file to port associated with that contact
    this way it uses the port already made for the handshake instead of having to go through handshake again
    """
    contact_search.list_online_contacts()
    receiver_email = input("please enter the email you would like to send to: ").strip().lower()
    while receiver_email not in contact_search.online_contacts.keys():
        receiver_email = input("sorry that is not a recognized email of an online contact, please enter a valid email")
    sender_email = session.email #my email

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



"""
do I have to implement a receiver function?
yeah right?
like I have to implement the receiving of the file and writing to save but I don't know where
we really should've split the connection and web stuff into a seperate file from contact search"""