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
    #list out the online contacts for the user
    if not contact_search.list_online_contacts():
        #no online contacts were found, exit send()
        print("cannot send when there are no contacts online")
        return
    #get the contact the user would like to send to
    receiver_email = input("please enter the email you would like to send to: ").strip().lower()
    #get valid input from the user
    while receiver_email not in contact_search.online_contacts.keys():
        if receiver_email == "exit":
            #let the user have some way to escape
            return
        else:
            #ask them for a valid email
            receiver_email = input("sorry that is not a recognized email of an online contact, please enter a valid email: ")
    sender_email = session.email #my email
    #FIXME only can look in the working directory for the file, maybe add control flow to look in any path, likely unnecessary
    #get the file that we want to send
    file_name = input("what is the name of the file you would like to send?")
    #make sure it's a valid filepath
    while not os.path.isfile(file_name):
        #while it is not a valid file
        if file_name == "exit":
            #allow the user a way out
            return
        else:
            file_name = input("unable to find file, please enter a valid file name: ")

    #> have the contact email, the file to send, now I just send it right?

    contact_search.send_file(contact_search.online_contacts[receiver_email][0], file_name)



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
