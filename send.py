#author: Cullen Walsh
#soruce file for the send functionality
import os
import socket
from contact_search import server


def send_file():
    """
    choose from available online contacts
    choose file to send
    send file to port associated with that contact
    """
