#author: Cullen Walsh
#soruce file for the send functionality
import os
import socket
from contact_search import server

def send_file(destination, fileName):
    """
    send a specific file to a destination
    :param destination: destination socket
    :param fileName: name of the file to send
    """
    server.connect(destination)

    with open(fileName, 'rb') as file:
        file_size = os.path.getsize(fileName) #grab the size of the file
