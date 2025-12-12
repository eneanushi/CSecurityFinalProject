import os
from ca_setup import ca_setup

def first_time_setup():
    if not os.path.exists("data/ca_private_key.pem") or not os.path.exists("data/ca_certificate.pem"):
        print("*" * 30)
        print("FIRST TIME SECUREDROP SETUP")
        print("*" * 30)
        response = input("Create Certificate Authority? y/N: ")
        if response.lower() == "y":
            ca_setup()
            print("Certificate Authority Created")
            return "REGISTER"
        else:
            print("Setup Cancelled")
            return "EXIT"
    return "CONTINUE"
