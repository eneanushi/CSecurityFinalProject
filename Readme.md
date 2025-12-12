To test the program

1. Clone the repo

2. cd into SecureDrop Folder location into your directory
   a - If you haven't download -> pip3 install cryptography pycryptodome. Please do. You can just copy paste the command into your terminal and thats it.

3. To test Milestone 1:
    a - run -> python secure_drop.py
    b - Register a user
    c - Check that data/users.json and data/keys/ are created

4. To test Milestone 2:
    a - run -> python secure_drop.py
    b - Enter your login username
    c - First time enter a wrong password
    d - Test correct password

5. To test Milestone 3: 
    a - run -> python secure_drop.py
    b - Login using your correct username and password
    c - Add contacts using "add" command
    d - Check inside SecureDrop folder for data/contacts/ directory for encrypted files


--End of testing

6. To reset and start fresh so we can test the program from the beggining (Milestone 1)
    a - cd into SecureDrop Folder location into your directory
    b - run -> rm -rf data
    c. Repeat steps from 3 - 5.

 -------------
  MILESTONE 4
 -------------
1. Upon running the program a menu will be displayed you must choose (1-3) in command line 
    -> 1. Register New User
    -> 2. Login existing User
    -> 3. Exit
2. If Registering a New User (1)the pogram does the following
    2.1 Checks if a Certificate Authority exist.
        - if the it doesnt then it asks if you would like to create one (was done for debugging)
        - if input is y then it generates 
            - CA private key 
            - CA public key
            - CA certificate
        which are stored in the data folder

    2.2 Proceeds to Registration, once finalized :
        -The user will be issued a private and public key
        -The user will be issued a certificate signed by the CA

3. If Login existing User is Selected (2)
    3.1 Upon login starts a TCP server which is local
        3.1.1 Tries to bind to ports in a range (:12345-12354)
        3.1.2 The first available port is then assigned to the user
        3.1.3 The server runs in a background thread to allow it to continuesly discover users
    3.2 Handling connections
        3.2.1 It receives data but it does expect it to be a certificate
            - checks if the data starts with "-----BEGIN CERTIFICATE-----"
            -if this is not the case then then the connection is rejected
        3.2.2 Loads the CA public key to verify the certificate
            - Signature validity (must be signed by the CA)
            - Time validity (Not expired, checks timestamps)
            - Must have an email in the certificate subject
        3.2.3 If verification is Completed
            - the users email is added to all online users
            - if the email is int the logged-in users contacts, it adds it adds the online_contact list
            - The server sends back its own certificate to the connecting client
    3.3 How Scanning for Contacts work
        - Connect to a port 
        - Send the local user's certificate 
        - Recieve a certificate from the remote user
        - verifies the certificate using CA
        - if valid add the user to all online users list or online_contacts if the are a contact
    3.4 Listing Users
        -User can run the list command to look for the contacts who are online
        -User can run list all command to look for all the user who are online

------------
   TESTING
------------
1. Run python3 secureDrop on two different terminals
2. Register each window with two different contacts
    - first registered contact must create the CA
    - wont see that step for the second user
3. log in
    - when first user will not see anyone online 
    - once the second user logs in the first user will see a user in their end
    - second person will not see anyone until he runs list all
4. Run add on first user to add second user a contact
    - first user will be able to run list and see second user in the list
    - Second user will not be able to see first user in their list only on list all
