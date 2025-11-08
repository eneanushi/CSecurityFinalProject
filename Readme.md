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



