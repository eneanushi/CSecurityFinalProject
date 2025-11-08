import os
from user_registration import register_user, user_exists
from user_login import login_user, session
from contacts import add_contact

def main():
    """Main entry point"""
    os.makedirs("data", exist_ok=True)
    
    # Check if any users exist
    if not os.path.exists("data/users.json") or os.path.getsize("data/users.json") == 0:
        print("No users are registered with this client.")
        response = input("Do you want to register a new user (y/n)? ")
        
        if response.lower() == 'y':
            register_user()
        
        print("Exiting SecureDrop.")
        return
    
    # Login existing user
    if not login_user():
        return
    
    # Command shell
    while True:
        command = input("secure_drop> ").strip().lower()
        
        if command == "help":
            print('"add" -> Add a new contact')
            print('"list" -> List all online contacts')
            print('"send" -> Transfer file to contact')
            print('"exit" -> Exit SecureDrop')
        
        elif command == "add":
            add_contact()
        
        elif command == "list":
            print("Not implemented yet (Milestone 4)")
        
        elif command == "send":
            print("Not implemented yet (Milestone 5)")
        
        elif command == "exit":
            session.clear()
            break
        
        else:
            print(f'Unknown command: "{command}". Type "help" for commands.')

if __name__ == "__main__":
    main()