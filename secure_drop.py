
import os
from user_registration import register_user
from user_login import login_user, session
from contacts import add_contact
from contact_search import start_server, start_background_scanner, list_online_contacts
from first_time_setup import first_time_setup
from send import send_file

def main():
    os.makedirs("data", exist_ok=True)

    while True:
        print("\n" + "=" * 30)
        print("SecureDrop Main Menu")
        print("=" * 30)
        print("1. Register new User")
        print("2. Login existing User")
        print("3. Exit")

        choice = input("Choose option (1-3) ").strip()

        if choice == "1":
            setup_result = first_time_setup()
            if setup_result == "EXIT":
                continue
            elif setup_result == "REGISTER":
                if register_user():
                    print("Successful")
                    if login_user():
                        break
            else:
                if register_user():
                    print("Successful")
                    if login_user():
                        break
        elif choice == "2":
            if login_user():
                break
        elif choice == "3":
            return
        else:
            print("Invalid Input. Try again")

    start_server()
    start_background_scanner()

    while True:
        command = input("secure_drop> ").strip().lower()

        if command == "help":
            print('"add" -> Add a new contact')
            print('"list all" -> List all users') #FIXME<-- command not implemented
            print('"list"     -> List all online contacts')
            print('"send"     -> Transfer file to contact')
            print('"exit"     -> Exit SecureDrop')

        elif command == "add":
            add_contact()

        elif command == "list":
            list_online_contacts()

        elif command == "send":
            print("Not implemented yet (Milestone 5)")
            send_file()

        elif command == "exit":
            session.clear()
            from contact_search import cleanup_server
            cleanup_server()  # signal server/scanner threads to stop
            return

        else:
            print(f'Unknown command: "{command}". Type "help" for commands.')

if __name__ == "__main__":
    main()
