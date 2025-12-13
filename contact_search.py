import socket
import threading
import time
import os
import atexit
import json

from user_login import session
from contacts import load_contacts
from crypto_utils import *

# Globals
online_contacts = {}  #dict { contact_email : (connected_client_socket, time_connected) }
_server_lock = threading.Lock()
_lists_lock = threading.Lock()
SERVER_PORT = None
server = None
_shutdown_event = threading.Event() #event to extra triple make sure threads shut down


SCAN_INTERVAL = 5
OFFLINE_TIMEOUT = 10.0


# Server cleanup on exit
def cleanup_server():
    """cleans up the server at program end"""
    _shutdown_event.set()  # tell threads to exit
    global server
    with _server_lock:
        if server is not None:
            try:
                server.close()
            except Exception:
                pass

#assign cleanup_server() to be run at program termination
atexit.register(cleanup_server)


# Server start / accept loop
def start_server():
    """starts the listening server thread"""
    if not session.email:
        return
    threading.Thread(target=run_server, daemon=True).start()

def run_server():
    """runs the server
    the function that actually runs the listening server, looks for an open port binds to the open port, then listens on the port and waits running handle_request()
    no Return"""
    global server, SERVER_PORT
    HOST = "0.0.0.0"
    s = None
    for port in range(12345, 12355):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #this was causing it to just use the same port
            s.bind((HOST, port))
            s.listen(10)
            s.settimeout(10)
            SERVER_PORT = port
            print(f"[Server] Listening on port: {port}")
            break
        except OSError as e:
            s.close()
            continue

    if s is None:
        print("[Server] Failed to bind any port.")
        return

    with _server_lock:
        server = s

    try:
        while not _shutdown_event.is_set(): #this is changed so the threads don't hang and the program exits
            try:
                client_socket, _ = server.accept()
                threading.Thread(target=handle_request, args=(client_socket,), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception:
                continue
    finally:
        with _server_lock:
            if server:
                try:
                    server.close()
                except:
                    pass
            server = None


# receive all
def recv_all(sock, n):
    """receive all
    receives all data from sock
    Args:
        sock (socket): socket to receive from
         n (int): block size to receive the data in
    Returns:
        returns the data taken in from the socket
        """
    data = b""
    while len(data) < n:
        try:
            packet = sock.recv(n - len(data))
        except (socket.timeout, ConnectionResetError):
            return None
        if not packet:
            return None
        data += packet
    return data


# Framing helpers (length-prefixed)
def send_block(sock, data: bytes):
    """send a block of data from sock
    attempts to send a block of data from sock
    Args:
        sock (socket): socket to send the data from
        data (bytes): bytes stream of data to be sent
    """
    if not isinstance(data, (bytes, bytearray)):
        return
    try:
        sock.sendall(len(data).to_bytes(4, "big") + data)
    except (BrokenPipeError, ConnectionResetError, OSError):
        return

#receive block of data
def recv_block(sock):
    try:
        len_bytes = recv_all(sock, 4)
        if not len_bytes:
            return None
        length = int.from_bytes(len_bytes, "big")
        if length <= 0:
            return None
        return recv_all(sock, length)
    except (socket.timeout, ConnectionResetError):
        return None


def send_file(sock, filename):
    """sends the file at filepath using sock
    send the file at filepath using the sock socket that is passed in, sock should already be connected to another socket
    assumes valid filepath and connected socket
    Args:
        sock (socket): the socket to send the file from
        filename (string): name of the file to send
    Returns:
        none
    """
    filesize = os.path.getsize(filename)

    send_block(sock, b"FILE")
    send_block(sock, filename.encode())
    send_block(sock, filesize.to_bytes(8, "big"))

    with open(filename, "rb") as f:
        while chunk := f.read(4096):
            sock.sendall(chunk)

    print("[Client] File sent")


def receive_file(sock, sender_email):
    """receives a file from sock, and says the sender once received

    receives a file from the passed in socket, and saves the file in 'received_files' directory

    Args:
        sock (socket): socket to receive the file from
        sender_email (string): the email of the sender, to be printed out
    Returns:
        none
        """
    # filename
    filename = recv_block(sock).decode()
    filesize = int.from_bytes(recv_block(sock), "big")

    os.makedirs(f"received_files{session.full_name}", exist_ok=True) #TODO change made so that each user has their own received directory
    path = os.path.join(f"received_files{session.full_name}", filename)

    received = 0

    with open(path, "wb") as f:
        received = 0
        while received < filesize:
            try:
                chunk = sock.recv(min(4096, filesize - received))
            except (socket.timeout, ConnectionResetError):
                break
            if not chunk:
                break
            f.write(chunk)
            received += len(chunk)

    print(f"[File] Received {filename} from {sender_email}")

def authenticate_socket_as_server(sock):
    """
    Perform mutual authentication on an already-connected socket.

    Returns:
        their_email (str)

    Raises:
        Exception if authentication fails
    """
    sock.settimeout(6)

    # Step 1: send nonce
    nonce = os.urandom(16)
    send_block(sock, nonce)

    # Step 2: receive signed nonce + certificate
    signed_nonce = recv_block(sock)
    cert_bytes = recv_block(sock)

    if not signed_nonce or not cert_bytes:
        raise Exception("Missing auth data")

    try:
        cert_text = cert_bytes.decode().strip()
    except Exception:
        raise Exception("Invalid certificate encoding")

    if not cert_text.startswith("-----BEGIN CERTIFICATE-----"):
        raise Exception("Invalid certificate format")

    # Verify certificate
    ca_public = load_ca_public_key()
    if not verify_certificate_data(cert_text, ca_public):
        raise Exception("Certificate verification failed")

    their_email = extract_email_from_cert(cert_text)
    if not their_email:
        raise Exception("No email in certificate")

    client_public_key = load_public_key_cert_from_text(cert_text)

    # Verify nonce signature
    if not verify_signature_bytes(nonce, signed_nonce, client_public_key):
        raise Exception("Invalid nonce signature")

    # Authorization: must be in contacts
    if their_email not in load_contacts():
        raise Exception("Unauthorized contact")

    # Step 3: send server proof
    cert_path = f"data/certificate/{session.email}.crt"
    if not os.path.exists(cert_path):
        raise Exception("Server certificate missing")

    server_cert = read_certificate_file(cert_path)
    send_block(sock, server_cert)

    server_email_bytes = session.email.encode()
    server_sig = sign_bytes(server_email_bytes, session.private_key)
    send_block(sock, server_sig)

    # Step 4: receive client confirmation
    client_conf_sig = recv_block(sock)
    if not client_conf_sig:
        raise Exception("Client confirmation missing")

    if not verify_signature_bytes(
        server_email_bytes, client_conf_sig, client_public_key
    ):
        raise Exception("Client confirmation invalid")

    return their_email


def handle_request(client_socket):
    """
    Authenticate the client socket, then handle commands.
    """
    their_email = None
    try:
        their_email = authenticate_socket_as_server(client_socket)

        with _lists_lock:
            online_contacts[their_email] = (client_socket, time.time())

        # Command loop
        while not _shutdown_event.is_set():
            cmd = recv_block(client_socket)
            if not cmd:
                break

            if cmd == b"FILE":
                print("file command received") #FIXME debugging
                receive_file(client_socket, their_email)

            elif cmd == b"QUIT":
                print("quit command received") #FIXME debugging
                break

    except Exception as e:
        print(f"[Auth / Connection error] {e}")

    finally:
        try:
            client_socket.close()
        except Exception:
            pass
def connect_and_authenticate(ip, port):
    """
    Create a socket, authenticate as client, and return (email, socket).

    Returns:
        (server_email, sock) on success
        None on failure
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(6)

    try:
        sock.connect((ip, port))

        # Receive nonce
        nonce = recv_block(sock)
        if not nonce:
            raise Exception("No nonce")

        # Send signed nonce + certificate
        signature = sign_bytes(nonce, session.private_key)
        send_block(sock, signature)

        cert_path = f"data/certificate/{session.email}.crt"
        with open(cert_path, "rb") as f:
            send_block(sock, f.read())

        # Receive server certificate + signature
        serv_cert_bytes = recv_block(sock)
        serv_sig = recv_block(sock)
        if not serv_cert_bytes or not serv_sig:
            raise Exception("Server proof missing")

        serv_cert_text = serv_cert_bytes.decode().strip()

        ca_public = load_ca_public_key()
        if not verify_certificate_data(serv_cert_text, ca_public):
            raise Exception("Invalid server certificate")

        server_email = extract_email_from_cert(serv_cert_text)
        server_public_key = load_public_key_cert_from_text(serv_cert_text)

        server_email_bytes = server_email.encode()
        if not verify_signature_bytes(
            server_email_bytes, serv_sig, server_public_key
        ):
            raise Exception("Server signature invalid")

        # Confirm mutual
        conf_sig = sign_bytes(server_email_bytes, session.private_key)
        send_block(sock, conf_sig)

        return server_email, sock

    except Exception as e:
        print(f"[Client auth failed] {e}")
        try:
            sock.close()
        except Exception:
            pass
        return None


# Client-side mutual exchange (for discovery)
def check_contact_certificate_exchange(ip, port):
    """client side mutual authentication

    attempts the client side mutual authentication of handle_request(), creates a socket and connects to the passed in ip and port
    performs the mutual authentication, then returns the server email and the connected socket if successful

    Args:
        ip (string): ip to connect to with the created socket
        port (int): the port to connect to with the created socket
    Returns:
        success: (server_email, sock)
            server_email (string): the email of the server the socket connected to
            sock (socket): the live socket connected to the server
        failure: None
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((ip, port))

        # Step 1: receive nonce
        nonce = recv_block(sock)
        if not nonce:
            sock.close()
            return None

        # Step 2: sign nonce and send signed_nonce and our certificate
        signature = sign_bytes(nonce, session.private_key)
        send_block(sock, signature)

        our_cert_path = f"data/certificate/{session.email}.crt"
        if not os.path.exists(our_cert_path):
            sock.close()
            return None
        with open(our_cert_path, "rb") as f:
            cert_bytes = f.read()
        send_block(sock, cert_bytes)

        # Step 3: try to receive server certificate (server will only send if they have us in their contacts)
        # If server did not have us in their contacts it likely closed; attempt to read may time out
        serv_cert_bytes = recv_block(sock)
        if not serv_cert_bytes:
            sock.close()
            return None

        # Step 4: server signature over server email
        serv_sig = recv_block(sock)
        if not serv_sig:
            sock.close()
            return None

        # decode and verify server certificate
        try:
            serv_cert_text = serv_cert_bytes.decode().strip()
        except Exception:
            sock.close()
            return None
        if not serv_cert_text.startswith("-----BEGIN CERTIFICATE-----"):
            sock.close()
            return None

        ca_public = load_ca_public_key()
        if not verify_certificate_data(serv_cert_text, ca_public):
            sock.close()
            return None

        # Extract and validate server email
        server_email = extract_email_from_cert(serv_cert_text)

        # Check for empty AND ensure it's a string
        if not server_email or not isinstance(server_email, str):
            sock.close()
            return None

        server_public_key = load_public_key_cert_from_text(serv_cert_text)

        # Verify server signature over server_email
        # Now safe to encode
        server_email_bytes = server_email.encode()
        if not verify_signature_bytes(server_email_bytes, serv_sig, server_public_key):
            sock.close()
            return None

        # Step 5: confirm mutual by checking our contacts and sending confirmation signature
        my_contacts = load_contacts()
        if server_email not in my_contacts:
            sock.close()
            # We don't have them; not mutual
            return None

        # Create confirmation signature over server_email
        # Add safety check for session state
        if not hasattr(session, 'private_key') or not session.private_key:
            sock.close()
            return None

        conf_sig = sign_bytes(server_email_bytes, session.private_key)
        send_block(sock, conf_sig)

        # If server verifies, we assume success and can return server_email and connected socket
        return server_email, sock

    except Exception:
        sock.close()
        return None


# Discovery / scanner
def _get_local_ips():
    """Return a small set of local ips to probe (loopback + host ip)."""
    ips = ["127.0.0.1", "localhost"]
    try:
        hostname = socket.gethostname()
        host_ip = socket.gethostbyname(hostname)
        if host_ip not in ips:
            ips.append(host_ip)
    except:
        pass
    return ips

def search_for_contacts():
    """Scan likely ports on local IPs and attempt mutual authentication."""
    if not session.email:
        return []

    likely_ports = range(12345, 12355)
    results = dict()
    threads = []
    lock = threading.Lock()

    def probe(ip, port):
        if port == SERVER_PORT:
            return
        contact = check_contact_certificate_exchange(ip, port)
        if contact is not None:
            email, foundSock = contact
            # they both exist :)
            with lock:
                results[email] = foundSock

    for ip in _get_local_ips():
        for port in likely_ports:
            t = threading.Thread(target=probe, args=(ip, port), daemon=True)
            threads.append(t)
            t.start()

    # join with small timeout to keep scanner responsive
    for t in threads:
        t.join(timeout=1.5)

    return results

def start_background_scanner():
    """starts the background scanner threads"""
    threading.Thread(target=scanner, daemon=True).start()

def scanner():
    """scans for online known contacts, and the time they were last connected to"""
    while not _shutdown_event.is_set():
        if not session.email:
            time.sleep(SCAN_INTERVAL)
            continue
        discovered = search_for_contacts()
        now = time.time()

        with _lists_lock:
            for email in discovered.keys():
                my_contacts = load_contacts()
                if email in my_contacts:
                    online_contacts[email] = (discovered[email], now)

            #handle stale connections for security
            stale = []

            for info in online_contacts.values():
                timeConnected = info[1]
                if (now - timeConnected) > OFFLINE_TIMEOUT:

                    stale.append(email)

            for email in stale:
                online_contacts.pop(email)

        time.sleep(SCAN_INTERVAL)


# List online (mutual) contacts
def list_online_contacts():
    """lists the online mutual contacts, and lists them as well as how long since last connected
    Returns:
        false if none online
        true if there are contacts online
        """
    with _lists_lock:
        if len(online_contacts.keys()) == 0:
            #no online contacts
            print("No mutual contacts currently online")
            return False
        my_contacts = load_contacts() #load my contacts
        now = time.time() #get now for the timestamp
        print("Online contacts (mutual only):")
        for email in online_contacts.keys():
            if email not in my_contacts:
                continue
            name = my_contacts[email].get("full_name", email)
            age = (now - online_contacts[email][1])
            print(f"* {name} ({email}) — last seen {age}s ago")
    #only gets here if there were online contacts found
    return True