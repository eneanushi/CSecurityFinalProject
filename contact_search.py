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
online_contacts = {}       
_server_lock = threading.Lock()
_lists_lock = threading.Lock()
SERVER_PORT = None
server = None
_shutdown_event = threading.Event()


SCAN_INTERVAL = 5
OFFLINE_TIMEOUT = 10  


# Server cleanup on exit
def cleanup_server():
    _shutdown_event.set()  # tell threads to exit
    global server
    with _server_lock:
        if server:
            try:
                server.close()
            except Exception:
                pass

#assign cleanup_server() to be run at program termination
atexit.register(cleanup_server)


# Server start / accept loop
def start_server():
    if not session.email:
        return
    threading.Thread(target=run_server, daemon=True).start()

def run_server():
    global server, SERVER_PORT
    HOST = "0.0.0.0"
    s = None
    for port in range(12345, 12355):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #this was causing it to just use the same port
            s.bind((HOST, port))
            s.listen(5)
            #s.settimeout(1)
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
    sock.sendall(len(data).to_bytes(4, "big") + data)

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

def send_file(sock, filepath):
    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)

    send_block(sock, b"FILE")
    send_block(sock, filename.encode())
    send_block(sock, filesize.to_bytes(8, "big"))

    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            sock.sendall(chunk)

    print("[Client] File sent")


def receive_file(sock, sender_email):
    # filename
    filename = recv_block(sock).decode()
    filesize = int.from_bytes(recv_block(sock), "big")

    os.makedirs("received_files", exist_ok=True)
    path = os.path.join("received_files", filename)

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


# Mutual-consent protocol (server side)
def handle_request(client_socket):
   
    their_email = None
    try:
        client_socket.settimeout(6)

        # Step 1: send nonce
        nonce = os.urandom(16)
        send_block(client_socket, nonce)

        # Step 2: receive signed_nonce and client cert
        signed_nonce = recv_block(client_socket)
        if not signed_nonce:
            return

        cert_bytes = recv_block(client_socket)
        if not cert_bytes:
            return

        # cert as text
        try:
            cert_text = cert_bytes.decode().strip()
        except Exception:
            return

        if not cert_text.startswith("-----BEGIN CERTIFICATE-----"):
            return

        # Verify certificate
        ca_public = load_ca_public_key()
        if not verify_certificate_data(cert_text, ca_public):
            return

        their_email = extract_email_from_cert(cert_text)
        if not their_email:
            return

        client_public_key = load_public_key_cert_from_text(cert_text)

        # Verify signature over nonce
        if not verify_signature_bytes(nonce, signed_nonce, client_public_key):
            return

        # Save certificate locally for future encrypted sends
        try:
            save_certificate_from_data(cert_text, their_email)
        except Exception:
            pass

        # Step 4: check if server has them in our contacts
        my_contacts = load_contacts()
        if their_email not in my_contacts:
            # Not in our contacts: do not proceed with mutual confirmation
            return

        # Step 4b: send our certificate and signature over our email
        our_cert_path = f"data/certificate/{session.email}.crt"
        if not os.path.exists(our_cert_path):
            # can't proceed without our certificate saved
            return

        # Read our certificate bytes
        our_cert_bytes = read_certificate_file(our_cert_path)

        # Create a signature over our email to let client verify identity (server proof)
        # Ensure session.email is a string
        if not isinstance(session.email, str):
            return  # Invalid session state

        server_email_bytes = session.email.encode()
        server_sig = sign_bytes(server_email_bytes, session.private_key)

        # Send server certificate then signature (both length-prefixed)
        send_block(client_socket, our_cert_bytes)
        send_block(client_socket, server_sig)

        # Step 5: receive client's confirmation signature over server_email
        client_conf_sig = recv_block(client_socket)
        if not client_conf_sig:
            return

        # Step 6: verify client's confirmation signature using client's public key
        if not verify_signature_bytes(server_email_bytes, client_conf_sig, client_public_key):
            return

        # Mutual confirmed: mark them online
        with _lists_lock:
            online_contacts[their_email] = time.time()

    except Exception:
        # silent on purpose; caller code previously relied on silent failures
        return
    # AFTER mutual authentication succeeds
    while not _shutdown_event.is_set():
            cmd = recv_block(client_socket)
            if not cmd:
                break

            if cmd == b"FILE":
                receive_file(client_socket, their_email)

            elif cmd == b"QUIT":
                break


# Client-side mutual exchange (for discovery)
def check_contact_certificate_exchange(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
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

        # If server verifies, we assume success and can return server_email
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
    threading.Thread(target=scanner, daemon=True).start()

def scanner():
    while not _shutdown_event.is_set():
        if not session.email:
            time.sleep(SCAN_INTERVAL)
            continue
        discovered = search_for_contacts()
        now = time.time()

        with _lists_lock:
            for email, sock in discovered.items():
                my_contacts = load_contacts()
                if email in my_contacts:
                    online_contacts[email] = (sock, now)

            stale = []

            for email, info in online_contacts.items():
                if isinstance(info, tuple) and len(info) == 2:
                    _, ts = info
                else:
                    # legacy float-only entry
                    ts = info

                if now - ts > OFFLINE_TIMEOUT:
                    stale.append(email)

            for e in stale:
                online_contacts.pop(e, None)

        time.sleep(SCAN_INTERVAL)


# List online (mutual) contacts
def list_online_contacts():
    with _lists_lock:
        if not online_contacts:
            print("No mutual contacts currently online")
            return

        my_contacts = load_contacts()
        now = time.time()

        print("Online contacts (mutual only):")
        for email, info in sorted(online_contacts.items()):
            if email not in my_contacts:
                continue

            # Handle both old float entries and new tuple entries
            if isinstance(info, tuple) and len(info) == 2:
                _, last_seen = info
            else:
                # fallback for old float-only entries
                last_seen = info

            name = my_contacts[email].get("full_name", email)
            age = int(now - last_seen)
            print(f"* {name} ({email}) — last seen {age}s ago")

