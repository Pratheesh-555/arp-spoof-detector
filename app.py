# from flask import Flask, render_template, request, redirect, url_for, session, jsonify
# from flask_socketio import SocketIO
# import sqlite3
# import bcrypt
# import threading
# from scapy.all import ARP, sniff

# app = Flask(__name__)
# app.secret_key = 'e2f89b67d8d2a3d81b912fcdf63ad9cfb47a7a95b7c77d32'  # Secret key for session management
# socketio = SocketIO(app)

# arp_cache = {}
# notifications = []  # List to store notifications

# # Function to detect ARP spoofing
# def detect_arp_spoof(packet):
#     if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP replies only
#         ip = packet[ARP].psrc
#         mac = packet[ARP].hwsrc

#         if ip in arp_cache:
#             if arp_cache[ip] != mac:
#                 alert_msg = f"ARP Spoofing detected! IP: {ip} was {arp_cache[ip]}, now {mac}"
#                 notifications.append(alert_msg)
#                 # Emit the new alert to the web interface
#                 socketio.emit('new_alert', alert_msg)
#         else:
#             arp_cache[ip] = mac

# # Function to sniff ARP packets
# def start_sniffing():
#     sniff(store=False, prn=detect_arp_spoof)

# # Start sniffing in a thread
# def start_detection():
#     t = threading.Thread(target=start_sniffing)
#     t.start()

# # Helper function to check user credentials from the database
# def check_user_credentials(username, password):
#     conn = sqlite3.connect('users.db')
#     cursor = conn.cursor()

#     cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
#     result = cursor.fetchone()

#     conn.close()

#     if result:
#         stored_password = result[0]
#         # Check if the entered password matches the hashed password in the database
#         return bcrypt.checkpw(password.encode('utf-8'), stored_password)  # No need to encode stored_password
#     return False
#     # if username == 'username' and password == 'password':
#     #     return True
#     # return False

# # Flask route for the login page
# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']
        
#         # Check credentials against the database
#         if check_user_credentials(username, password):
#             session['logged_in'] = True
#             return redirect(url_for('index'))
#         else:
#             return render_template('login.html', error="Invalid credentials")
#     return render_template('login.html')

# # Flask route for the logout page
# @app.route('/logout')
# def logout():
#     session.pop('logged_in', None)
#     return redirect(url_for('login'))

# # Flask route for the ARP detection interface (requires login)
# @app.route('/')
# def index():
#     if not session.get('logged_in'):
#         return redirect(url_for('login'))
#     return render_template('index.html')

# @app.route('/notifications')
# def get_notifications():
#     if not session.get('logged_in'):
#         return redirect(url_for('login'))
#     return jsonify(notifications)

# @app.route('/arp_cache')
# def get_arp_cache():
#     if not session.get('logged_in'):
#         return redirect(url_for('login'))
#     return jsonify(arp_cache)

# @app.route('/simulate_multiple_spoofs')
# def simulate_multiple_spoofs():
#     # Simulated data for multiple IP-MAC pairs
#     simulated_spoofing_data = {
#         "192.168.1.2": "99:88:77:66:55:45",
#         "192.168.1.3": "88:77:66:55:44:23",
#         "192.168.1.4": "77:66:55:44:33:22",
#         "192.168.1.5": "99:88:77:66:55:25",
#         "192.168.1.6": "88:77:66:55:44:13",
#         "192.168.1.7": "77:66:55:44:33:62",
#         "192.168.1.8": "99:88:77:66:55:15",
#         "192.168.1.9": "88:77:66:55:44:16",
#         "192.168.1.10": "77:66:55:44:33:82",
#     }
#     for ip, spoofed_mac in simulated_spoofing_data.items():
#         if ip in arp_cache:
#             if arp_cache[ip] != spoofed_mac:
#                 alert_msg = f"ARP Spoofing detected! IP: {ip} was {arp_cache[ip]}, now {spoofed_mac}"
#                 notifications.append(alert_msg)
#                 socketio.emit('new_alert', alert_msg)
#         else:
#             arp_cache[ip] = spoofed_mac



# if __name__ == '__main__':
#     start_detection()
#     socketio.run(app, host='0.0.0.0', port=5002)

# frontend_demo_safe.py
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = "demo-secret-key-pk"  # demo-only
socketio = SocketIO(app, cors_allowed_origins="*")

# In-memory demo state (safe)
arp_cache = {}
notifications = []

# Demo credentials (safe, hardcoded for presentation)
DEMO_USER = {"username": "pk", "password": "pkpass"}

# Home (requires login)
@app.route("/")
def index():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("index.html")

# Simple demo login (no DB, no bcrypt)
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == DEMO_USER["username"] and password == DEMO_USER["password"]:
            session["logged_in"] = True
            return redirect(url_for("index"))
        return render_template("login.html", error="Invalid credentials (demo)")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))

# Return notifications (JSON)
@app.route("/notifications")
def get_notifications():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return jsonify(notifications)

# Return current (demo) ARP cache
@app.route("/arp_cache")
def get_arp_cache():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return jsonify(arp_cache)

# Populate sample ARP entries (safe)
@app.route("/load")
def load_sample_arp():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    sample = {
        "192.168.1.2": "00:11:22:33:44:55",
        "192.168.1.3": "66:77:88:99:AA:BB",
        "192.168.1.4": "aa:bb:cc:dd:ee:ff",
    }
    arp_cache.update(sample)
    return jsonify({"status": "ok", "loaded": sample})

# Simulate a batch of spoof events (safely)
@app.route("/simulate")
def simulate_multiple_spoofs():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    simulated_spoofing_data = {
        "192.168.1.2": "99:88:77:66:55:45",
        "192.168.1.3": "88:77:66:55:44:23",
        "192.168.1.4": "77:66:55:44:33:22",
        "192.168.1.5": "99:88:77:66:55:25",
        "192.168.1.6": "88:77:66:55:44:13",
    }

    for ip, spoofed_mac in simulated_spoofing_data.items():
        if ip in arp_cache:
            if arp_cache[ip] != spoofed_mac:
                alert_msg = f"ARP Spoofing detected! IP: {ip} was {arp_cache[ip]}, now {spoofed_mac}"
                notifications.append(alert_msg)
                socketio.emit("new_alert", alert_msg)
        else:
            arp_cache[ip] = spoofed_mac

    return jsonify({"status": "simulated", "count": len(simulated_spoofing_data)})

# Simulate a single spoof (convenience)
@app.route("/simulate", methods=["POST"])
def simulate_spoof():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    data = request.json or {}
    ip = data.get("ip")
    mac = data.get("mac")
    if not ip or not mac:
        return jsonify({"error": "ip and mac required"}), 400

    if ip in arp_cache and arp_cache[ip] != mac:
        alert_msg = f"ARP Spoofing detected! IP: {ip} was {arp_cache[ip]}, now {mac}"
        notifications.append(alert_msg)
        socketio.emit("new_alert", alert_msg)
    else:
        arp_cache[ip] = mac
    return jsonify({"status": "ok", "ip": ip, "mac": mac})

# Reset all data (clear cache and notifications)
@app.route("/reset")
def reset():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    arp_cache.clear()
    notifications.clear()
    return jsonify({"status": "reset", "message": "All data cleared successfully"})

if __name__ == "__main__":
    # Run only the frontend demo. No sniffing, no privileged ops.
    socketio.run(app, host="0.0.0.0", port=5002, debug=True)
