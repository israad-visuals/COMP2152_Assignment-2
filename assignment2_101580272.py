"""
Author: ISMAIL ABDI
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

# TODO: Import the required modules (Step ii)
# socket, threading, sqlite3, os, platform, datetime
import socket
import sqlite3
import threading
import os
import platform
import datetime


# TODO: Print Python version and OS name (Step iii)
print("Python Version:" , platform.python_version())
print("Operating System:" , os.name)

# TODO: Create the common_ports dictionary (Step iv)
# Add a 1-line comment above it explaining what it stores

# This dictionary maps each port number to the name of the service that usually runs on it .It basically gives it its name.
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}


# TODO: Create the NetworkTool parent class (Step v)
# - Constructor: takes target, stores as private self.__target
# - @property getter for target
# - @target.setter with empty string validation
# - Destructor: prints "NetworkTool instance destroyed"

# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool so it gets the target property and the setter for free without rewriting them.
# For example when we call super().__init__(target) in PortScanner it runs the parent constructor to store the target.
# This means PortScanner can use self.target to get the IP address even though that code is in NetworkTool.

class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter lets us control how the target is read and changed.
    # If someone tries to set the target to an empty string the setter will block it and print an error.
    # Without this we would have no way to stop bad values from being assigned to __target directly.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")




# TODO: Create the PortScanner child class that inherits from NetworkTool (Step vi)
# - Constructor: call super().__init__(target), initialize self.scan_results = [], self.lock = threading.Lock()
# - Destructor: print "PortScanner instance destroyed", call super().__del__()
#
# - scan_port(self, port):
#
#     TODO: Your 2-4 sentence answer here... (Part 2, Q4)
#
#     - try-except with socket operations
#     - Create socket, set timeout, connect_ex
#     - Determine Open/Closed status
#     - Look up service name from common_ports (use "Unknown" if not found)
#     - Acquire lock, append (port, status, service_name) tuple, release lock
#     - Close socket in finally block
#     - Catch socket.error, print error message
#
# - get_open_ports(self):
#     - Use list comprehension to return only "Open" results
#
#
#
# - scan_range(self, start_port, end_port):
#     - Create threads list
#     - Create Thread for each port targeting scan_port
#     - Start all threads (one loop)
#     - Join all threads (separate loop)

class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):
        # Q4: What would happen without try-except here?
        # If we didnt have try-except and we tried to scan a machine that is not reachable the program would crash.
        # Python would raise a socket.error and stop running completely instead of moving to the next port.
        # The try-except catches the error so we can print a message and keep going without the program breaking.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            # look up service name from common_ports dictionary
            if port in common_ports:
                service_name = common_ports[port]
            else:
                service_name = "Unknown"

            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
        finally:
            sock.close()

    def get_open_ports(self):
        # use list comprehension to filter only open ports
        open_ports = [r for r in self.scan_results if r[1] == "Open"]
        return open_ports


# Q2: Why do we use threading instead of scanning one port at a time?
#     Threading lets us scan many ports at the same time instead of waiting for each one to finish.
#      If we scanned 1024 ports one by one and each one takes up to 1 second timeout it could take over 17 minutes.
#     With threads they all run at once so the whole scan finishes in just a few seconds which is way faster.

    def scan_range(self, start_port, end_port):
        threads = []
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)

        # start all threads
        for t in threads:
            t.start()

        # join all threads in separate loop
        for t in threads:
            t.join()


# TODO: Create save_results(target, results) function (Step vii)
# - Connect to scan_history.db
# - CREATE TABLE IF NOT EXISTS scans (id, target, port, status, service, scan_date)
# - INSERT each result with datetime.datetime.now()
# - Commit, close
# - Wrap in try-except for sqlite3.Error

def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )""")

        for result in results:
            cursor.execute("INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                           (target, result[0], result[1], result[2], str(datetime.datetime.now())))

        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"Database error: {e}")


# TODO: Create load_past_scans() function (Step viii)
# - Connect to scan_history.db
# - SELECT all from scans
# - Print each row in readable format
# - Handle missing table/db: print "No past scans found."
# - Close connection

def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()
        for row in rows:
            print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
        conn.close()
    except:
        print("No past scans found.")


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    # TODO: Get user input with try-except (Step ix)
    # - Target IP (default "127.0.0.1" if empty)
    # - Start port (1-1024)
    # - End port (1-1024, >= start port)
    # - Catch ValueError: "Invalid input. Please enter a valid integer."
    # - Range check: "Port must be between 1 and 1024."

    # TODO: After valid input (Step x)
    # - Create PortScanner object
    # - Print "Scanning {target} from port {start} to {end}..."
    # - Call scan_range()
    # - Call get_open_ports() and print results
    # - Print total open ports found
    # - Call save_results()
    # - Ask "Would you like to see past scan history? (yes/no): "
    # - If "yes", call load_past_scans()

    try:
        target = input("Enter target IP (default 127.0.0.1): ")
        if target == "":
            target = "127.0.0.1"

        start_port = int(input("Enter start port (1-1024): "))
        end_port = int(input("Enter end port (1-1024): "))

        if start_port < 1 or start_port > 1024 or end_port < 1 or end_port > 1024:
            print("Port must be between 1 and 1024.")
        elif end_port < start_port:
            print("End port must be greater than or equal to start port.")
        else:
            scanner = PortScanner(target)
            print(f"Scanning {target} from port {start_port} to {end_port}...")
            scanner.scan_range(start_port, end_port)

            open_ports = scanner.get_open_ports()
            print(f"\n--- Scan Results for {target} ---")
            for port_info in open_ports:
                print(f"Port {port_info[0]}: {port_info[1]} ({port_info[2]})")
            print("------")
            print(f"Total open ports found: {len(open_ports)}")

            save_results(target, scanner.scan_results)

            choice = input("Would you like to see past scan history? (yes/no): ")
            if choice == "yes":
                load_past_scans()
    except ValueError:
        print("Invalid input. Please enter a valid integer.")


# Q5: New Feature Proposal
# I would add a Port Risk Classifier feature that looks at each open port and gives it a risk level.
# It uses a nested if-statement to check if the port is in a list of high risk ports like 21, 22, 23, 3389
# and if not it checks if its in medium risk ports like 25, 110, 143, 3306 and everything else is low risk.
# This helps the user quickly see which open ports are the most dangerous.
# Diagram: See diagram_101580272.png in the repository root