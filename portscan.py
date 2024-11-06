import socket
import threading
import tkinter as tk
from queue import Queue
from datetime import datetime

from knownports import persistence_attack_ports

# Set target address and port range
addr = '127.0.0.1'
start_port = 1
end_port = 1000
num_threads = 1000  # Number of worker threads

# Create a queue to hold the ports to scan
port_queue = Queue()

global open_ports
open_ports=[]

global scan_stats
scan_stats = []

global scan_results
scan_results = []

def format_timedelta(td):
    total_seconds = int(td.total_seconds())
    days = total_seconds // 86400
    hours = (total_seconds % 86400) // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    milliseconds = int(td.microseconds / 1000)  # Convert microseconds to milliseconds

    # Construct a formatted string
    formatted_str = ""
    if days > 0:
        formatted_str += f"{days} day{'s' if days > 1 else ''}, "
    if hours > 0 or days > 0:
        formatted_str += f"{hours:02} hours, "
    formatted_str += f"{minutes:02} minutes, {seconds:02} seconds"
    
    # Append milliseconds if needed
    if milliseconds > 0:
        formatted_str += f", {milliseconds} milliseconds"

    return formatted_str.strip(", ")

# Function to scan a single port
def scanport(addr, port):
    '''Check if a port is open on the target address.'''
    socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_obj.settimeout(0.5)  # Use a small timeout for faster scans
    result = socket_obj.connect_ex((addr, port))
    socket_obj.close()

    if result == 0:
        #print(f"Port {port} is open.")
        open_ports.append(port)

# Worker function for each thread
def worker(addr):
    '''Thread worker function that scans ports from the queue.'''
    while not port_queue.empty():
        port = port_queue.get()
        scanport(addr, port)
        port_queue.task_done()
        #return open_ports

# Function to start the port scanner using multithreading
def portscanner(addr, start_port, end_port, num_threads):
    # Populate the queue with the port numbers to scan
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    # Create and start threads
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(addr,))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    # Wait for all tasks in the queue to be completed
    port_queue.join()

    # Ensure all threads have finished execution
    for thread in threads:
        thread.join()

    #print("Port scanning completed.")


def bannergrabbing(addr, port):
    '''Connect to process and return application banner'''
    print("Gettig service information for port: ", port)
    bannergrabber = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    socket.setdefaulttimeout(2)
    try:
        bannergrabber.connect((addr, port))
        bannergrabber.send('WhoAreYou\r\n')
        banner = bannergrabber.recv(100)
        bannergrabber.close()
        print(banner, "\n")

        scan_results.append((port,banner))
    except:
        scan_results.append((port,"Cannot connect to port "))

def get_service_banners_for_host(address, portlist):
    for port in portlist:
        bannergrabbing(addr, port)


def button_click_port(lbl):
    lbl.insert(tk.END, "Scanning for results")
    start_time = datetime.now()
    
    # Start the port scanner with multiple threads
    portscanner(addr, start_port, end_port, num_threads)

    get_service_banners_for_host(addr, open_ports)

    end_time = datetime.now()

    duration = end_time - start_time
    time = format_timedelta(duration)
    scan_stats.append(start_time)
    scan_stats.append(end_time)
    scan_stats.append(time)
    scan_stats.append(len(open_ports))
    display_information(lbl)

def display_information(l):
    l.delete("1.0", tk.END)
    l.insert(tk.END,"-- Port Scan results --" + "\n")
    l.insert(tk.END,"Scan Stats: " + "\n")
    l.insert(tk.END, "Number of open ports: " + str(len(open_ports)) + "\n")
    l.insert(tk.END, "Duration of scan: " + scan_stats[2] + "\n")
    l.insert(tk.END, "\nPort\tBanner\t\tPersistence Analysis\n")
    l.insert(tk.END, '-'*80 + "\n")
    for port,banner in scan_results:
        if port in persistence_attack_ports:
            x = persistence_attack_ports.get(port)
            line = str(port) + "\t" + banner + "\t\t" + x['description'] + "\n"
        else:
            line = str(port) + "\t" + banner + "\t\t-\n"
        l.insert(tk.END, line)