from scapy.all import sniff
import threading
import tkinter as tk
import queue
from datetime import datetime
from net import flag_packet

# Global variables
rst_flag = threading.Event()
thread_start = None
result_display = None  # Will be set from the main GUI file
packet_queue = queue.Queue()  # Thread-safe queue to pass packets

def packet_show(packet):
    print(packet)

def cbk(packet):
    #print(packet)
    global packet_queue
    if flag_packet(packet):
        packet_queue.put(('MALICIOUS', packet.summary()))
    else:
        packet_queue.put(('NORMAL', packet.summary()))  # Place the packet summary into the queue

def process_queue():
    """Poll the queue and update the result_display in the main GUI thread."""
    global result_display
    while not packet_queue.empty():
        packet_type, packet_summary = packet_queue.get_nowait()
        if result_display:
            if packet_type == 'MALICIOUS':
                result_display.insert(tk.END, packet_summary + "\n", 'malicious')
            else:
                result_display.insert(tk.END, packet_summary + "\n")
            result_display.see(tk.END)  # Auto-scroll to the latest entry
    result_display.after(100, process_queue)  # Schedule the next queue check

def scan(filter_str):
    global rst_flag
    try:
        while not rst_flag.is_set():
            sniff(prn=cbk, store=0, timeout=1, filter=filter_str, stop_filter=lambda x: rst_flag.is_set())
    except Exception as e:
        print(f"Error during scanning: {e}")

def starting_function(filter_str):
    global thread_start, rst_flag
    if thread_start is None or not thread_start.is_alive():
        rst_flag.clear()  # Ensure the flag is clear before starting
        thread_start = threading.Thread(target=scan, args=(filter_str,), daemon=True)  # Pass filter_str
        thread_start.start()

def stop_function():
    global rst_flag, thread_start, packet_queue
    if thread_start is not None and thread_start.is_alive():
        rst_flag.set()  # Signal the thread to stop
        thread_start.join()  # Wait for the thread to finish
        thread_start = None  # Reset the thread for future use
        packet_queue.queue.clear()  # Clear any remaining packets in the queue

def set_result_display(display_widget):
    global result_display
    result_display = display_widget
    # Configure the tag for malicious packets
    result_display.tag_configure('malicious', foreground='red')
    process_queue()  # Start processing the queue immediately

def button_start_scan(filter_str):
    result_display.insert(tk.END, "Starting Scan at: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n\n\n")
    result_display.see(tk.END)
    starting_function(filter_str)
    print(threading.enumerate())

def button_stop_scan():
    stop_function()
    result_display.insert(tk.END, "\n\n\nStopping Scan at: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n\n\n")
    result_display.see(tk.END)
    print(threading.enumerate())

def button_apply_filter(filter_str):
    stop_function()
    starting_function(filter_str)