#MainWindow.py

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog
import threading
import os
from SniffMod import button_start_scan, button_stop_scan, set_result_display, starting_function, button_apply_filter
from PassCheck import password_checker_call
#from document_scan import click
from dcs import button_call
from submitQ import submit_query
from nta import scan
from portscan import button_click_port

def onClickScan():
    #switch_frame(frame_scan)
    scan()

def onClickSniff():
    switch_frame(frame_sniff)

def onClickFaq():
    switch_frame(frame_faq)

def onClickHome():
    switch_frame(frame_default)

def onClickPWS():
    switch_frame(frame_pws)
    
def onClickDoc():
    switch_frame(frame_doc)

def onClickPort():
    switch_frame(frame_scan_p)

def switch_frame(new_frame):
    global currently_displayed_frame
    if currently_displayed_frame is not None:
        currently_displayed_frame.pack_forget()
    currently_displayed_frame = new_frame
    new_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)

def mainWindow(userName, passWord):
    global frame_scan, frame_sniff, frame_faq, frame_doc, frame_default, frame_pws, currently_displayed_frame, entry, frame_scan_p

    # CONSTANTS
    screenSize = "1000x680"
    colorSideBar = "#1d1d1d"
    default_color_but_darker = "#2d2d2d"
    customColor1 = "#4d4b4b"
    default_color = "#2B2B2B"
    # WINDOWS
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    root = ctk.CTk()
    root.title("--Title--")
    root.geometry(screenSize)

    # WIDGETS
    main_frame = ctk.CTkFrame(root, fg_color=default_color, bg_color=default_color)
    main_frame.pack(fill=tk.BOTH, expand=1)

    sidebar_frame = ctk.CTkFrame(main_frame, width=400, fg_color=colorSideBar, bg_color=colorSideBar)
    sidebar_frame.pack(side=tk.LEFT, fill=tk.Y)

    content_frame = ctk.CTkFrame(main_frame)
    content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)

    frame_default = ctk.CTkFrame(content_frame)
    frame_scan = ctk.CTkFrame(content_frame)
    frame_sniff = ctk.CTkFrame(content_frame)
    frame_faq = ctk.CTkFrame(content_frame)
    frame_pws = ctk.CTkFrame(content_frame)
    frame_doc = ctk.CTkFrame(content_frame)
    frame_scan_p = ctk.CTkFrame(content_frame)

    currently_displayed_frame = frame_default
    frame_default.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)

    def create_home():
        # CREATE DEFAULT FRAME CONTENTS
        df_container_frame = ctk.CTkFrame(frame_default, width=300, height=300, fg_color="gray")
        df_container_frame.pack(expand=1, anchor="center")
        df_container_frame.pack_propagate(0)
        # HOME PAGE ELEMENTS
        label_title = ctk.CTkLabel(df_container_frame, text="W3LC0ME", font=("Helvetica", 24))
        label_title.pack(expand=1, pady=10, anchor="center")

        label_name = ctk.CTkLabel(df_container_frame, text=userName, font=("Helvetica", 24))
        label_name.pack(expand=1, pady=2, anchor="center")

    def init_sidebar():
        btn = ctk.CTkButton(sidebar_frame, text="Home", height=35, command=onClickHome)
        btn.pack(pady=10, padx=10)

        btn1 = ctk.CTkButton(sidebar_frame, text="Analyze Traffic", height=35, command=onClickScan)
        btn1.pack(pady=10, padx=10)

        btn2 = ctk.CTkButton(sidebar_frame, text="Sniffer", height=35, command=onClickSniff)
        btn2.pack(pady=10, padx=10)

        btn4 = ctk.CTkButton(sidebar_frame, text="Password Checker", height=35, command=onClickPWS)
        btn4.pack(pady=10, padx=10)

        btn5 = ctk.CTkButton(sidebar_frame, text="Document Scanner", height=35, command=onClickDoc)
        btn5.pack(pady=10, padx=10)

        btn6 = ctk.CTkButton(sidebar_frame, text="Port Scanner", height=35, command=onClickPort)
        btn6.pack(pady=10,padx=0)

        btn3 = ctk.CTkButton(sidebar_frame, text="FAQ", height=35, command=onClickFaq)
        btn3.pack(pady=10, padx=10)

    def init_sniff():
        # frame_sniff is the main frame
        frame_sniff_sidebar = ctk.CTkFrame(frame_sniff, width=200, fg_color=default_color, bg_color=default_color)
        frame_sniff_sidebar.pack(side=tk.LEFT, fill=tk.Y)

        frame_sniff_content = ctk.CTkFrame(frame_sniff, fg_color=default_color_but_darker, bg_color=default_color_but_darker)
        frame_sniff_content.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)

        # Text Field for Input
        global entry
        entry = ctk.CTkEntry(frame_sniff_content, width=300, placeholder_text="Enter filter expression")
        entry.pack(pady=10, padx=10)

        # Start Sniffing Button
        btn_start_sniff = ctk.CTkButton(frame_sniff_sidebar, text="Start Scan", height=35, command=lambda: button_start_scan(entry.get()))
        btn_start_sniff.pack(pady=10, padx=10)

        # Stop Sniffing Button
        btn_stop_sniff = ctk.CTkButton(frame_sniff_sidebar, text="Stop Scan", height=35, command=button_stop_scan)
        btn_stop_sniff.pack(pady=10, padx=10)

        # Display Area for Results
        result_display = tk.Text(frame_sniff_content, width=600, height=400, wrap=tk.WORD)
        result_display.pack(pady=10, padx=10, fill=tk.BOTH, expand=1)

        """result_display.tag_configure("malicious", foreground="red")
                                result_display.tag_configure("normal", foreground="white")"""

        # Set the result display in the sniffing module
        set_result_display(result_display)

        # Additional Buttons (Example: Apply Filter, Clear Results)
        btn_apply_filter = ctk.CTkButton(frame_sniff_sidebar, text="Apply Filter", height=35, command=lambda: button_apply_filter(entry.get()))
        btn_apply_filter.pack(pady=10, padx=10, anchor="w")

        btn_clear_results = ctk.CTkButton(frame_sniff_sidebar, text="Clear Results", height=35, command=lambda: result_display.delete("1.0", tk.END))
        btn_clear_results.pack(pady=10, padx=10, anchor="w")

    def init_pws():
        global password_result_display
        
        constPasswordHolder = "@"

        def show_password():
            if password_entry.cget("show") == constPasswordHolder:
                password_entry.configure(show="")
                btn_show_password.configure(text="Hide Password")
            else:
                password_entry.configure(show=constPasswordHolder)
                btn_show_password.configure(text="Show Password")
        #APP PREFS
        password_description = "A password strength checker is a tool designed to evaluate the security level of a password \nby analyzing its complexity and resistance to various forms of attack, such as brute-force\n or dictionary attacks. This tool helps users create stronger, more secure passwords"

        # frame_pws is the main frame
        frame_pws_content = ctk.CTkFrame(frame_pws, fg_color=default_color, bg_color=default_color)
        frame_pws_content.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)

        # Text Field for Password Input
        password_title = ctk.CTkLabel(frame_pws_content, text="Password Strength", font=("Helvetica", 24), text_color="white")
        password_title.pack(pady=25, padx=0)

        password_desc = ctk.CTkLabel(frame_pws_content, text=password_description, font=("Helvetica", 14, "italic"), text_color="white")
        password_desc.pack(pady=25, padx=0)

        password_entry = ctk.CTkEntry(frame_pws_content, width=300, placeholder_text="Enter password", show=constPasswordHolder)
        password_entry.pack(pady=10, padx=10)

        # Password strength display
        password_strength_score = ctk.CTkLabel(frame_pws_content, text="Sample", font=("Helvetica", 14, "bold"), text_color="white")

        # Check Password Button
        btn_check_password = ctk.CTkButton(frame_pws_content, text="Check Password", height=35, command=lambda : password_checker_call(password_entry.get(), password_strength_score,password_mitigation))
        btn_check_password.pack(pady=10, padx=10)

        btn_show_password = ctk.CTkButton(frame_pws_content, text="Show Password", height=35, command=show_password)
        btn_show_password.pack(pady=2)

        password_requirements = (
            "1. Password must be at least 8 characters long and selected from 94 character sets:\n"
            "   - Include at least one uppercase letter (26 characters)\n"
            "   - Include at least one lowercase letter (26 characters)\n"
            "   - Include at least one number (10 characters)\n"
            "   - Include at least one special character from the keyboard (32 characters)\n\n"
            "2. Avoid using common words or phrases as passwords (e.g., password blacklists).\n\n"
            "3. Do not use personal information (e.g., name, birthday, phone number) as part of the password."
        )

        password_mitigation = ctk.CTkLabel(frame_pws_content, text=password_requirements, font=("Helvetica", 14, "italic"), text_color="white")
        

        



        # Display Area for Password Strength Results
        
    def init_doc():
        global file_path
        file_path = None  # Initialize file_path to None to avoid undefined errors

        def select_file():
            global file_path  # Use nonlocal to modify the global file_path variable
            file_path = filedialog.askopenfilename(title="Select a file")
            if file_path:
                file_path_label.configure(text=f"Selected File: {os.path.basename(file_path)}")

        frame_doc_content = ctk.CTkFrame(frame_doc, fg_color=default_color, bg_color=default_color)
        frame_doc_content.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)

        # Title Label
        doc_title = ctk.CTkLabel(frame_doc_content, text="Document Scanner", font=("Helvetica", 24), text_color="white")
        doc_title.grid(row=0,column=0,stick='w', pady=25, padx=(50,0))

        # Description Label
        doc_text = ctk.CTkLabel(frame_doc_content, text="Scan your documents here:")
        doc_text.grid(row=1,column=0,stick='w',pady=25, padx=(50,0))

        # Button to open file dialog
        text1 = ctk.CTkLabel(frame_doc_content, text="_SELECT DOCUMENT:")
        text1.grid(row=2,column=0,stick='w',pady=25, padx=(50,0))

        select_button = ctk.CTkButton(frame_doc_content, text="Select File", command=select_file)
        select_button.grid(row=2,column=1,stick='w',padx=0,pady=15)

        # Button to scan the file
        text2 = ctk.CTkLabel(frame_doc_content, text="_START SCANNING:")
        text2.grid(row=3,column=0,stick='w',pady=25, padx=(50,0))

        scan_file_button = ctk.CTkButton(frame_doc_content, text="Scan File", command=lambda: button_call(file_path,frame_doc_content, document_results) if file_path else file_path_label.configure(text="No file selected"))
        scan_file_button.grid(row=3,column=1,stick='w',padx=0,pady=5)

        # Label to display selected file path
        global file_path_label
        file_path_label = ctk.CTkLabel(frame_doc_content, text="No file selected", text_color="yellow")
        file_path_label.grid(row=4,column=0,stick='w',padx=50,pady=15)

        document_results = ctk.CTkLabel(frame_doc_content, text="You'll find your results here", text_color="white")
        document_results.grid(row=5,column=0,stick='w',padx=50,pady=15)

        frame_doc_content.grid_columnconfigure(0, weight=0)
        frame_doc_content.grid_columnconfigure(1, weight=1)

    def init_port():
        # Port Scanner Content Frame
        frame_port_scan_content = ctk.CTkFrame(frame_scan_p, fg_color=default_color_but_darker, bg_color=default_color_but_darker)
        frame_port_scan_content.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)

        port_scan_frame_desc = "A password strength checker is a tool designed to evaluate the security level of a password by analyzing its complexity and resistance to various forms of attack, such as brute-force or dictionary attacks. This tool helps users create stronger, more secure passwords"

        portscan_title = ctk.CTkLabel(frame_port_scan_content, text="Port Scanner", font=("Helvetica", 24), text_color="white", width=600)
        portscan_title.pack(pady=25, padx=0)

        portscan_desc = ctk.CTkLabel(frame_port_scan_content, text=port_scan_frame_desc, font=("Helvetica", 14, "italic"), text_color="white", wraplength=600)
        portscan_desc.pack(pady=25, padx=0)

        # Display Area for Scan Results (Text widget)
        port_scan_result_display = ctk.CTkTextbox(frame_port_scan_content, width=650, height=400)
        port_scan_result_display.pack(pady=10, padx=10)

        # Start Port Scan Button
        btn_start_port_scan = ctk.CTkButton(frame_port_scan_content, text="Start Port Scan", height=35, command=lambda: button_click_port(port_scan_result_display))
        btn_start_port_scan.pack(pady=10, padx=10)

    def init_scan():
        pass 

    def init_faq():
        helpw = ctk.CTkFrame(frame_faq, width=400,height=400, fg_color=default_color_but_darker)
        helpw.pack(expand=1, anchor="center")
        helpw.grid_columnconfigure(0, weight=1)  # First column
        helpw.grid_propagate(False)  # Keeps the frame from shrinking, but allows for size flexibility

        # Name Entry
        title_help = ctk.CTkLabel(helpw,text="User Queires",font=("Helvetica", 20))
        title_help.grid(row=0, column=0, columnspan=2, padx=20, pady=20, sticky="ew")  

        name_label_help = ctk.CTkLabel(helpw, text="Name")
        name_label_help.grid(row=1, column=0, padx=20, pady=10)  # Align label to the left
        name_entry_help = ctk.CTkEntry(helpw, placeholder_text="Enter your name", width=200)
        name_entry_help.grid(row=1, column=1, padx=20, pady=10)

        # Email Entry
        email_label_help = ctk.CTkLabel(helpw, text="Email")
        email_label_help.grid(row=2, column=0, padx=20, pady=10)  # Align label to the left
        email_entry_help = ctk.CTkEntry(helpw, placeholder_text="Enter your email", width=200)
        email_entry_help.grid(row=2, column=1, padx=20, pady=10)

        help_label = ctk.CTkLabel(helpw,text="Description: ")
        help_label.grid(row=3,column=0)
        help_entry = ctk.CTkTextbox(helpw, height=80, width=200)  # Adjust height as needed
        help_entry.grid(row=3, column=1, padx=20, pady=10)

        submit_button_help = ctk.CTkButton(helpw, text="Submit",  command=lambda: submit_query(name_entry_help, email_entry_help, help_entry))
        submit_button_help.grid(row=4, column=0, columnspan=2, padx=20, pady=20, sticky="ew")

    create_home()
    init_sidebar()
    init_sniff()
    init_pws()
    init_scan() 
    init_faq()
    init_doc()
    init_port()   
    root.mainloop()

if __name__ == "__main__":
    mainWindow("root", "rooooot")