#submitQ.py

#   FETCH DATA
#   CALL FIREBASE FUNCTION

import customtkinter as ctk
from tkinter import messagebox
import re
from database import addQuery


def submit_query(nl,el,ql):
    name = nl.get()
    email = el.get()
    query = ql.get("1.0", "end-1c")  # Get content from the Textbox

    if not name:
        messagebox.showerror("Input Error", "Name field cannot be empty.")
        return
    if not email:
        messagebox.showerror("Input Error", "Email field cannot be empty.")
        return
    # Basic email format validation using regex
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        messagebox.showerror("Input Error", "Invalid email format.")
        return
    if not query:
        messagebox.showerror("Input Error", "Description field cannot be empty.")
        return

    if addQuery(name,email,query):
        messagebox.showinfo("Success", "Form submitted successfully!")
    else:
        messagebox.showerror("Something Went Wrong!", "Check if app is updated & you are connected to the internet")
