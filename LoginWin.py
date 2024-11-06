#loginwin.py

import tkinter as tk
import customtkinter as ctk 
from MainWindow import mainWindow
#from passwordSec import validate_user

from database import auth

def mainLogin():

	#CONSTANTS

	customColor1 = "#4d4b4b"
	customColor2 = "#de4343" #invalid credentials color

	constPasswordHolder = "*"
	
	constPassword = "root"
	constUsername = "root"

	def onSubmit():

		passw = password_Textbox.get()
		usern = username_Textbox.get()

		if auth(usern,passw):
			#end_background_tasks()

			label_authStat.pack_forget()
			password_Textbox.configure(bg_color="transparent")
			username_Textbox.configure(bg_color="transparent")

			root.destroy()
			mainWindow(usern, passw)
		else:
			label_authStat.pack(pady=1)
			password_Textbox.configure(bg_color="red")
			username_Textbox.configure(bg_color="red")


	def show_password():
		if password_Textbox.cget("show") == constPasswordHolder:
			password_Textbox.configure(show="")
			show_password_button.configure(text="Hide Password")
		else:
			password_Textbox.configure(show=constPasswordHolder)
			show_password_button.configure(text="Show Password")
	#APP PREFS

	ctk.set_appearance_mode("dark") 
	ctk.set_default_color_theme("blue")

	#ROOT WINDOW DEFINITIONS

	root = ctk.CTk()
	root.title("--Login--")
	root.geometry("800x640")

	main_frame = ctk.CTkFrame(root)
	main_frame.pack(fill=tk.BOTH, expand=1)

	#WINDOW CONTENT

	content_frame = ctk.CTkFrame(main_frame, width=440, height=440, fg_color=customColor1)
	content_frame.pack(expand=1, anchor="center")

	label_title = ctk.CTkLabel(content_frame, text="Login Page")
	label_title.pack(expand=1, pady=10)

	label_authStat = ctk.CTkLabel(content_frame, text="Invalid Credentials", text_color="red")

	username_Textbox = ctk.CTkEntry(content_frame, placeholder_text="Enter Username")
	username_Textbox.pack(pady=2, padx=10, expand=1)

	password_Textbox = ctk.CTkEntry(content_frame, placeholder_text="Enter Password", show=constPasswordHolder)
	password_Textbox.pack(pady=2, padx=10, expand=1)

	global show_password_button
	show_password_button = ctk.CTkButton(content_frame, text="Show Password", command=show_password)
	show_password_button.pack(pady=2)

	btn1 = ctk.CTkButton(content_frame, text="Login", command=onSubmit)
	btn1.pack(pady=25, padx=10, expand=1)

	root.mainloop()



if __name__ == "__main__":
	mainLogin()