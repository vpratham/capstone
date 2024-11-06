# PassCheck.py
import tkinter as tk
from zxcvbn import zxcvbn

# Global variables

# Code to check passwords
def password_checker_call(password, lbl, lbl2):
	results = zxcvbn(password)

	# Return only the score
	scr = results['score']

	text = ""

	text_score = "Password Strength\n" + "Score: " + str(scr)

	fb = results['feedback']

	txt = ""

	for i in fb['warning']:
		txt = txt + i

	txt += "\n"

	for x in fb['suggestions']:
		txt = txt + x

    
	text = text_score + "\n" + txt

	lbl.configure(text=text)
	

	lbl.pack(pady=10,padx=10)

	lbl2.pack(pady=25,padx=0)
	pass