import requests
import tkinter
import threading
import customtkinter as ctk
import os
import time

API_KEY = '3aac00130a4a556c161ea7d3ab5ea1504d533614bd86d5cc1a369cdd0172f618'

baseURI = 'https://www.virustotal.com/vtapi/v2/'

file_path = 'todo.txt'

def display_contents(file_path, info, frm, lbl):

	#print(info)

	if info['response_code'] == -2:
		lbl.configure(text="File Queued, too many API calls, try again later")
	else:

		lbl.configure(text="")

		txt = ""
		txt = txt + "File path : " + file_path + "\n"

		txt += "Positive Indicators : " + str(info['positives']) + "\n"
		txt += "Scan Date : " + info['scan_date'] + "\n"
		txt += "Sha1 : " + info['sha1'] + "\n"
		txt += "Sha256 : " + info['sha256'] + "\n"

		"""for key,value in info.items():
						print(f'{key} : {value}')"""

		#lbl.configure(text=txt)

		ctk.CTkLabel(frm, text="File Path", font=("Helvetic",10), text_color="white").grid(row=6,column=0,padx=(50,0),sticky="w")
		ctk.CTkLabel(frm, text=os.path.basename(file_path), font=("Helvetic",10), text_color="white").grid(row=6,column=1,sticky="w")

		ctk.CTkLabel(frm, text="Positive Indicators", font=("Helvetic",10), text_color="white").grid(row=7,column=0,padx=(50,0),sticky="w")
		ctk.CTkLabel(frm, text=info['positives'], font=("Helvetic",10), text_color="white").grid(row=7,column=1,sticky="w")
		
		ctk.CTkLabel(frm, text="Scan Date", font=("Helvetic",10), text_color="white").grid(row=8,column=0,padx=(50,0),sticky="w")
		ctk.CTkLabel(frm, text=info['scan_date'], font=("Helvetic",10), text_color="white").grid(row=8,column=1,sticky="w")
		
		ctk.CTkLabel(frm, text="SHA1", font=("Helvetic",10), text_color="white").grid(row=9,column=0,padx=(50,0),sticky="w")
		ctk.CTkLabel(frm, text=info['sha1'], font=("Helvetic",10), text_color="white").grid(row=9,column=1,sticky="w")

		ctk.CTkLabel(frm, text="SHA256", font=("Helvetic",10), text_color="white").grid(row=10,column=0,padx=(50,0),sticky="w")
		ctk.CTkLabel(frm, text=info['sha256'], font=("Helvetic",10), text_color="white").grid(row=10,column=1,sticky="w")
		frm.grid_columnconfigure(0,weight=0)
		frm.grid_columnconfigure(1,weight=1)

def upload_file(file_path):
    try:
        request_url = f'{baseURI}file/scan'
        params = {'apikey': API_KEY}
        
        # Ensure file exists
        try:
            files = {'file': (file_path, open(file_path, 'rb'))}
        except FileNotFoundError:
            raise Exception(f"File '{file_path}' not found.")

        # Make the API request
        response = requests.post(request_url, files=files, params=params)

        # Check if the response is successful
        if response.status_code == 204:
            raise Exception("API rate limit exceeded. Please try again later.")
        elif response.status_code != 200:
            raise Exception(f"Unexpected status code {response.status_code}. Response: {response.text}")

        # Attempt to parse the response as JSON
        try:
            info = response.json()
        except requests.exceptions.JSONDecodeError:
            raise Exception("Error: Received empty or invalid JSON from API.")

        # Check for VirusTotal response_code
        if info.get('response_code') == 1:
            return info['scan_id']
        else:
            raise Exception(f"Error in VirusTotal response: {info.get('verbose_msg', 'Unknown error')}")

    except Exception as e:
        errMessage = f'Error while trying to scan file: {e}'
        print(errMessage)
        raise Exception(errMessage)

def get_report(file_path, scan_id, frame, label):
	try:
		request_url = f'{baseURI}file/report'
		params = {'apikey' : API_KEY, 'resource' : scan_id}
		response = requests.get(request_url, params=params)


		if response.status_code == 204:
			label.configure(text="File Queued, too many API calls, try again later")
		elif response.status_code == 200:
			label.configure(text="File Queued, too many API calls, try again later")
			info = response.json()

			#print(info['response_code'])

			if info['response_code'] == -2:
				label.configure(text="File is in the queue, please try again later.")
				while True:
				    time.sleep(5)
				    response = requests.get(request_url, params=params)
				    info = response.json()
				    if info['response_code'] == 1:
				        break

				display_contents(file_path, info, frame, label)
			elif info['response_code'] == 1:
				# File scan completed, display results
				display_contents(file_path, info, frame, label)
			else:
				label.configure(text=f"Error: {info.get('verbose_msg', 'Unknown error')}")
		else:
			print('Try again later')
	

	except Exception as e:
            errMessage = f'Error while trying to scan file (2) :{e}'
            #print(errMessage)
            raise Exception(errMessage)

def button_call(FP, L, lbl):
	lbl.configure(text="Running Scan")
	scanId = upload_file(FP)
	get_report(FP,scanId,L,lbl)

