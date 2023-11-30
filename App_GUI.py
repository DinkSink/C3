import tkinter as tk
from tkinter import ttk
import ttkbootstrap as ttkb
from functools import partial
from tkinter import messagebox
from tkinter import filedialog
import json
import re

json_loaded = False
page1, page2, page3, page4 = None, None, None, None

def find_ip_addresses_and_urls(json_data):
    ip_regex = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    url_regex = r"(http|ftp|https):\/\/([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:\/~+#-]*[\w@?^=%&\/~+#-])"

    ip_addresses = []
    urls = []

    for item in json_data["strings"]:
        value = item["value"]
        location = item["location"]
        if re.match(ip_regex, value):
            ip_addresses.append({"location": location, "value": value})
        elif re.match(url_regex, value):
            urls.append({"location": location, "value": value})

    return ip_addresses, urls

def load_json():
    global json_loaded
    global json_data
    file_path = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json")])
    if file_path:
        try:
            with open(file_path, 'r') as file:
                json_data = json.load(file)
                json_loaded = True
                enable_navigation_buttons()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load JSON file: {e}")

def show_frame(frame):
    if not json_loaded and frame != home_frame:
        messagebox.showwarning("Warning", "Please load your strings file")
        return
    frame.tkraise()

def create_page1(parent):
    frame = ttk.Frame(parent)
    ttk.Label(frame, text='This is page 1').pack()
    ttk.Button(frame, text='Back', command=lambda: show_frame(home_frame)).pack(side='bottom')
    return frame

def create_page2(parent):
    frame = ttk.Frame(parent)
    ttk.Label(frame, text='This is page 2').pack()
    ttk.Button(frame, text='Back', command=lambda: show_frame(home_frame)).pack(side='bottom')
    return frame

def create_page3(parent):
    frame = ttk.Frame(parent)
    ttk.Label(frame, text='This is page 3').pack()
    ttk.Button(frame, text='Back', command=lambda: show_frame(home_frame)).pack(side='bottom')
    return frame

def create_page4(parent):
    frame = ttk.Frame(parent)
    ttk.Label(frame, text='IP Addresses and URLs').pack(pady=10)
    results_text = tk.Text(frame, height=20, width=80)
    results_text.pack()
    if json_loaded:
        ip_addresses, urls = find_ip_addresses_and_urls(json_data)
        results_text.insert('end', "IP Addresses:\n")
        for ip in ip_addresses:
            results_text.insert('end', f"{ip['location']}: {ip['value']}\n")
        results_text.insert('end', "\nURLs:\n")
        for url in urls:
            results_text.insert('end', f"{url['location']}: {url['value']}\n")
    ttk.Button(frame, text='Back', command=lambda: show_frame(home_frame)).pack(side='bottom')
    return frame

def enable_navigation_buttons():
    global page1, page2, page3, page4

    # Create pages and assign them to global variables
    page1 = create_page1(app)
    page2 = create_page2(app)
    page3 = create_page3(app)
    page4 = create_page4(app)

    # Configure layout for each page
    for frame in [page1, page2, page3, page4]:
        frame.grid(row=0, column=0, sticky='nsew')

    # Create and place navigation buttons with commands to show respective frames
    btn1 = ttk.Button(home_frame, text='Strings defined by programmer', width=30, command=partial(show_frame, page1))
    btn1.grid(row=1, column=0, sticky='nsew', padx=5, pady=5)

    btn2 = ttk.Button(home_frame, text='English words', width=30, command=partial(show_frame, page2))
    btn2.grid(row=1, column=1, sticky='nsew', padx=5, pady=5)

    btn3 = ttk.Button(home_frame, text='Commands and Scripts', width=30, command=partial(show_frame, page3))
    btn3.grid(row=2, column=0, sticky='nsew', padx=5, pady=5)

    btn4 = ttk.Button(home_frame, text='Network Access', width=30, command=partial(show_frame, page4))
    btn4.grid(row=2, column=1, sticky='nsew', padx=5, pady=5)

    # Configure grid row and column sizes in the home frame
    for i in range(1, 3):
        home_frame.grid_rowconfigure(i, weight=1, minsize=100)
        home_frame.grid_columnconfigure(i, weight=1, minsize=200)

    # Ensure the home frame is shown after setting up the buttons
    show_frame(home_frame)

def create_home_frame(parent):
    frame = ttk.Frame(parent)
    load_button = ttk.Button(frame, text='Load JSON File', width=20, command=load_json)
    load_button.grid(row=0, column=0, columnspan=2, sticky='nsew', padx=5, pady=5)
    frame.grid_rowconfigure(0, weight=1, minsize=50)
    return frame

app = ttkb.Window(themename='cyborg')
app.geometry('800x1000')

home_frame = create_home_frame(app)
home_frame.grid(row=0, column=0, sticky='nsew')
app.grid_columnconfigure(0, weight=1)
app.grid_rowconfigure(0, weight=1)
show_frame(home_frame)

app.mainloop()
