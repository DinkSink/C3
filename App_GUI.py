import tkinter as tk
from tkinter import ttk
import ttkbootstrap as ttkb
from functools import partial
from tkinter import messagebox
from tkinter import filedialog
import json


json_loaded = False

def load_json():
    global json_loaded
    global json_data
    file_path = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json")])
    if file_path:
        # Assuming you want to load the JSON file and do something with it
        try:
            with open(file_path, 'r') as file:
                # You can store the loaded JSON in a global variable or process it as needed
                json_data = json.load(file)
                json_loaded = True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load JSON file: {e}")


def show_frame(frame):
    if not json_loaded and frame != home_frame:
        messagebox.showwarning("Warning", "Please load your strings file")
        return
    frame.tkraise()


def create_page1(parent):
    frame = ttk.Frame(parent)
    # Add your widgets for page 1 here
    ttk.Label(frame, text='This is page 1').pack()
    ttk.Button(frame, text='Back', command=lambda: show_frame(home_frame)).pack(side='bottom')
    return frame

def create_page2(parent):
    frame = ttk.Frame(parent)
    # Add your widgets for page 2 here
    ttk.Label(frame, text='This is page 2').pack()
    ttk.Button(frame, text='Back', command=lambda: show_frame(home_frame)).pack(side='bottom')
    return frame

def create_page3(parent):
    frame = ttk.Frame(parent)
    # Add your widgets for page 3 here
    ttk.Label(frame, text='This is page 3').pack()
    ttk.Button(frame, text='Back', command=lambda: show_frame(home_frame)).pack(side='bottom')
    return frame

def create_page4(parent):
    frame = ttk.Frame(parent)
    # Add your widgets for page 4 here
    ttk.Label(frame, text='This is page 4').pack()
    ttk.Button(frame, text='Back', command=lambda: show_frame(home_frame)).pack(side='bottom')
    return frame

app = ttkb.Window(themename='cyborg')
app.geometry('800x1000')  # Set window size to 800x1000

# Create pages
page1 = create_page1(app)
page2 = create_page2(app)
page3 = create_page3(app)
page4 = create_page4(app)
pages = [page1, page2, page3, page4]

def create_home_frame(parent):
    frame = ttk.Frame(parent)

    # Large buttons with new titles
    btn1 = ttk.Button(frame, text='Strings defined by programmer', width=30, command=partial(show_frame, pages[0]))
    btn1.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)

    btn2 = ttk.Button(frame, text='English words', width=30, command=partial(show_frame, pages[1]))
    btn2.grid(row=0, column=1, sticky='nsew', padx=5, pady=5)

    btn3 = ttk.Button(frame, text='Commands and Scripts', width=30, command=partial(show_frame, pages[2]))
    btn3.grid(row=1, column=0, sticky='nsew', padx=5, pady=5)

    btn4 = ttk.Button(frame, text='Magic Filter', width=30, command=partial(show_frame, pages[3]))
    btn4.grid(row=1, column=1, sticky='nsew', padx=5, pady=5)

    # Smaller "Load JSON File" button
    load_button = ttk.Button(frame, text='Load JSON File', width=20, command=load_json)
    load_button.grid(row=2, column=0, columnspan=2, sticky='nsew', padx=5, pady=5)

    # Configure row and column sizes
    for i in range(2):
        frame.grid_rowconfigure(i, weight=1, minsize=100)
        frame.grid_columnconfigure(i, weight=1, minsize=200)

    frame.grid_rowconfigure(2, weight=1, minsize=50)  # Smaller row height for the JSON button

    return frame




# Home frame creation
home_frame = create_home_frame(app)

# Configuration for layout
for frame in [home_frame, page1, page2, page3, page4]:
    frame.grid(row=0, column=0, sticky='nsew')

app.grid_columnconfigure(0, weight=1)
app.grid_rowconfigure(0, weight=1)

show_frame(home_frame)

app.mainloop()
