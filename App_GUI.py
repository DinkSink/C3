import tkinter as tk
from tkinter import ttk
import ttkbootstrap as ttkb
from functools import partial
from tkinter import messagebox
from tkinter import filedialog
import json
import re
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

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

def filter_out_compiler(json_data):
    newList = []
    for item in json_data["strings"]:
        if not re.search(r"_Z", item["value"]) and not re.search(r"gxx", item["value"]) and not re.search(r"GLIBC", item["value"]) and not re.search(r"CXX", item["value"]) and not re.search(r"GCC", item["value"]) and not (item["value"] == "None") and not re.search(r"align", item["value"]):
            newList.append({"location": item["location"], "value": item["value"]})
    return newList

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
    columns = ('location', 'string')
    table = ttk.Treeview(frame, columns=columns, show='headings')
    table.heading('location', text='Location in Memory')
    table.heading('string', text='String')

    # Define column width and alignment
    table.column('location', width=100, anchor='center')
    table.column('string', width=200, anchor='center')


    ttk.Label(frame, text='Deletes all of the strings are compiler defined').pack(pady=10)
    if json_loaded:
        strings = filter_out_compiler(json_data)
        for str in strings:
            table.insert('', 'end', values=(str['location'], str['value']))
    scrollbar = ttk.Scrollbar(frame, orient='vertical', command=table.yview)
    table.configure(yscroll=scrollbar.set)
    scrollbar.pack(side='right', fill='y')

    table.pack(expand=True, fill='both')
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

    # Create a frame for the table
    table_frame = ttk.Frame(frame)
    table_frame.pack(side='top', fill='both', expand=True)

    # Create the Treeview widget for the table
    columns = ('location', 'string', 'type')
    table = ttk.Treeview(table_frame, columns=columns, show='headings')
    table.heading('location', text='Location in Memory')
    table.heading('string', text='String')
    table.heading('type', text='Type')
    table.column('location', width=100, anchor='center')
    table.column('string', width=200, anchor='center')
    table.column('type', width=100, anchor='center')

    # Insert data into the table
    if json_loaded:
        ip_addresses, urls = find_ip_addresses_and_urls(json_data)
        for ip in ip_addresses:
            table.insert('', 'end', values=(ip['location'], ip['value'], 'IP Address'))
        for url in urls:
            table.insert('', 'end', values=(url['location'], url['value'], 'URL'))

    # Add a scrollbar to the table
    scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=table.yview)
    table.configure(yscroll=scrollbar.set)
    scrollbar.pack(side='right', fill='y')
    table.pack(expand=True, fill='both')

    # Create a frame for the pie chart
    chart_frame = ttk.Frame(frame)
    chart_frame.pack(side='top', fill='both', expand=True)

    # Create a pie chart
    if json_loaded:
        ip_count = len(ip_addresses)
        url_count = len(urls)
        sizes = [ip_count, url_count]
        labels = 'IP Addresses', 'URLs'
        colors = ['gold', 'lightcoral']
        fig, ax = plt.subplots(figsize=(5, 3))  # Smaller figure size
        ax.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
        ax.axis('equal')
        chart = FigureCanvasTkAgg(fig, master=chart_frame)
        chart_widget = chart.get_tk_widget()
        chart_widget.pack(side='top', fill='both', expand=True)

    # Create a frame for the Back button
    button_frame = ttk.Frame(frame)
    button_frame.pack(side='bottom', fill='x')
    ttk.Button(button_frame, text='Back', command=lambda: show_frame(home_frame)).pack(side='right', padx=10, pady=10)

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
    btn1 = ttk.Button(home_frame, text='No Compiler Strings', width=30, command=partial(show_frame, page1))
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
