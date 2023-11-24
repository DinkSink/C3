import PySimpleGUI as sg
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Function to create a matplotlib figure and return it
def draw_figure(canvas, figure):
    figure_canvas_agg = FigureCanvasTkAgg(figure, canvas)
    figure_canvas_agg.draw()
    figure_canvas_agg.get_tk_widget().pack(side='top', fill='both', expand=1)
    return figure_canvas_agg

# Function to plot random data (you can modify this to plot your actual data)
def plot_random_data():
    plt.figure(figsize=(5, 4))
    plt.plot([0, 1, 2, 3, 4], [10, 5, 10, 5, 10], marker='o')  # Random data
    plt.title("This will visualize something")
    plt.xlabel("X")
    plt.ylabel("Occurrences of X")
    return plt.gcf()

# Layout with four buttons and a canvas for the graph
layout = [
    [sg.Button('Script 1'), sg.Button('Potentially Encrypted Text'), sg.Button('Script 3'), sg.Button('Script 4')],
    [sg.Canvas(key='-CANVAS-')]
]

# Create the Window
window = sg.Window('Ghidra RE Data Analytics', layout, finalize=True)

# Draw the initial graph
fig = plot_random_data()
fig_canvas_agg = draw_figure(window['-CANVAS-'].TKCanvas, fig)

# Event Loop
while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED:
        break

    # Handle button clicks and update graphs
    if event in 'Potentially Encrypted Text':
        print(f'{event} clicked')

window.close()
