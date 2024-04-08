import tkinter as tk

window = tk.Tk()
window.title("Number + 1 Calculator")
window.resizable(width=False, height=False)

#addition
def dosomething():
    num = provided.get()
    newnum = int(num) + 1
    lbl_result["text"] = f"{int(newnum)} is the new num + 1"

#entry frame with an Entry and a label
frm_entry = tk.Frame(master=window)
provided = tk.Entry(master=frm_entry, width=10)
lbl_num = tk.Label(master=frm_entry, text=" is the num")
#should there be a bounds check if entered val + 1 is too large for int?

#sizing of entry and label
provided.grid(row=0, column=0, sticky="e")
lbl_num.grid(row=0, column=1, sticky="w")

#addition button to display result and label
btn_convert = tk.Button(
    master=window,
    text="\N{RIGHTWARDS BLACK ARROW}",
    command=dosomething
)
lbl_result = tk.Label(master=window, text=" is the new num")

#sizing of result, button, and label
frm_entry.grid(row=0, column=0, padx=10)
btn_convert.grid(row=0, column=1, pady=10)
lbl_result.grid(row=0, column=2, padx=10)

#run
window.mainloop()