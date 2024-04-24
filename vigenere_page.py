import time
import logging
import cProfile
import pstats
import tkinter as tk
from tkinter import filedialog
from base import BasePage  # Adjust the import based on your file structure

# Set up logging
logging.basicConfig(filename='vigenere_performance.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def measure_time(func):
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        logging.info(f"{func.__name__} execution time: {end_time - start_time} seconds")
        return result
    return wrapper

def profile_cpu(func):
    def wrapper(*args, **kwargs):
        profiler = cProfile.Profile()
        profiler.enable()
        result = func(*args, **kwargs)
        profiler.disable()
        stats = pstats.Stats(profiler).sort_stats('cumtime')
        stats.print_stats()
        return result
    return wrapper


class VigenerePage(BasePage):
    def __init__(self, master):
        super().__init__(master)

        # Title
        self.lblInfo = tk.Label(self, font=('helvetica', 40, 'bold'), text="Vigenère Cipher", bd=10, anchor='center')
        self.lblInfo.grid(row=0, column=0, columnspan=10, padx=0, sticky="ew")

        # Message
        self.lblMsg = tk.Label(self, font=('arial', 16, 'bold'), text="Message", bd=16, anchor="e", pady=8)
        self.lblMsg.grid(row=1, column=0)
        self.txtMsg = tk.Text(self, font=('arial', 16, 'bold'), bd=10, insertwidth=4, bg="#add8e6", fg="black", height=5, width=50)
        self.txtMsg.grid(row=1, column=1, sticky="we", pady=(10,0), columnspan=3)
        self.btnImportMsg = tk.Button(self, text="Import Message File", font=('arial', 16, 'bold'), bd=4, bg="light grey",pady=8, command=self.importMessage)
        self.btnImportMsg.grid(row=1, column=4 , padx=10)

        # Key
        self.lblkey = tk.Label(self, font=('arial', 16, 'bold'), text="Key", bd=16, anchor="e")
        self.lblkey.grid(row=2, column=0)
        self.key = tk.StringVar()
        self.txtkey = tk.Entry(self, font=('arial', 16, 'bold'), textvariable=self.key, insertwidth=4, bg="#add8e6", justify='right', fg="black", width=50)
        self.txtkey.grid(row=2, column=1, pady=(20, 20), sticky="we", columnspan=3)
        #self.btnImportKey = tk.Button(self, text="Import Key", font=('arial', 16, 'bold'), bd=4, bg="light grey", padx=8, pady=2, command=self.importKey)
        #self.btnImportKey.grid(row=2, column=2, padx=(10,0))

        # Encrypt button
        self.btnEncrypt = tk.Button(self, padx=16, pady=8, bd=16, fg="black",
                                    font=('arial', 16, 'bold'), width=16,
                                    text="Encrypt", bg="powder blue",
                                    command=self.Encrypt)
        self.btnEncrypt.grid(row=3, column=1, padx=40)

        # Decrypt button
        self.btnDecrypt = tk.Button(self, padx=16, bd=16, pady=8, fg="black",
                                    font=('arial', 16, 'bold'), width=16,
                                    text="Decrypt", bg="powder blue",
                                    command=self.Decrypt)
        self.btnDecrypt.grid(row=4, column=1, padx=40)

        # Result
        self.lblService = tk.Label(self, font=('arial', 16, 'bold'), text="Result", bd=16, anchor="e")
        self.lblService.grid(row=5, column=0)
        self.txtService = tk.Text(self, font=('arial', 16, 'bold'), bd=10, insertwidth=4, bg="#add8e6", fg="black", height=5, width=50)
        self.txtService.grid(row=5, column=1, sticky="ew", columnspan=3)
        self.txtService.config(state="disabled")

        self.btnExportMsg = tk.Button(self, text="Export Message", font=('arial', 16, 'bold'), bd=4, bg="light grey",pady=8, command=self.exportMessage)
        self.btnExportMsg.grid(row=5, column=4, padx=10)

    

    def importMessage(self):
            filepath = filedialog.askopenfilename()
            if filepath:
                try:
                    with open(filepath, 'r') as file:
                        messageFromFile = file.read()
                        self.txtMsg.delete("1.0", tk.END)
                        self.txtMsg.insert("1.0", messageFromFile)
                        print("Message imported successfully.")
                except Exception as e:
                    print(f"Error importing message: {e}")

    def importKey(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            try:
                with open(filepath, 'r') as file:
                    keyFromFile = file.read().strip()
                    self.key.set(keyFromFile)
                    print("Key imported successfully.")
            except Exception as e:
                print(f"Error importing key: {e}")

    def exportMessage(self):
        filepath = filedialog.asksaveasfilename(defaultextension=".txt")
        if filepath:
            try:
                messageToExport = self.txtService.get("1.0", tk.END).strip()
                with open(filepath, 'w') as file:
                    file.write(messageToExport)
                    print("Result message exported successfully.")
            except Exception as e:
                print(f"Error exporting result message: {e}")

    @measure_time
    @profile_cpu
    def Encrypt(self):
        clear = self.txtMsg.get("1.0", tk.END).strip()
        k = self.key.get()
        encrypted_text = self.encode(clear, k)
        self.updateResult(encrypted_text)

    @measure_time
    @profile_cpu
    def Decrypt(self):
        clear = self.txtMsg.get("1.0", tk.END).strip()
        k = self.key.get()
        decrypted_text = self.decode(clear, k)
        self.updateResult(decrypted_text)

    def encode(self, plaintext, key):
        key_as_int = [ord(i) - ord('A') for i in key.upper() if i.isalpha()]
        plaintext_int = [ord(i) - ord('A') for i in plaintext.upper() if i.isalpha()]
        ciphertext = ''
        for i in range(len(plaintext_int)):
            value = (plaintext_int[i] + key_as_int[i % len(key_as_int)]) % 26
            ciphertext += chr(value + ord('A'))
        return ciphertext

    def decode(self, ciphertext, key):
        key_as_int = [ord(i) - ord('A') for i in key.upper() if i.isalpha()]
        ciphertext_int = [ord(i) - ord('A') for i in ciphertext.upper() if i.isalpha()]
        plaintext = ''
        for i in range(len(ciphertext_int)):
            value = (ciphertext_int[i] - key_as_int[i % len(key_as_int)] + 26) % 26
            plaintext += chr(value + ord('A'))
        return plaintext

    def updateResult(self, text):
        self.txtService.config(state=tk.NORMAL)
        self.txtService.delete("1.0", tk.END)
        self.txtService.insert("1.0", text)
        self.txtService.config(state=tk.DISABLED)
