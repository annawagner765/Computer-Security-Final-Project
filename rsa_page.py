
# d = 52203292265329821477201215331647767385
# e = 65537
# n = 109658872566201497189314566136483333067


import os
import time
import tkinter as tk
from tkinter import messagebox, filedialog, Frame, Label, Button, Entry, Radiobutton
from tkinter.scrolledtext import ScrolledText
import logging
import cProfile
import pstats
import functools
from memory_profiler import profile
from base import BasePage

logging.basicConfig(filename='rsa_performance.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def measure_time(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        logging.info(f"{func.__name__} execution time: {end_time - start_time} seconds")
        print(f"{func.__name__} execution time: {end_time - start_time} seconds")
        return result
    return wrapper

def profile_cpu(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not hasattr(wrapper, 'profiler'):
            wrapper.profiler = cProfile.Profile()
            wrapper.profiler.enable()
            result = func(*args, **kwargs)
            wrapper.profiler.disable()
            stats = pstats.Stats(wrapper.profiler).sort_stats('cumtime')
            stats.print_stats()
        else:
            result = func(*args, **kwargs)
        return result
    return wrapper


class RSAPage(BasePage):
    def __init__(self, master):
        super().__init__(master)
        self.create_widgets()

    def create_widgets(self):
        # Title
        self.lblInfo = Label(self, font=('helvetica', 40, 'bold'),
                            text="RSA Cipher",  bd=10,  anchor='center')
        self.lblInfo.grid(row=0, column=0, columnspan=16, sticky="ew", pady=(0,20))


        # Labels, entries, and buttons
        self.label_n = tk.Label(self, font=('arial', 16, 'bold'),
                                text="Modulus n", bd=16, anchor="w")
        self.label_n.grid(row=2, column=0, sticky='e')
        self.entry_n = tk.Entry(self, font=('arial', 16, 'bold'),
                                 bg="#add8e6", fg="black", width=50 )
        self.entry_n.grid(row=2, column=1, columnspan=2)

        self.label_e = tk.Label(self, font=('arial', 16, 'bold'),
                                text="Public Exponent e", bd=16, anchor="w")
        self.label_e.grid(row=3, column=0, sticky='e')
        self.entry_e = tk.Entry(self, font=('arial', 16, 'bold'),
                                  bg="#add8e6", fg="black", width=50 )
        self.entry_e.grid(row=3, column=1, columnspan=2)

        self.label_d = tk.Label(self, font=('arial', 16, 'bold'),
                                text="Private Exponent d", bd=16, anchor="w")
        self.label_d.grid(row=4, column=0, sticky='e')
        self.entry_d = tk.Entry(self, font=('arial', 16, 'bold'),
                                 bg="#add8e6", fg="black", width=50 )
        self.entry_d.grid(row=4, column=1, columnspan=2 )

        self.btnEncrypt = Button(self, bd=16, pady=8, padx=16, fg="black",
                                font=('arial', 16, 'bold'), width=12,
                                text="Encrypt", bg="powder blue",
                                command=self.set_operation_to_encrypt)
        self.btnEncrypt.grid(row=5, column=1, columnspan=2)

        self.btnDecrypt = Button(self, bd=16, pady=8, padx=16, fg="black",
                                font=('arial', 16, 'bold'), width=12,
                                text="Decrypt", bg="powder blue",
                                command=self.set_operation_to_decrypt)
        self.btnDecrypt.grid(row=6, column=1, columnspan=2)

        self.var_data_type = tk.StringVar(value='text')
        self.radio_text = tk.Radiobutton(self, text="Text", variable=self.var_data_type, value='text', font=('arial', 16, 'bold'))
        self.radio_text.grid(row=1, column=3)
        self.radio_file = tk.Radiobutton(self, text="File", variable=self.var_data_type, value='file', font=('arial', 16, 'bold'))
        self.radio_file.grid(row=1, column=4)
        self.radio_image = tk.Radiobutton(self, text="Image", variable=self.var_data_type, value='image', font=('arial', 16, 'bold'))
        self.radio_image.grid(row=1, column=5, sticky='w')

        self.text_msg = Label(self, font=('arial', 16, 'bold'),
                            text="Message", bd=16, anchor="e")
        self.text_msg.grid(row=1, column=0, sticky='e', padx=12)
        self.text_input = ScrolledText(self, font=('arial', 16, 'bold'),
                                    bd=10, bg="#add8e6", fg="black", height=3, width=48)
        self.text_input.grid(row=1, column=1, columnspan=2, pady=(4, 0))

        self.btnOpenFile = Button(self, padx=16, bd=16, pady=8, fg="black",
                                font=('arial', 16, 'bold'), width=12,
                                text="Import Message File", bg="powder blue",
                                command=self.open_file)
        self.btnOpenFile.grid(row=2, column=4)

        self.text_out = Label(self, font=('arial', 16, 'bold'),
                            text="Result", bd=16, anchor="w")
        self.text_out.grid(row=7, column=0, sticky="e")
        self.text_output = ScrolledText(self, font=('arial', 16, 'bold'),
                                        bd=10, bg="#add8e6", fg="black", height=3, width=48)
        self.text_output.grid(row=7, column=1, columnspan=2, pady=(4, 0))


    # RSA
    def gcd(a, b):
    #"""Compute the Greatest Common Divisor of a and b using Euclid's algorithm."""
        while b:
            a, b = b, a % b
        return a




    def multiplicative_inverse(e, phi):
    #"""Compute the multiplicative inverse of e modulo phi. This is used in the RSA algorithm to find the decryption key d."""
        d, x1, x2, y1 = 0, 0, 1, 1
        while e > 0:
            temp1, temp2 = divmod(phi, e)
            phi, e = e, temp2
            x1, x2 = x2 - temp1 * x1, x1
            y1, d = d - temp1 * y1, y1
        if phi == 1:
            return d + phi




    def is_prime(num):
    #"""Check whether a number is prime, which is required for RSA key generation."""
        if num < 2:
            return False
        for n in range(2, int(num**0.5) + 1):
            if num % n == 0:
                return False
        return True

    @staticmethod
    def char_to_number(char):
        """Convert a character to a number for encryption with RSA."""
        if char == ' ':
            return 26
        if char.isalpha():
            char = char.lower()
            return ord(char) - ord('A') - 5
        return

    @staticmethod
    def number_to_char(number):
        """Convert a number back to a character after decryption with RSA."""
        if number == 26:
            return ' '
        return chr(number + ord('A'))




    @measure_time
    @profile_cpu
    def rsa_encrypt(self, pk, plaintext):
        key, n = pk
        numbers = [self.char_to_number(char) for char in plaintext]  # Convert every character, including spaces
        return [pow(number, key, n) for number in numbers]  # Encrypt all numbers





    @measure_time
    @profile_cpu
    def rsa_decrypt(self, pk, ciphertext):
        key, n = pk
        numbers = [pow(number, key, n) for number in ciphertext]
        return ''.join(self.number_to_char(number % 27) for number in numbers)  # Use 27 to include 0 for space



    @measure_time
    @profile_cpu
    def rsa_encrypt_binary(self, pk, data):
        key, n = pk
        k = (n.bit_length() + 7) // 8  # Total bytes in a single block
        chunk_size = k - 11  # PKCS#1 v1.5 padding requires at least 11 bytes

        if chunk_size < 1:
            raise ValueError("Encryption block size is too small")

        encrypted_data = bytearray()
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]

            # Adding PKCS#1 v1.5 padding: 0x00 0x02 [random non-zero bytes] 0x00 [data]
            padding_length = k - len(chunk) - 3
            padding = b'\x02' + os.urandom(padding_length).replace(b'\x00', b'\x01') + b'\x00'
            padded_chunk = b'\x00' + padding + chunk  # Start with 0x00 to ensure the integer is smaller than n

            chunk_int = int.from_bytes(padded_chunk, 'big')
            encrypted_chunk_int = pow(chunk_int, key, n)
            encrypted_chunk = encrypted_chunk_int.to_bytes(k, 'big')
            encrypted_data.extend(encrypted_chunk)
            
        return encrypted_data




    @measure_time
    @profile_cpu
    def rsa_decrypt_binary(self, pk, data):
        key, n = pk
        k = (n.bit_length() + 7) // 8  # Total bytes in a single block

        decrypted_data = bytearray()
        for i in range(0, len(data), k):
            chunk = data[i:i + k]
            chunk_int = int.from_bytes(chunk, 'big')
            decrypted_chunk_int = pow(chunk_int, key, n)
            decrypted_chunk = decrypted_chunk_int.to_bytes(k, 'big')

            # Remove the padding
            if decrypted_chunk[0] == 0 and decrypted_chunk[1] == 2:
                pos = decrypted_chunk.find(b'\x00', 2)
                if pos != -1:
                    decrypted_data.extend(decrypted_chunk[pos+1:])

        return decrypted_data


    def set_operation_to_encrypt(self):
        self.perform_rsa('Encrypt')


    def set_operation_to_decrypt(self):
        self.perform_rsa('Decrypt')


    def open_file(self):
        filepath = filedialog.askopenfilename()
        if filepath:
            self.text_input.delete("1.0", tk.END)
            self.text_input.insert("1.0", filepath)


    def save_file(self, filedata, operation):
        operation_suffix = 'enc' if operation == 'encrypt' else 'dec'
        #filepath = filedialog.asksaveasfilename(defaultextension=f"-rsa.{operation_suffix}")
        filepath = filedialog.asksaveasfilename(defaultextension=f"-rsa.{operation_suffix}",filetypes=[("Encrypted files", "*.enc"), ("Decrypted files", "*.dec"), ("All files", "*.*")])
        if filepath:
            with open(filepath, 'wb') as file: # if isinstance(filedata, bytes) else 'w'
                file.write(filedata)
            self.text_output.delete("1.0", tk.END)
            self.text_output.insert("1.0", filepath)




    def perform_rsa(self, operation):
        try:
            n = int(self.entry_n.get())
            e = int(self.entry_e.get())
            d = int(self.entry_d.get())
            public_key = (e, n)
            private_key = (d, n)
            data_type = self.var_data_type.get()


            if data_type == 'text':
                text_data = self.text_input.get("1.0", tk.END).rstrip()
                if operation == 'Encrypt':
                    encrypted_data = self.rsa_encrypt(public_key, text_data)
                    self.text_output.delete("1.0", tk.END)
                    self.text_output.insert("1.0", ' '.join(map(str, encrypted_data)))
                elif operation == 'Decrypt':
                    ciphertext = list(map(int, text_data.split()))
                    decrypted_text = self.rsa_decrypt(private_key, ciphertext)
                    self.text_output.delete("1.0", tk.END)
                    self.text_output.insert("1.0", decrypted_text)
            else:
                file_path = self.text_input.get("1.0", tk.END).strip()
                if operation == 'Encrypt':
                    with open(file_path, 'rb') as file_input:
                        data = file_input.read()
                    encrypted_data = self.rsa_encrypt_binary(public_key, data)
                    self.save_file(encrypted_data, 'encrypt')  # Change to use save_file
                elif operation == 'Decrypt':
                    with open(file_path, 'rb') as file_input:
                        encrypted_data = file_input.read()
                    decrypted_data = self.rsa_decrypt_binary(private_key, encrypted_data)
                    self.save_file(decrypted_data, 'decrypt')  # Change to use save_file


        except ValueError as ve:
            messagebox.showerror("Input Error", str(ve))
        except Exception as ex:
            messagebox.showerror("Error", str(ex))



