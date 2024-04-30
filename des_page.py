import os
import time
import binascii
import tkinter as tk
from tkinter import messagebox, filedialog
import logging
import cProfile
import pstats
import functools
from base import BasePage

logging.basicConfig(filename='des_performance.log', level=logging.INFO, format='%(asctime)s - %(message)s')

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


class TripleDESPage(BasePage):
    # Define arrays
    PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
    ]


    PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
    ]


    IP= [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
    ]


    E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
    ]


    P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
    ]


    IP_1 = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
    ]


    S = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [1, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
    ]

    def __init__(self, master):
        super().__init__(master)
        self.create_widgets()

    def create_widgets(self):

        bg_color = '#add8e6'
        btn_color = 'light grey'
        title_font = ('helvetica', 40, 'bold')
        font = ('arial', 16, 'bold')

        tk.Label(self, text="3DES Cipher", bd=10,  anchor='center', font=title_font).grid(row=0, column=0, columnspan=10, pady=(0,20), padx=0, sticky="ew")

        self.mode = tk.StringVar(value="Text")
        tk.Radiobutton(self, text="Text", variable=self.mode, value="Text", font=font).grid(row=2, column=2)
        tk.Radiobutton(self, text="File", variable=self.mode, value="File", font=font).grid(row=2, column=3)
        tk.Radiobutton(self, text="Image", variable=self.mode, value="Image", font=font).grid(row=2, column=4)

        self.message_label = tk.Label(self, text="Message", font=font,  padx=10, pady=10)
        self.message_label.grid(row=2, column=0, sticky='e')
        # input box
        self.input_entry = tk.Text(self, font=font, bg=bg_color, fg="black", width=50, height=5)
        self.input_entry.grid(row=2, column=1, sticky='we')

        tk.Button(self, text="Import Message File", command=self.open_file, font=font, bg=btn_color, pady=8, padx=4).grid(row=3, column=3, padx=10)

        self.keys_entries = []
        for i in range(3):
            tk.Label(self, text=f"Key {i+1}", font=font, padx=10, pady=10).grid(row=3+i, column=0, sticky='e')
            entry = tk.Entry(self, font=font, bg=bg_color, fg="black", width=50)
            entry.grid(row=3+i, column=1, sticky='we')
            self.keys_entries.append(entry)

        tk.Button(self, text="Encrypt", command=lambda: self.encrypt_decrypt('encrypt'), font=font, bg=btn_color,  bd=16, pady=8, padx=16, fg="black", width=12).grid(row=6, column=1, padx=12)
        tk.Button(self, text="Decrypt", command=lambda: self.encrypt_decrypt('decrypt'), font=font, bg=btn_color,  bd=16, pady=8, padx=16, fg="black", width=12).grid(row=7, column=1,  padx=12)

        self.result_label = tk.Label(self, text="Result", font=font,  padx=10)
        self.result_label.grid(row=8, column=0, sticky='e')
        self.result_text = tk.Text(self, font=font, bg=bg_color, fg="black", height=5, width=50)
        self.result_text.grid(row=8, column=1, sticky='we')
    
    def open_file(self):
        file_path = filedialog.askopenfilename(title="Select file")
        if file_path:
            self.input_entry.delete('1.0', tk.END)
            self.input_entry.insert('1.0', file_path)


    def encrypt_decrypt(self, mode):
        input_type = self.mode.get()
        keys = [entry.get() for entry in self.keys_entries]


        if not all(len(key) == 64 for key in keys):  # Ensuring each key is 64 bits
            messagebox.showerror("Error", "Each key must be exactly 64 bits long.")
            return


        if input_type == "Text":
            data = self.input_entry.get('1.0', tk.END).strip()
            if mode == 'decrypt':
                # Assuming data is in hex for decryption
                try:
                    binary_data = self.hex_to_binary(data)
                except ValueError:
                    messagebox.showerror("Error", "Invalid hex input for decryption.")
                    return
            else:
                binary_data = self.text_to_binary(data)


            if mode == 'encrypt':
                padded_data, _ = self.pad_binary(binary_data)
            else:
                padded_data = binary_data  # No padding needed for decryption


            blocks = [padded_data[i:i+64] for i in range(0, len(padded_data), 64)]
            result = self.process_blocks(blocks, keys, mode)
            self.display_result(result)


        elif input_type in ["File", "Image"]:
            # File handling remains largely the same
            file_path = self.input_entry.get('1.0', tk.END).strip()
            if not os.path.isfile(file_path):
                messagebox.showerror("Error", "Invalid file path.")
                return
            output_path = self.file_operation(file_path, keys, mode)
            self.display_result(f"File {mode}ed successfully. Saved as: {output_path}")
            
    def process_blocks(self, blocks, keys, mode):
        if len(keys) < 3:
            messagebox.showerror("Error", "Three keys are required for Triple DES.")
            return


        key1, key2, key3 = keys[0], keys[1], keys[2]
        processed_blocks = []
        for block in blocks:
            if mode == 'encrypt':
                processed_block = self.triple_des_encrypt_decrypt(block, key1, key2, key3, 'encrypt')
            else:
                processed_block = self.triple_des_encrypt_decrypt(block, key1, key2, key3, 'decrypt')
            processed_blocks.append(processed_block)


        processed_data = ''.join(processed_blocks)
        if mode == 'encrypt':
            return self.binary_to_hex(processed_data)
        else:
            return self.binary_to_string(self.unpad_binary(processed_data))


    def file_operation(self, file_path, keys, mode):
        operation_suffix = 'enc' if mode == 'encrypt' else 'dec'
        output_path = f"{os.path.splitext(file_path)[0]}-3des.{operation_suffix}"
        print(f"Encrypting/Decrypting file: {file_path} to {output_path} using keys {keys} in {mode} mode")
        try:
            key1, key2, key3 = keys  # Unpacking keys from the list
            self.encrypt_decrypt_file(file_path, output_path, key1, key2, key3, mode)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to process file: {str(e)}")
            return None
        return output_path


    def display_result(self, text):
        self.result_text.delete('1.0', tk.END)
        self.result_text.insert(tk.END, text)
    
    def text_to_hex(self, text):
        """ Convert text string to a hexadecimal string. """
        return binascii.hexlify(text.encode()).decode()


    def hex_to_text(self, hex_str):
        """ Convert a hexadecimal string to a plain text string. """
        try:
            bytes_obj = binascii.unhexlify(hex_str)
            return bytes_obj.decode('utf-8')
        except binascii.Error as e:
            return f"Invalid hexadecimal input: {str(e)}"
        except UnicodeDecodeError as e:
            return f"Decoded text is not valid UTF-8: {str(e)}"


    def hex_to_binary(self, hex_str):
        """ Convert a hexadecimal string to a binary string. """
        try:
            binary_str = ''.join(format(byte, '08b') for byte in binascii.unhexlify(hex_str))
            return binary_str
        except binascii.Error:
            return "Invalid hexadecimal input"


    def binary_to_hex(self, binary_str):
        """ Convert a binary string to a hexadecimal string. """
        try:
            n = int(binary_str, 2)
            return '{0:0{1}X}'.format(n, len(binary_str) // 4)
        except ValueError:
            return "Invalid binary data"


    def pad_binary(self, data):
        """Add padding to ensure the data length is a multiple of 64 bits."""
        padding_length = 8 - (len(data) // 8) % 8
        padding = '{:08b}'.format(padding_length) * padding_length
        padded_data = data + padding
        return padded_data, padding_length * 8


        # this function is whack
    def unpad_binary(self, padded_data):
        """Return data without any modification, as no padding is applied."""
        padding_length = int(padded_data[-8:], 2)
        # Ensure that all the padding bits are what they should be
        expected_padding = '{:08b}'.format(padding_length) * padding_length
        if padded_data[-padding_length * 8:] != expected_padding:
            raise ValueError("Invalid padding detected")
        # Remove the padding
        return padded_data[:-padding_length * 8]


    def permute(self, input_data, table):
        """Ensure input data is correctly permuted according to the specified table."""
        if len(input_data) < max(table):
            raise ValueError("Input data is too short for the permutation table.")
        return ''.join(input_data[i - 1] for i in table)


    def xor_function(self, a, b):
        return ''.join('0' if a[i] == b[i] else '1' for i in range(len(a)))


    def f_function(self, right, round_key):
        expanded_right = self.permute(right, self.E)
        xored = self.xor_function(expanded_right, round_key)
        s_box_result = ''
        for i in range(8):
            row = 2 * int(xored[i*6]) + int(xored[i*6 + 5])
            col = int(xored[i*6 + 1:i*6 + 5], 2)
            val = self.S[i][row][col]
            s_box_result += format(val, '04b')
        final_result = self.permute(s_box_result, self.P)
        return final_result


    def left_shift(self, k, shifts):
        return k[shifts:] + k[:shifts]


    def generate_round_keys(self, key):
        round_keys = []
        key_permuted = self.permute(key, self.PC1)
        left, right = key_permuted[:28], key_permuted[28:]
        shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
        for i in shifts:
            left = self.left_shift(left, i)
            right = self.left_shift(right, i)
            combined = left + right
            round_key = self.permute(combined, self.PC2)
            round_keys.append(round_key)
        return round_keys


    def des_encrypt(self, plaintext, round_keys):
        binary_data = self.text_to_binary(plaintext)
        padded_binary_data = self.pad_binary(binary_data)  # Apply PKCS5 padding
        permuted_text = self.permute(padded_binary_data, self.IP)
        left, right = permuted_text[:32], permuted_text[32:]
        for i in range(16):
            right_expanded = self.f_function(right, round_keys[i])
            new_right = self.xor_function(left, right_expanded)
            left, right = right, new_right
        combined = right + left
        encrypted = self.permute(combined, self.IP_1)
        return encrypted  # Return encrypted data as binary string


    def des_decrypt(self, ciphertext_binary, round_keys):
        permuted_text = self.permute(ciphertext_binary, self.IP)
        left, right = permuted_text[:32], permuted_text[32:]
        for i in range(15, -1, -1):
            right_expanded = self.f_function(right, round_keys[i])
            new_right = self.xor_function(left, right_expanded)
            left, right = right, new_right
        combined = right + left
        decrypted = self.permute(combined, self.IP_1)
        unpadded_binary = self.unpad_binary(decrypted)  # Remove PKCS5 padding
        return self.binary_to_string(unpadded_binary)


    def text_to_binary(self, text):
        return ''.join(format(ord(char), '08b') for char in text)


    def binary_to_string(self, binary):
        """ Convert binary string to text, managing non-ASCII and control characters. """
        chars = []
        for i in range(0, len(binary), 8):
            byte = binary[i:i+8]
            if len(byte) < 8:
                continue
            chars.append(chr(int(byte, 2)))
        return ''.join(chars)


    @measure_time
    @profile_cpu
    def des_operation(self, binary_data, round_keys, mode):
        permuted_text = self.permute(binary_data, self.IP)
        left, right = permuted_text[:32], permuted_text[32:]
        if mode == "decrypt":
            round_keys = round_keys[::-1]
        for i in range(16):
            right_expanded = self.f_function(right, round_keys[i])
            new_right = self.xor_function(left, right_expanded)
            left, right = right, new_right
        combined = right + left
        final_result = self.permute(combined, self.IP_1)
        return final_result


    @measure_time
    @profile_cpu
    def triple_des_encrypt_decrypt(self, data, key1, key2, key3, mode="encrypt"):
        round_keys1 = self.generate_round_keys(key1)
        round_keys2 = self.generate_round_keys(key2)
        round_keys3 = self.generate_round_keys(key3)
        
        if mode == "encrypt":
            result = self.des_operation(data, round_keys1, "encrypt")
            result = self.des_operation(result, round_keys2, "decrypt")
            result = self.des_operation(result, round_keys3, "encrypt")
        else:
            result = self.des_operation(data, round_keys3, "decrypt")
            result = self.des_operation(result, round_keys2, "encrypt")
            result = self.des_operation(result, round_keys1, "decrypt")


        return result


    def file_to_binary(self, file_path):
        """Read file content and convert to a binary string."""
        with open(file_path, 'rb') as file:
            content = file.read()
        return ''.join(format(byte, '08b') for byte in content)


    def binary_to_file(self, binary_str, output_path):
        """Convert binary string back to file content."""
        n = len(binary_str)
        byte_array = bytearray()
        for i in range(0, n, 8):
            byte_array.append(int(binary_str[i:i+8], 2))
        with open(output_path, 'wb') as file:
            file.write(byte_array)


    @measure_time
    @profile_cpu
    def encrypt_decrypt_file(self, input_path, output_path, key1, key2, key3, operation='encrypt'):
        """Encrypt or decrypt a file based on operation mode."""
        with open(input_path, 'rb') as f:
            data = f.read()


        # Convert to binary string for processing
        binary_data = ''.join(format(byte, '08b') for byte in data)


        if operation == 'encrypt':
            padded_binary_data, padding_length = self.pad_binary(binary_data)
            blocks = [padded_binary_data[i:i+64] for i in range(0, len(padded_binary_data), 64)]
            encrypted_blocks = [self.triple_des_encrypt_decrypt(block, key1, key2, key3, 'encrypt') for block in blocks]
            encrypted_binary = ''.join(encrypted_blocks)
            self.binary_to_file(encrypted_binary, output_path)
        else:
            encrypted_binary = self.file_to_binary(input_path)
            blocks = [encrypted_binary[i:i+64] for i in range(0, len(encrypted_binary), 64)]
            decrypted_blocks = [self.triple_des_encrypt_decrypt(block, key1, key2, key3, 'decrypt') for block in blocks]
            decrypted_binary = ''.join(decrypted_blocks)
            # Handling padding removal correctly
            unpadded_binary = self.unpad_binary(decrypted_binary)
            self.binary_to_file(unpadded_binary, output_path)


    def main(self):
        user_input = input("Enter the path to your file or message: ")
        operation = input("Type 'encrypt' to encrypt or 'decrypt' to decrypt: ").lower()
        keys = [
            "0100110001001111010101100100010101000011010100110100111001000100",  # Key 1
            "0011001100110011001100110011001100110011001100110011001100110011",  # Key 2
            "0001001100011001010101100110010101000011010100110100111001000101"   # Key 3
        ]


        if os.path.isfile(user_input):
            # Handling file
            file_path = user_input
            # output_path = f"{os.path.splitext(file_path)[0]}_{'encrypted' if operation == 'encrypt' else 'decrypted'}{os.path.splitext(file_path)[1]}"
            operation_suffix = 'enc' if operation == 'encrypt' else 'dec'
            output_path = f"{os.path.splitext(file_path)[0]}-3des.{operation_suffix}"
            self.encrypt_decrypt_file(file_path, output_path, keys, operation)
        else:
            # Handling text
            binary_message = self.text_to_binary(user_input)
            print(f"Original Binary (before padding): {binary_message} (Length: {len(binary_message)})")


            if operation == 'encrypt':
                binary_message, padding_length = self.pad_binary(binary_message)
                # Split into blocks and encrypt
                blocks = [binary_message[i:i+64] for i in range(0, len(binary_message), 64)]
                encrypted_blocks = [self.triple_des_encrypt_decrypt(block, keys, 'encrypt') for block in blocks]
                encrypted_binary = ''.join(encrypted_blocks)
                encrypted_hex = self.binary_to_hex(encrypted_binary)
                print(f"Encrypted Hexadecimal: {encrypted_hex}")
                print(f"Stored Padding Length: {padding_length} bits")
            elif operation == 'decrypt':
                encrypted_binary = self.hex_to_binary(user_input)  # Assume input is in hex for decryption
                # Split into blocks and decrypt
                blocks = [encrypted_binary[i:i+64] for i in range(0, len(encrypted_binary), 64)]
                decrypted_blocks = [self.triple_des_encrypt_decrypt(block, keys, 'decrypt') for block in blocks]
                decrypted_binary = ''.join(decrypted_blocks)
                unpadded_binary = self.unpad_binary(decrypted_binary)
                decrypted_text = self.binary_to_string(unpadded_binary)
                print(f"Decrypted Text: {decrypted_text}")
