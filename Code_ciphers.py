import random
import string
import tkinter as tk
from tkinter import messagebox

# ------------------------------------------------------------------------------------------Mixed Alphabet 
def generate_mixed_alphabet(key):
    key = key.upper()
    original_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    unique_list = []
    for item in key:
        if item not in unique_list:
            unique_list.append(item)
    substituted_alphabet = list(unique_list)
    remaining_letters = [letter for letter in original_alphabet if letter not in substituted_alphabet]
    substituted_alphabet.extend(remaining_letters)
    mixed_alphabet = dict(zip(original_alphabet, substituted_alphabet))
    return mixed_alphabet

def encrypt(plaintext, mixed_alphabet):
    ciphertext = ""
    for char in plaintext.upper():
        if char.isalpha():
            ciphertext += mixed_alphabet.get(char, char)
        else:
            ciphertext += char
    return ciphertext

def decrypt(ciphertext, reverse_mixed_alphabet):
    decrypted_text = ""
    for char in ciphertext.upper():
        if char.isalpha():
            decrypted_text += reverse_mixed_alphabet.get(char, char)
        else:
            decrypted_text += char
    return decrypted_text

# ----------------------------------------------------------------------------------------------Caesar Cipher 
def caesar_encrypt(plain_text, shift):
    encrypted_text = ""
    for char in plain_text:
        if char.isalpha():  
            ascii_val = ord(char)
            shift_base = 65 if char.isupper() else 97
            encrypted_text += chr((ascii_val - shift_base + shift) % 26 + shift_base)
        else:
            encrypted_text += char 
    return encrypted_text

def caesar_decrypt(encrypted_text, shift):
    decrypted_text = ""
    for char in encrypted_text:
        if char.isalpha():  
            ascii_val = ord(char)
            shift_base = 65 if char.isupper() else 97
            decrypted_text += chr((ascii_val - shift_base - shift) % 26 + shift_base)
        else:
            decrypted_text += char  
    return decrypted_text

def caesar_poly_cipher(text, shift, mode):
    result = ""
    oshift = shift  
    if mode == "d":
        shift = -shift
        oshift = -oshift
    for char in text:
        if char.isalpha():
            ascii_val = ord(char)
            shift_base = 65 if char.isupper() else 97
            result += chr((ascii_val - shift_base + shift) % 26 + shift_base)
            shift = shift + oshift
        else:
            result += char
    return result

# --------------------------------------------------------------------------------------------Vigenère Cipher with ASCII
def vigenere_cipher_ascii(text, keyword, mode):
    min_ascii = 32
    max_ascii = 126
    num_chars = 95  
    result = ""
    
    keyword_repeated = (keyword * (len(text) // len(keyword) + 1))[:len(text)]
    
    for char, key_char in zip(text, keyword_repeated):
        char_ascii = ord(char)
        key_ascii = ord(key_char)
        
        if mode == "d":
            key_ascii = -key_ascii
        
        shifted_value = (char_ascii + key_ascii - min_ascii) % num_chars + min_ascii
        result += chr(shifted_value)
            
    return result

# ----------------------------------------------------------------------------------------------Columnar Transposition 
def columnar_transposition_decrypt(ciphertext, key):
    num_cols = len(key) if isinstance(key, (list, str)) else key
    num_rows = len(ciphertext) // num_cols
    extra_chars = len(ciphertext) % num_cols
    
    if isinstance(key, (list, str)):
        col_order = sorted(range(len(key)), key=lambda x: key[x])
    else:
        col_order = list(range(num_cols))

    matrix = [''] * num_cols
    col_start = 0
    for i in col_order:
        col_length = num_rows + (1 if i < extra_chars else 0)
        matrix[i] = ciphertext[col_start:col_start + col_length]
        col_start += col_length

    decrypted_text = ''
    for row in range(num_rows + (1 if extra_chars > 0 else 0)):
        for col in range(num_cols):
            if row < len(matrix[col]):
                decrypted_text += matrix[col][row]

    return decrypted_text

def columnar_transposition(text, key):
    text = ''.join([char for char in text if char])
    num_cols = len(key) if isinstance(key, (list, str)) else key

    if isinstance(key, (list, str)):
        sorted_key_indices = sorted(range(num_cols), key=lambda x: key[x])
    else:
        sorted_key_indices = list(range(num_cols))

    cipher_text = [''] * num_cols

    for column in range(num_cols):
        pointer = column
        while pointer < len(text):
            cipher_text[column] += text[pointer]
            pointer += num_cols

    encrypted_text = ''.join([cipher_text[i] for i in sorted_key_indices])
    return encrypted_text

# ------------------------------------------------------------------------------------------------------------Rail Fence 
def rail_fence_decrypt(ciphertext, rails):
    ciphertext = ''.join([char for char in ciphertext if char.isalpha()])
    rail_matrix = [['' for _ in range(len(ciphertext))] for _ in range(rails)]
    
    direction = 1
    row, col = 0, 0
    for i in range(len(ciphertext)):
        rail_matrix[row][col] = '*'
        col += 1
        if row == 0:
            direction = 1  
        elif row == rails - 1:
            direction = -1  
        row += direction
    
    index = 0
    for r in range(rails):
        for c in range(len(ciphertext)):
            if rail_matrix[r][c] == '*' and index < len(ciphertext):
                rail_matrix[r][c] = ciphertext[index]
                index += 1

    result = []
    direction = 1 
    row, col = 0, 0
    for i in range(len(ciphertext)):
        result.append(rail_matrix[row][col])
        col += 1
        if row == 0:
            direction = 1  
        elif row == rails - 1:
            direction = -1  
        row += direction

    return ''.join(result)


def encrypt_rail_fence(text, key):
    text = ''.join([char for char in text if char.isalpha()])
    rail = [['' for cols in range(len(text))] for rows in range(key)]
    
    row, col = 0, 0
    direction = 1  
    
    for char in text:
        rail[row][col] = char
        col += 1
        
        if row + direction < 0 or row + direction >= key:
            direction *= -1
        row += direction

    encrypted_text = ''.join([''.join(row) for row in rail if ''.join(row) != ''])
    return encrypted_text

#---------------------------------------------------------------------------------------------------------------monoalphabatic
def generate_monoalphabatic_cipher_key():
    lowercase_alphabet = list(string.ascii_lowercase)
    uppercase_alphabet = list(string.ascii_uppercase)
    random.shuffle(lowercase_alphabet)
    random.shuffle(uppercase_alphabet)
    return ''.join(lowercase_alphabet + uppercase_alphabet)

def encrypt_monoalphabetic(plaintext, cipher_key):
    encrypted_text = ''
    for char in plaintext:
        if char in string.ascii_lowercase:
            index = string.ascii_lowercase.index(char)
            encrypted_text += cipher_key[index]
        elif char in string.ascii_uppercase:
            index = string.ascii_uppercase.index(char)
            encrypted_text += cipher_key[index + 26]
        else:
            encrypted_text += char
    return encrypted_text

def decrypt_monoalphabetic(ciphertext, cipher_key):
    decrypted_text = ''
    for char in ciphertext:
        if char in string.ascii_lowercase:
            index = cipher_key.index(char)
            decrypted_text += string.ascii_lowercase[index]
        elif char in string.ascii_uppercase:
            index = cipher_key.index(char)
            decrypted_text += string.ascii_uppercase[index - 26]
        else:
            decrypted_text += char
    return decrypted_text


# ----------------------------------------------------------------------------------------------------------------------gui

class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptography Ciphers")
        self.root.geometry("450x500") 

        self.selected_cipher = None
        self.result_label = None
        self.result_text = None
        
        self.display_cipher_buttons()

    def display_cipher_buttons(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        self.cipher_label = tk.Label(self.root, text="Please choose a cipher to continue:", font=("Arial", 14))
        self.cipher_label.pack(pady=10)

        cipher_buttons = [
            "Mixed Alphabet Cipher", 
            "Caesar Cipher", 
            "Monoalphabetic Cipher",
            "Polyalphabetic Caesar Cipher", 
            "Vigenère Cipher", 
            "Columnar Transposition Cipher", 
            "Rail Fence Cipher" 
            
        ]
        
        for cipher in cipher_buttons:
            cipher_button = self.create_button_with_shadow(
                text=cipher,
                command=lambda c=cipher: self.select_cipher(c),
                width=30, height=2, 
                bg="blue", fg="white",
                font=("Arial", 9)
            )
            cipher_button.pack(pady=5)

    def create_button_with_shadow(self, text, command, width, height, bg, fg, font):
        frame = tk.Frame(self.root)
        frame.pack_propagate(0) 
        frame.config(width=width + 4, height=height + 4) 

        shadow_button = tk.Button(frame, text=text, command=command, width=width, height=height,bg="gray", fg="gray", font=font, relief="raised")
        shadow_button.grid(row=0, column=0, padx=3, pady=3) 

        button = tk.Button(frame, text=text, command=command, width=width, height=height,
                           bg=bg, fg=fg, font=font, relief="raised")
        button.grid(row=0, column=0) 

        return frame

    def select_cipher(self, cipher):
        self.selected_cipher = cipher
        self.show_action_page()

    def show_action_page(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        self.action_label = tk.Label(self.root, text=f"Choose Action for {self.selected_cipher}:", font=("Arial", 14))
        self.action_label.pack(pady=10)

        self.action_choice = tk.StringVar()
        self.action_choice.set("Encrypt")
        self.action_menu = tk.OptionMenu(self.root, self.action_choice, "Encrypt", "Decrypt")
        self.action_menu.pack(pady=5)

        self.key_label = tk.Label(self.root, text="Enter Key:", font=("Arial", 12))
        self.key_label.pack(pady=5)

        self.key_entry = tk.Entry(self.root)
        self.key_entry.pack(pady=5)

        self.text_label = tk.Label(self.root, text="Enter Text:", font=("Arial", 12))
        self.text_label.pack(pady=5)

        self.text_entry = tk.Text(self.root, height=5, width=40)
        self.text_entry.pack(pady=10)

        self.process_button = self.create_button_with_shadow(
            text="Process", 
            command=self.process_input,
            width=20, height=2, 
            bg="blue", fg="white", 
            font=("Arial", 9)
        )
        self.process_button.pack(pady=10)

        self.back_button = self.create_button_with_shadow(
            text="Back", 
            command=self.display_cipher_buttons,
            width=20, height=2, 
            bg="gray", fg="white", 
            font=("Arial", 9)
        )
        self.back_button.pack(pady=10)

    def process_input(self):  # Ensure this is inside the CipherApp class
        action = self.action_choice.get()
        key = self.key_entry.get()
        text = self.text_entry.get("1.0", tk.END).strip()

        if not key or not text:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        try:
            if self.selected_cipher == "Mixed Alphabet Cipher":
                self.handle_mixed_alphabet(action, key, text)
            elif self.selected_cipher == "Caesar Cipher":
                self.handle_caesar(action, key, text)
            elif self.selected_cipher == "Polyalphabetic Caesar Cipher":
                self.handle_caesar_poly(action, key, text)
            elif self.selected_cipher == "Vigenère Cipher":
                self.handle_vigenere(action, key, text)
            elif self.selected_cipher == "Columnar Transposition Cipher":
                self.handle_columnar(action, key, text)
            elif self.selected_cipher == "Rail Fence Cipher":
                self.handle_rail_fence(action, key, text)
            elif self.selected_cipher == "Monoalphabetic Cipher":
                self.handle_monoalphabetic(action, key, text)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
    def handle_mixed_alphabet(self, action, key, text):
        mixed_alphabet = generate_mixed_alphabet(key)
        reverse_mixed_alphabet = {v: k for k, v in mixed_alphabet.items()}
        
        if action == "Encrypt":
            result = encrypt(text, mixed_alphabet)
        else:
            result = decrypt(text, reverse_mixed_alphabet)
        
        self.display_result(result)

    def handle_caesar(self, action, key, text):
        try:
            shift = int(key)
            if action == "Encrypt":
                result = caesar_encrypt(text, shift)
            else:
                result = caesar_decrypt(text, shift)
            self.display_result(result)
        except ValueError:
            messagebox.showerror("Error", "Invalid Caesar cipher key. Please enter an integer.")

    def handle_caesar_poly(self, action, key, text):
        try:
            shift = int(key)
            result = caesar_poly_cipher(text, shift, "e" if action == "Encrypt" else "d")
            self.display_result(result)
        except ValueError:
            messagebox.showerror("Error", "Invalid Caesar cipher key. Please enter an integer.")

    def handle_vigenere(self, action, key, text):
        result = vigenere_cipher_ascii(text, key, "e" if action == "Encrypt" else "d")
        self.display_result(result)

    def handle_columnar(self, action, key, text):
        key_type = self.key_entry.get().strip()
    
        if key_type.isdigit():  
            key = int(key_type)
        elif ' ' in key_type:  
            key = [int(num) for num in key_type.split()]
        else:  
            key = list(key_type)
        
        if action == "Encrypt":
            result = columnar_transposition(text, key)
        else:
            result = columnar_transposition_decrypt(text, key)
    
        self.display_result(result)
    

    def handle_rail_fence(self, action, key, text):
        try:
            rails = int(key)
            if action == "Encrypt":
                result = encrypt_rail_fence(text, rails)
            else:
                result = rail_fence_decrypt(text, rails)
            self.display_result(result)
        except ValueError:
            messagebox.showerror("Error", "Invalid Rail Fence cipher key. Please enter an integer.")

    def handle_monoalphabetic(self, action, key, text):
        cipher_key = generate_monoalphabatic_cipher_key() 
        if action == "Encrypt":
            result = encrypt_monoalphabetic(text, cipher_key)
        else:
            result = decrypt_monoalphabetic(text, cipher_key)
        self.display_result(result)

    def display_result(self, result):
        if self.result_label:
            self.result_label.destroy()
        if self.result_text:
            self.result_text.destroy()
    
        self.result_label = tk.Label(self.root, text="Result:", font=("Arial", 14))
        self.result_label.pack(pady=0)
    
        self.result_text = tk.Text(self.root, height=2, width=40)  
        self.result_text.pack(pady=(0))
        self.result_text.insert(tk.END, result)
        self.result_text.config(state=tk.DISABLED)

root = tk.Tk()
app = CipherApp(root)
root.mainloop()
