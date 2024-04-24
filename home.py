import tkinter as tk
import tkinter as tk
from tkinter import filedialog
from vigenere_page import VigenerePage
from base import BasePage
from rsa_page import RSAPage
from aes_page import AESPage
from des_page import TripleDESPage


class HomePage(BasePage):
    def __init__(self, master):
        super().__init__(master)

        # Creating a Text widget
        self.content_text = tk.Text(self, wrap="word", font=("Helvetica", 16), pady=20)
        self.content_text.pack(expand=True, fill="both")

        # Inserting the text
        centered_text = ("Welcome to Cryptic GUIde!\n\n"
                         "Explore the exciting world of cryptography with our fun and interactive app.\n "
                         "Choose from a variety of ciphers and encryption techniques to encrypt and decrypt "
                         "messages and test your skills!\n\n"
                         "Click on the buttons up top to get started")
        self.content_text.insert(tk.END, centered_text)
        self.content_text.tag_configure("center", justify="center")
        self.content_text.tag_add("center", "1.0", "end")
        self.content_text.tag_configure("title", font=("Helvetica", 40, "bold"))
        self.content_text.tag_add("title", "1.0", "1.end")
        self.content_text.config(state="disabled")


class NavigationApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Navigation App")
        self.geometry("1100x800")

        self.nav_frame = tk.Frame(self, bg='#add8e6')
        self.nav_frame.pack(side="top", fill="x")

        self.pages = {
            "Home": HomePage,
            "Vigenere": VigenerePage,
            "Triple DES": TripleDESPage,
            "AES": AESPage,
            "RSA": RSAPage
        }

        self.current_page = None
        self.create_navigation_buttons()
        self.show_page("Home")
    def home(self):
        self.show_page("Home")

    def show_page(self, page_name):
        if self.current_page is not None:
            self.current_page.destroy()

        page_class = self.pages[page_name]
        self.current_page = page_class(self)
        self.current_page.pack(expand=True, fill="both")

    def create_navigation_buttons(self):
        # Clear existing navigation buttons
        for widget in self.nav_frame.winfo_children():
            widget.destroy()

        # Create buttons for each page
        for page_name in self.pages:
            button = tk.Button(self.nav_frame, text=page_name, bg='powder blue', command=lambda page=page_name: self.show_page(page))
            button.pack(side="left", padx=10, pady=5)




if __name__ == "__main__":
    app = NavigationApp()
    app.create_navigation_buttons()  # Create navigation buttons
    app.mainloop()

