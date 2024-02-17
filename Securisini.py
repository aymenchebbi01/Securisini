import hashlib
import os
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import *
from tkinter import filedialog, messagebox
from Cryptodome.Cipher import AES


class EncryptionTool:
    def __init__(self, user_file, user_key, user_salt):
    
       # Store file information:
        self.user_file = user_file  # Path to the input file
        self.input_file_size = os.path.getsize(self.user_file)  # Size of the input file
        self.chunk_size = 1024  # Size of chunks for reading/writing
        self.total_chunks = self.input_file_size // self.chunk_size + 1  # Total number of chunks

        # convert the key and salt to bytes:
        self.user_key = bytes(user_key, "utf-8")  # Convert key to bytes
        self.user_salt = bytes(user_key[::-1], "utf-8")  # Generate salt from reversed key

        # Store file extension and hash type:
        self.file_extension = self.user_file.split(".")[-1]   # Extract file extension
        self.hash_type = "SHA256"  # Hashing algorithm used for key and salt

        # Set output file names:
        self.encrypt_output_file = (
            ".".join(self.user_file.split(".")[:-1])  # Construct encrypted file name
            + "."
            + self.file_extension
            + ".encr"
        )

        self.decrypt_output_file = self.user_file[:-5].split(".")  # Construct decrypted file name
        self.decrypt_output_file = (
            ".".join(self.decrypt_output_file[:-1])
            + "_decrypted."
            + self.decrypt_output_file[-1]
        )       
	# Hash key and salt:
        self.hashed_key_salt = dict()
        self.hash_key_salt()  # Call the hashing function

    def read_in_chunks(self, file_object, chunk_size=1024):
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def encrypt(self):
        # create a cipher object
        cipher_object = AES.new(self.hashed_key_salt["key"], AES.MODE_CFB, self.hashed_key_salt["salt"])
        self.abort()  # if the output file already exists, remove it first
        input_file = open(self.user_file, "rb")
        output_file = open(self.encrypt_output_file, "ab")
        done_chunks = 0

        for piece in self.read_in_chunks(input_file, self.chunk_size):
            encrypted_content = cipher_object.encrypt(piece)
            output_file.write(encrypted_content)
            done_chunks += 1
            yield done_chunks / self.total_chunks * 100

        input_file.close()
        output_file.close()

        # clean up the cipher object
        del cipher_object

    def decrypt(self):

        #  exact same as above function except in reverse
        cipher_object = AES.new(
            self.hashed_key_salt["key"], AES.MODE_CFB, self.hashed_key_salt["salt"]
        )

        self.abort()  # if the output file already exists, remove it first

        input_file = open(self.user_file, "rb")
        output_file = open(self.decrypt_output_file, "xb")
        done_chunks = 0

        for piece in self.read_in_chunks(input_file):
            decrypted_content = cipher_object.decrypt(piece)
            output_file.write(decrypted_content)
            done_chunks += 1
            yield done_chunks / self.total_chunks * 100

        input_file.close()
        output_file.close()

        # clean up the cipher object
        del cipher_object

    def abort(self):
        if os.path.isfile(self.encrypt_output_file):
            os.remove(self.encrypt_output_file)
        if os.path.isfile(self.decrypt_output_file):
            os.remove(self.decrypt_output_file)

    def hash_key_salt(self):

        # --- convert key to hash
        #  create a new hash object
        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_key)

        # turn the output key hash into 32 bytes (256 bits)
        self.hashed_key_salt["key"] = bytes(hasher.hexdigest()[:32], "utf-8")

        # clean up hash object
        del hasher

        # --- convert salt to hash
        #  create a new hash object
        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_salt)

        # turn the output salt hash into 16 bytes (128 bits)
        self.hashed_key_salt["salt"] = bytes(hasher.hexdigest()[:16], "utf-8")

        # clean up hash object
        del hasher

# Create the main application window
class MainWindow:

    # Determine the root directory path based on execution context
    THIS_FOLDER_G = ""
    if getattr(sys, "frozen", False):
        # frozen
        THIS_FOLDER_G = os.path.dirname(sys.executable)
    else:
        # unfrozen
        THIS_FOLDER_G = os.path.dirname(os.path.realpath(__file__))
        
    # Constructor for initializing the GUI elements
    def __init__(self, root):
        self.root = root  	# Assign the root Tkinter window to an attribute
        self._cipher = None  	# Initialize a placeholder for the encryption/decryption cipher
        self._file_url = tk.StringVar()  	# Create a StringVar to store the file path
        self._secret_key = tk.StringVar()  	# Create a StringVar to store the secret key
        self._secret_key_check = tk.StringVar() # Create a StringVar to store the key confirmation
        self._salt = tk.StringVar()  	 # Create a StringVar to store the salt (not currently used)
        self._status = tk.StringVar() 	 # Create a StringVar to display status messages
        self._status.set("---")  	 # Set the initial status message

        self.should_cancel = False

        root.title("Securisini")      # Set the window title
        root.configure(bg="#eeeeee")  # Set the background color

        try:     
            root.call("wm", root._w)
        except Exception:
            pass

	 # Create a menu bar
        self.menu_bar = tk.Menu(root, bg="#eeeeee", relief=tk.FLAT) 	# Create the menu bar
        root.configure(menu=self.menu_bar) 	# Attach the menu bar to the window

	# Create a label for file path input
        self.file_entry_label = tk.Label(
            root,
            text="Enter File Path Or Click SELECT FILE Button",
            bg="#eeeeee",
            anchor=tk.W,  # Anchor text to the left
        )
        # Positioning and layout
        self.file_entry_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=0,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )
	# Create an entry field for file path input
        self.file_entry = tk.Entry(
            root,
            textvariable=self._file_url,  # Link to the StringVar storing the file path 
            bg="#fff",
            exportselection=0, # Disable text selection highlighting 
            relief=tk.FLAT, # Remove border relief
        )
	# Positioning and layout
        self.file_entry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=1,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )
	# Create a button to select a file
        self.select_btn = tk.Button(
            root,
            text="SELECT FILE",
            command=self.selectfile_callback, # Function to call when clicked
            width=42,
            bg="#3498db",
            fg="#ffffff",
            bd=2,
            relief=tk.FLAT,
        )
        # Positioning and layout
        self.select_btn.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=2,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )
	# Create a label for key input #1
        self.key_entry_label1 = tk.Label(
            root,
            text="Enter Key (To be Remembered while Decryption)",
            bg="#eeeeee",
            anchor=tk.W,
        )
        # Positioning and layout
        self.key_entry_label1.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=3,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )
	    # Create an entry field for key input #1
        self.key_entry1 = tk.Entry(
            root,
            textvariable=self._secret_key, # Link to the StringVar storing the key
            bg="#fff",
            exportselection=0,
            relief=tk.FLAT,
        )
        # Positioning and layout
        self.key_entry1.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=4,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )
	# Create a label for key input #2 (validation)
        self.key_entry_label2 = tk.Label(
            root, 
            text="Re-enter Key (Validation)", 
            bg="#eeeeee", 
            anchor=tk.W,
        )
        # Positioning and layout
        self.key_entry_label2.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=5,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )
	# Create an entry field for key input #2 (validation)
        self.key_entry2 = tk.Entry(
            root,
            textvariable=self._secret_key_check,
            bg="#fff",
            exportselection=0,
            relief=tk.FLAT,
        )
        # Positioning and layout
        self.key_entry2.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=6,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )
	    # Create an "ENCRYPT" button
        self.encrypt_btn = tk.Button(
            root,
            text="ENCRYPT",
            command=self.e_check_callback, # Function to call when clicked
            bg="#e60000",
            fg="#ffffff",
            bd=2,
            relief=tk.FLAT,
        )
        # Positioning and layout
        self.encrypt_btn.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=7,
            column=0,
            columnspan=2,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )
	    # Create a "DECRYPT" button
        self.decrypt_btn = tk.Button(
            root,
            text="DECRYPT",
            command=self.d_check_callback,
            bg="#27ae60",
            fg="#ffffff",
            bd=2,
            relief=tk.FLAT,
        )
        # Positioning and layout
        self.decrypt_btn.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=7,
            column=2,
            columnspan=2,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )
	    # Create a label to display status messages
        self.status_label = tk.Label(
            root,
            textvariable=self._status,  # Link to the StringVar storing the status message
            bg="#eeeeee",
            anchor=tk.W,
            justify=tk.LEFT,
            relief=tk.FLAT,
            wraplength=350,
        )
        # Positioning and layout
        self.status_label.grid(
            padx=12,
            pady=(0, 12),
            ipadx=0,
            ipady=1,
            row=9,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )
	    # Configure column weights for equal distribution
        tk.Grid.columnconfigure(root, 0, weight=1) # Make all columns expand equally
        tk.Grid.columnconfigure(root, 1, weight=1)
        tk.Grid.columnconfigure(root, 2, weight=1)
        tk.Grid.columnconfigure(root, 3, weight=1)

    # File selection callback
    def selectfile_callback(self):
        try:
            name = filedialog.askopenfile() # Open a file dialog to select a file
            self._file_url.set(name.name) # Set the file path in the entry field
        except Exception as e:
        # Display an error message in the status label if an exception occurs
            self._status.set(e)
            self.status_label.update()

    # Disable input fields and buttons
    def freeze_controls(self):
        self.file_entry.configure(state="disabled")
        self.key_entry1.configure(state="disabled")
        self.key_entry2.configure(state="disabled")
        self.select_btn.configure(state="disabled", bg="#aaaaaa")
        self.encrypt_btn.configure(state="disabled", bg="#aaaaaa")
        self.decrypt_btn.configure(state="disabled", bg="#aaaaaa")
        self.status_label.update()
        
    # Re-enable input fields and buttons
    def unfreeze_controls(self):
        self.file_entry.configure(state="normal")
        self.key_entry1.configure(state="normal")
        self.key_entry2.configure(state="normal")
        self.select_btn.configure(state="normal", bg="#3498db")
        self.encrypt_btn.configure(state="normal", bg="#27ae60")
        self.decrypt_btn.configure(state="normal", bg="#27ae60")
        self.status_label.update()

    def e_check_callback(self):
 	    # Validate input before starting encryption:
    	# Check if the file path is valid
        newPath = Path(self._file_url.get())
        if newPath.is_file():
            pass
        else:
            messagebox.showinfo("Securisini", "Please Enter a valid File URL !!")
            return
            
        # Check if a valid secret key is entered and if the keys match
        if len(self._secret_key.get()) == 0:
            messagebox.showinfo("Securisini", "Please Enter a valid Secret Key !!")
            return
        elif self._secret_key.get() != self._secret_key_check.get():
            messagebox.showinfo("Securisini", "Passwords do not match !!")
            return
        # If all checks pass, proceed with encryption
        self.encrypt_callback()

    def d_check_callback(self):
	    # Validate input before starting decryption:
    	# Check if the file path is valid
        newPath = Path(self._file_url.get())
        if newPath.is_file():
            pass
        else:
            messagebox.showinfo("Securisini", "Please Enter a valid File URL !!")
            return
	    # Check if the file has the correct .encr extension
        if self._file_url.get()[-4:] != "encr":
            messagebox.showinfo(
                "Securisini",
                """Provided File is not an Encrypted File !!
		        Please Enter an Encrypted File to Decrypt.""")
            return
            
	     # Check if a valid secret key is entered and if the keys match
        if len(self._secret_key.get()) == 0:
            messagebox.showinfo("Securisini", "Please Enter a Secret Key !!")
            return
        elif self._secret_key.get() != self._secret_key_check.get():
            messagebox.showinfo("Securisini", "Passwords do not match !!")
            return
 
        self.decrypt_callback() # If all checks pass, proceed with decryption
        
   # Encryption callback (starts encryption in a separate thread)
    def encrypt_callback(self):
        t1 = threading.Thread(target=self.encrypt_execute) # Create a thread
        t1.start() # Start the thread to run encryption in the background

    def encrypt_execute(self):
        self.freeze_controls()  # Disable controls during encryption
        try:
            self._cipher = EncryptionTool(
              self._file_url.get(), self._secret_key.get(), self._salt.get()
              )  # Create an EncryptionTool instance
            for percentage in self._cipher.encrypt():  # Iterate through encryption progress
                 percentage = "{0:.2f}%".format(percentage)  # Format progress as percentage
                 self._status.set(percentage)  # Update status label
                 self.status_label.update()  # Refresh the label
	
            self._cipher = None  # Clean up the EncryptionTool object
            self._status.set("File Encryption Successful !!")
            messagebox.showinfo("Securisini", "File Encryption Successful !!")

        except Exception as e: 
            self._status.set(e)  # Display the error message 
        self.unfreeze_controls()  # Re-enable controls after encryption

    def decrypt_callback(self):
        t2 = threading.Thread(target=self.decrypt_execute) # Create a thread
        t2.start() # Start the thread to run decryption in the background

    def decrypt_execute(self):
        self.freeze_controls()  # Disable controls during decryption
        try:
            self._cipher = EncryptionTool(
                self._file_url.get(), self._secret_key.get(), self._salt.get()
            )  # Create an EncryptionTool instance
            for percentage in self._cipher.decrypt():  # Iterate through decryption progress
                percentage = "{0:.2f}%".format(percentage)  # Format progress as percentage
                self._status.set(percentage)  # Update status label
                self.status_label.update()  # Refresh the label

            self._cipher = None  # Clean up the EncryptionTool object
            self._status.set("File Decryption Successful !!")
            messagebox.showinfo("Securisini", "File Decryption Successful !!")

        except Exception as e:  # Catch any errors
            self._status.set(e)  # Display the error message
        self.unfreeze_controls()  # Re-enable controls after decryption

    def reset_callback(self):
        self._cipher = None  # Clear the EncryptionTool object
        self._file_url.set("")   # Clear input fields
        self._secret_key.set("")
        self._salt.set("")
        self._status.set("---")

if __name__ == "__main__":  # Check if the script is being run directly
    ROOT = tk.Tk()  # Create the main window using Tkinter
    MAIN_WINDOW = MainWindow(ROOT)  # Create an instance of the MainWindow class
    ROOT.resizable(height=False, width=True)  # Disable window resizing
    ROOT.mainloop()  # Start the Tkinter event loop to display and manage the GUI
