# -*- coding: utf-8 -*-
"""
Created on Sun Sep 17 18:58:09 2023

@author: ctm50
"""

import os
import tkinter as inter
from tkinter import messagebox as mb
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tkinter.simpledialog import askstring
from docx import Document

salt = "JX6U-qAPygq9bVl8migVfb7MEL3yYNpwM3RZ_CZYudI="
DMsalt = "0451-qAPygq9bVl8migVfb7MEL3yYNpwM3RZ_CZYudI="
key = Fernet(salt.encode())
DMkey = Fernet(DMsalt.encode())
directory = "Encode"
out = open("Truth.txt", "x")

for filename in os.listdir(directory):
    title = [];
    body = [];
    DMbody = [];
    f = os.path.join(directory, filename)
    # checking if it is a file
    titleId = 0
    bodyId = 0
    DMId = 0
    idx = 0
    document = Document(f)
    ticker = 0
    for par in document.paragraphs:
        if (len(par.text) > 0):
            if par.text[0] == '#':
                code = par.text[1:]
                out.write(par.text)
                out.write("\n")
            if par.text[0] == '@':
                if par.text[1:] == "Title":
                    ticker = 1
                    out.write("@Title")
                    out.write("\n")
                    out.write(str(key.encrypt(par.text[1:].encode()))[1:])
                    out.write("\n")
                elif par.text[1:] == "Body":
                    ticker = 2
                    out.write("@Body")
                    out.write("\n")
                    out.write(str(key.encrypt('bofa'.encode()))[1:])
                    out.write("\n")
                elif par.text[1:] == "DM":
                    ticker = 3
                    out.write("@DM")
                    out.write("\n")
                    out.write("\n")
                    DMId = idx
            else:
                if (ticker <= 2):
                    out.write(str(key.encrypt(par.text.encode()))[1:])
                    out.write("\n")
                elif (ticker == 3):
                    out.write(str(DMkey.encrypt(par.text.encode()))[1:])
                    out.write("\n")


out.write("<eof>")
out.close()



# # we will be encrypting the below string.
# message = "hello geeks"

# # generate a key for encryption and decryption
# # You can use fernet to generate
# # the key or use random key generator
# # here I'm using fernet to generate key
# salt = os.urandom(16)
# # derive
# kdf = PBKDF2HMAC(
#     algorithm=hashes.SHA256(),
#     length=32,
#     salt=salt,
#     iterations=480000,
# )
# key = kdf.derive(b"my great password")
# # verify
# kdf = PBKDF2HMAC(
#     algorithm=hashes.SHA256(),
#     length=32,
#     salt=salt,
#     iterations=480000,
# )
# kdf.verify(b"my great password", key)

# key = Fernet.generate_key()

# # Instance the Fernet class with the key

# fernet = Fernet(key)

# # then use the Fernet class instance
# # to encrypt the string string must
# # be encoded to byte string before encryption
# encMessage = fernet.encrypt(message.encode())

# print("original string: ", message)
# print("encrypted string: ", encMessage)

# # decrypt the encrypted string with the
# # Fernet instance of the key,
# # that was used for encrypting the string
# # encoded byte string is returned by decrypt method,
# # so decode it to string with decode methods
# decMessage = fernet.decrypt(encMessage).decode()

# print("decrypted string: ", decMessage)

# window = inter.Tk()
# window.title("Guessing Game")

# welcome = inter.Label(window, text="Welcome To The Guessing Game!", background="black", foreground="white")
# welcome.grid(row=0, column=0, columnspan=3)

# def Rules():
#    rule_window = inter.Toplevel(window)
#    rule_window.title("The Rules")
#    the_rules = inter.Label(rule_window, text="Here are the rules...", foreground="black")
#    the_rules.grid(row=0, column=0, columnspan=3)

# rules = inter.Button(window, text="Rules", command=Rules)
# rules.grid(row=1, column=0, columnspan=1)

# window.mainloop()
