# -*- coding: utf-8 -*-
"""
Created on Sun Sep 17 14:41:18 2023

@author: ctm50
"""

# import os
import tkinter as inter
from tkinter import filedialog as fd
import PyInstaller as PI
from tkinter import messagebox as mb
from cryptography.fernet import Fernet
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tkinter.simpledialog import askstring

class logicBox:
    player = True
    body = []
    salt = "JX6U-qAPygq9bVl8migVfb7MEL3yYNpwM3RZ_CZYudI="
    key = Fernet(salt.encode())
    DMkey = key
    isDM = False
    truth = open("Truth.txt", 'r')
    def next(self):
        return self.truth.readline().split('\n')[0]

    def resetRead(self):
        self.truth.seek(0)

    def advance(self,N):
        self.resetRead()
        for i in range(0,N):
            self.next()

    def getReadLines(self, N,M):
        lines = []
        self.resetRead()
        self.advance(N + 1)
        for i in range(N,M):
            lines.append(self.next())
        return lines

    def getCodeLines(self, code):
        titleId, bodyId, DMId, idx = 0,0,0,0
        self.resetRead()

        idx = 0
        encounteredCode = False
        while True:
            line = self.next()
            if (len(line) > 0):
                if (line == '<eof>'):
                    return titleId, bodyId, DMId, idx
                if (line[0] == '#'):
                    if code == str(x.key.decrypt(line[1:].encode()))[2:-1]:
                        encounteredCode = True
                        idx = idx + 1
                        continue
                    elif not encounteredCode:
                        idx = idx + 1
                        continue
                    else:
                        return titleId, bodyId, DMId, idx
                elif (line[0] == '@') & encounteredCode:
                    if line[1:] == "Title":
                        titleId = idx
                    elif line[1:] == "Body":
                        bodyId = idx
                    elif line[1:] == "DM":
                        DMId = idx
            idx = idx + 1

x = logicBox()

def DMmode():
    newpiece = askstring('DM mode', 'DM Password...')
    if len(newpiece) == 0:
        x.player = True
        return
    newkey = newpiece + x.salt[len(newpiece):]
    x.DMkey = Fernet(newkey.encode())
    x.player = False

def call():
    inputCode = askstring('Name', '#:')
    titleId, bodyId, DMId, idx = x.getCodeLines(inputCode)

#    x.body.append("{}\n\n".format(document.paragraphs[titleId+1].text))

    if bodyId == 0:
        return;
        
    titleLines = x.getReadLines(titleId, bodyId-1)
    lines = x.getReadLines(bodyId,DMId-1)
    dmlines = x.getReadLines(DMId, idx-1)

    if not x.player:
        for i in reversed(range(0,len(dmlines))):
            encDMLine = dmlines[i]
            if len(encDMLine) > 0:
                decDMLine = str(x.DMkey.decrypt(encDMLine.encode()))[2:-1]
                text.insert("1.0", "{}\n\n".format(decDMLine))
            else:
                decDMLine = ''
        
        text.insert("1.0", "----------DM----------\n")


    for i in reversed(range(0,len(lines))):
        encLine = lines[i]
        if len(encLine) > 0:
            decLine = str(x.key.decrypt(encLine.encode()))[2:-1]
            text.insert("1.0", "{}\n\n".format(decLine))
        else:
            decLine = ''

    for i in reversed(range(0,len(titleLines))):
        encTitle = titleLines[i]
        if len(encTitle) > 0:
            decTitle = str(x.key.decrypt(encTitle.encode()))[2:-1]
            text.insert("1.0", "{}\n\n".format(decTitle))
        else: 
            decTitle = ''
    
    text.insert("1.0", "========{}======\n".format(inputCode))


def saveandquit():
    res = mb.askquestion('Exit Application',
                         'Do you really want to exit')
    if res == 'yes' :
        saveFileName = askstring('Save game...', 'File name')
        out = open("{}.txt".format(saveFileName), "x")
        out.write(text.get("1.0",inter.END))
        out.write("\n")
        root.destroy()
        return 0


# Driver's code
root = inter.Tk()
canvas = inter.Canvas(root,
                   width = 400,
                   height = 100)

canvas.pack()
b = inter.Button(root,
           text ='#',
           command = call)
c = inter.Button(root,
           text ='DM',
           command = DMmode)
s = inter.Button(root,
           text ='Save and quit',
           command = saveandquit)
root.title("Welcome.")

text = inter.Text(root, height=30, width=100)
scroll = inter.Scrollbar(root)
text.configure(yscrollcommand=scroll.set)
text.pack(side=inter.LEFT)

scroll.config(command=text.yview)
scroll.pack(side=inter.RIGHT, fill=inter.Y)

canvas.create_window(50, 50,
                      window = b)
canvas.create_window(150, 50,
                      window = c)
canvas.create_window(100, 80,
                      window = s)
res = mb.askquestion('Load or new', 'Do you want to load a file?')
if res == 'yes':
    loadFileName = inter.filedialog.askopenfilename()
    loadFile = open(loadFileName)
    loadtxt = loadFile.read()
else:
    loadtxt = ''
    
text.insert("1.0", loadtxt)
if res == 'yes':
    text.insert("1.0", 
                "=====---From session {} ---=====\n".format(loadFileName))
    
root.mainloop()
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
