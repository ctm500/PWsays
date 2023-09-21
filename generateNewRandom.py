# -*- coding: utf-8 -*-
"""
Created on Sun Sep 17 19:06:03 2023

@author: ctm50
"""

# -*- coding: utf-8 -*-
"""
Created on Sun Sep 17 18:58:09 2023

@author: ctm50
"""

import os
import random

body = []
directory = "C:\\Users\\ctm50\\Documents\\OCR\\Encode"
hexdigits = '0123456789ABCDEF'

def generateCode():
    newCode = ''
    
    for i in range(0,8):
        newCode = newCode + random.choice(hexdigits)
        
    return newCode
    

code = generateCode()

isUnique = False
while (not isUnique):
    isUnique = True
    f = os.path.join(directory, "{}.docx".format(code))
    # checking if it is a file
    if os.path.isfile(f):
        isUnique = True
        code = generateCode()
        
print(code)