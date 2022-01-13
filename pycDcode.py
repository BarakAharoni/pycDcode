# -*- coding: utf-8 -*-
"""
 Python PYC File Analysis

 Use the script as follow:
    1) Get Bytecodes from pyc:  python pycDcode.py --pyc {pyc-file} --bytecode > {output-file}
    2) Build Script Template:   python pycDcode.py --bcfile {bytecode-file} --template

Bytecode parsing documentation: https://betterprogramming.pub/analysis-of-compiled-python-files-629d8adbe787

 Copyright (c) 2022 Barak Aharoni.  All Rights Reserved.
"""
from hashlib import new
from pickle import INST
import platform
import time
import binascii
import struct

import sys
import dis, marshal
import argparse
import re

__version__ = '13.1.22'
__author__ = "Barak Aharoni"

BANNER = """
###############################################################
#    Python PYC File Analysis                                 #
#                                                             #
#                   ___             _                         #
#      _ __ _  _ __|   \ __ ___  __| |___                     #
#     | '_ \ || / _| |) / _/ _ \/ _` / -_)                    #
#     | .__/\_, \__|___/\__\___/\__,_\___|                    #
#     |_|   |__/                                              #
#                                                             #
# Copyright (c) 2022 Barak Aharoni.  All Rights Reserved.     #
###############################################################
"""

# First 16 bytes comprise the pyc header (python 3.6+), else 8 bytes.
SIZE_FILE_VERSION = "3.6"
HEADER_SIZE_NEW = 16
HEADER_SIZE_OLD = 8

# Parsing Regex
INSTRUCTION_REGEX = "\s\d+\s([A-Z_]+)"
ARGUMENT_REGEX = "\s\d+\s\((.*)\)"
FUNCTION_OFFSET_REGEX = "at\s(.*),\s"
JUMP_TO_REGEX = "\d+\s\w+_JUMP_\w+\s+(\d+)"
LINE_NUMBER_REGEX = "\s+(\d+)\s\w+"
RETURN_REGEX = ">>"
PRIVATE_FUNCTION_REGEX = "Disassembly of <code object (\w+)"
FULL_PRIVATE_FUNCTION_REGEX = "Disassemblyof <code object (\w+).*>:(.*)Disassembly of <code object (\w+)"
RETURN_VALUE_REGEX = "RETURN_VALUE"
INSTRUCTION_DICT = {

    # Import
    "LOAD_GLOBAL|LOAD_METHOD" : "{}.{}(",

    "IMPORT_STAR" : ["IMPORT_NAME\s+\d+\s+\((.*)\)", "from {} import *"],
    "IMPORT_NAME|IMPORT_FROM" : ["IMPORT_FROM\s+\d+\s+\((.*)\).*IMPORT_NAME\s+\d+\s+\((.*)\)",
                                 "from {} import {}"],
    "IMPORT_NAME": "import {}",

    # Use variables
    "LOAD_FAST|STORE_FAST" : "{} = {}",
    "LOAD_GLOBAL|STORE_GLOBAL" : "global {}\n{} = {}",
    "LOAD_NAME|STORE_NAME" : "{} = {}",

    # Call Functions
    "CALL_METHOD" : ")",
    "CALL_FUNCTION" : "",

    # If
    "POP_JUMP_IF_FALSE" : "if {} ",
    "POP_JUMP_IF_TRUE" : "if {} ",
    "COMPARE_OP" : "{}",
    "CONTAINS_OP" : "{} in ",

    # Loop
    "LOAD_FAST|GET_ITER|FOR_ITER|STORE_FAST" : "for {} in {}:",
    "LOAD_GLOBAL|GET_ITER|FOR_ITER|STORE_FAST" : "for {} in {}:",
    "POP_TOP" : "\n"
    }
    
FINAL_PY_FILE = ".\\finalScript.py"

# Get bytecodes from pyc file.
# You'll need to pipe the result to dedicated file
def manuallyDecompile(pycFile, fileVersion):
  
    with open(pycFile, 'rb') as f:
        if fileVersion > SIZE_FILE_VERSION:
            headerSize = HEADER_SIZE_NEW
        else:
            headerSize = HEADER_SIZE_OLD
        
        pycHeader = f.read(headerSize)
        codeObj = marshal.load(f) # Suite to code object
    dis.dis(codeObj)

def buildTemplate(bytecodeFile):
    with open(bytecodeFile, 'r') as f:
        content = f.read().splitlines()
    with open(FINAL_PY_FILE, 'w') as f:
        f.write(BANNER)
    
    chunk = {}
    line_numbers = []
    for line in content:
        instruction, argument = "" , ""
        if re.findall(PRIVATE_FUNCTION_REGEX, line):
            return
        
        # End of chunk - start parsing
        if line == '':
            chunk["LINE_NUMBERS"] = line_numbers
            parseChunks(chunk)
            chunk = {}
            line_numbers = []
            continue

        try:
            if re.findall(INSTRUCTION_REGEX, line)[0] == "LOAD_CONST":
                if re.findall(RETURN_REGEX, line):
                    chunk["RETURN_VALUE"] = re.findall(RETURN_REGEX, line)[0]
                    continue
        except:
            pass

        if re.findall(INSTRUCTION_REGEX, line):
            instruction = re.findall(INSTRUCTION_REGEX, line)[0]
        
        if re.findall(ARGUMENT_REGEX, line):
            argument = re.findall(ARGUMENT_REGEX, line)[0]

        if re.findall(FUNCTION_OFFSET_REGEX, line):
            chunk["FUNC_OFFSET"] = re.findall(FUNCTION_OFFSET_REGEX, line)[0].split(',')[0]

        if re.findall(LINE_NUMBER_REGEX, line):
            line_numbers.append(re.findall(LINE_NUMBER_REGEX, line)[0])

        if re.findall(JUMP_TO_REGEX, line):
           chunk["JUMP_TO"] = re.findall(JUMP_TO_REGEX, line)[0]
        
        chunk[instruction] = argument

def parseChunks(chunk):
    instructions = chunk.keys()
    pyLine = ""
    newLine = True

    # Import module
    if "IMPORT_STAR" in instructions:
        pyLine += "from {} import *".format(chunk["IMPORT_NAME"])
        newLine = True
    elif "IMPORT_FROM" in instructions:
        pyLine += "from {} import {}".format(chunk["IMPORT_NAME"],
                                              chunk["IMPORT_FROM"])
    elif "IMPORT_NAME" in instructions:
        pyLine += "import {}".format(chunk["IMPORT_NAME"])
        newLine = True

    # Call function
    elif "CALL_METHOD" in instructions:
        newLine = True
        if "STORE_NAME" in instructions: # Save results to variable
            if "LOAD_NAME" in instructions: # The function
                if "LOAD_METHOD" in instructions: # With arguments
                    pyLine += "{} = {}({})".format(chunk["STORE_NAME"],
                                                    chunk["LOAD_NAME"],
                                                    chunk["LOAD_METHOD"])
                else:
                    pyLine += "{} = {}()".format(chunk["STORE_NAME"],
                                                  chunk["LOAD_NAME"])
            else:
                if "LOAD_NAME" in instructions: # The function
                    if "LOAD_METHOD" in instructions: # With arguments
                        pyLine += "{}({})".format(chunk["LOAD_NAME"],
                                                   chunk["LOAD_METHOD"])
                    else:
                        pyLine += "{}()".format(chunk["LOAD_NAME"])
                elif "LOAD_FAST" in instructions:
                    if "LOAD_METHOD" in instructions:
                        pyLine += "{}.{}()".format(chunk["LOAD_FAST"],
                                                    chunk["LOAD_METHOD"])
                    elif "LOAD_GLOBAL" in instructions:
                        if "LOAD_METHOD" in instructions:
                            pyLine += "{}.{}".format(chunk["LOAD_GLOBAL"],
                                                      chunk["LOAD_METHOD"])
    elif "CALL_FUNCTION" in instructions:
        newLine = True
        if "LOAD_NAME" in instructions:
            pyLine += "{}()".format(chunk["LOAD_NAME"])

    # If statement
    elif "COMPARE_OP" in instructions:
        newLine = True
        if "POP_JUMP_IF_FALSE" in instructions: # Jump to line number if statement is false
            jumpTo = chunk["JUMP_TO"]
            jumpFlag = True

        if "LOAD_CONST" in instructions:
            if "LOAD_NAME" in instructions:
                pyLine += "\nif {} == {}:".format(chunk["LOAD_NAME"], chunk["LOAD_CONST"])
            elif "LOAD_FAST" in instructions:
                pyLine += "\nif {} == {}:".format(chunk["LOAD_FAST"], chunk["LOAD_CONST"])
    
    # Create Function
    elif "MAKE_FUNCTION" in instructions:
        newLine = False
        buildFuncOffset = chunk["FUNC_OFFSET"]
        if "STORE_NAME" in instructions:
            pyLine = "\ndef {}():".format(chunk["STORE_NAME"])
        
    # Variables
    elif "STORE_NAME" in instructions:
        newLine = True
        if "LOAD_CONST" in instructions:
            pyLine += "{} = {}".format(chunk["STORE_NAME"], chunk["LOAD_CONST"])
        elif "LOAD_NAME" in instructions:
            pyLine += "{} = {}".format(chunk["STORE_NAME"], chunk["LOAD_NAME"])
    elif "STORE_GLOBAL" in instructions:
        newLine = True
        if "LOAD_CONST" in instructions:
            pyLine += "{} = {}".format(chunk["STORE_GLOBAL"], chunk["LOAD_CONST"])
        elif "LOAD_NAME" in instructions:
            pyLine += "{} = {}".format(chunk["STORE_GLOBAL"], chunk["LOAD_NAME"])

    with open(FINAL_PY_FILE, 'a') as f:
        f.write(pyLine)
        if newLine:
            f.write("\n")
    
if __name__ == '__main__':
    print(BANNER)

    parser = argparse.ArgumentParser(description='pycDcode - PYC Bytecode Analysis')
    parser.add_argument('--pyc', help='PYC file')
    parser.add_argument('--bcfile', help='ByteCode file')
    parser.add_argument('--version', help='Python script version (2.7, 3.6, 3.9...)')
    parser.add_argument('--bytecode', help='Return bytecodes' , action='store_true')
    parser.add_argument('--template', help='Build script template' , action='store_true')
    args = parser.parse_args()

    if args.pyc:
        if args.bytecode:
            if args.version:
                manuallyDecompile(args.pyc, args.version)
            else:
                manuallyDecompile(args.pyc, "2.7") # Default
    if args.bcfile:
        if args.template:
            buildTemplate(args.bcfile)