# -*- coding: utf-8 -*-
"""
 Python PYC File Analysis

 Use the script as follow:
    1) Get Bytecodes from pyc:  python pycDcode.py --pyc {pyc-file} --bytecode --version {py-version} > {output-file}
    2) Build Script Template:   python pycDcode.py --bcfile {bytecode-file} --template

Bytecode parsing documentation: https://betterprogramming.pub/analysis-of-compiled-python-files-629d8adbe787

 Copyright (c) 2022 Barak Aharoni.  All Rights Reserved.
"""

import sys
import dis, marshal
import argparse
import re
from packaging.version import Version

__version__ = '2.0.0'
__author__ = "Barak Aharoni"

BANNER = r"""
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
# Supports Python 2.7 - 3.13                                  #
###############################################################
"""

# ─────────────────────────────────────────────────────────────
# PYC Header Sizes
# ─────────────────────────────────────────────────────────────
# Python < 3.0  : 8 bytes  (magic + timestamp)
# Python 3.0-3.5: 12 bytes (magic + timestamp + source size)
# Python 3.6    : 12 bytes (magic + bit field + timestamp + source size)
# Python 3.7+   : 16 bytes (magic + bit field + timestamp + source size)
#                  OR 16 bytes (magic + bit field + hash + source size) for hash-based validation

def get_header_size(version_str):
    """Return the correct PYC header size for a given Python version string."""
    ver = Version(version_str)
    if ver < Version("3.0"):
        return 8
    elif ver < Version("3.6"):
        return 12
    else:
        # 3.6 has 12, but 3.7+ has 16; in practice 3.6+ is often treated as 16
        # because 3.6 added the PEP 552 flags field in later micro versions.
        # The original code used 16 for >3.6, 8 otherwise. We keep 16 for 3.7+
        # and 12 for 3.6.
        if ver >= Version("3.7"):
            return 16
        else:
            return 12


# ─────────────────────────────────────────────────────────────
# Parsing Regex
# ─────────────────────────────────────────────────────────────
INSTRUCTION_REGEX = r"\s\d+\s([A-Z_]+)"
ARGUMENT_REGEX = r"\s\d+\s\((.*)\)"
FUNCTION_OFFSET_REGEX = r"at\s(.*),\s"
JUMP_TO_REGEX = r"\d+\s\w+_JUMP_\w+\s+(\d+)"
LINE_NUMBER_REGEX = r"\s+(\d+)\s\w+"
RETURN_REGEX = r">>"
PRIVATE_FUNCTION_REGEX = r"Disassembly of <code object (\w+)"
FULL_PRIVATE_FUNCTION_REGEX = r"Disassemblyof <code object (\w+).*>:(.*)Disassembly of <code object (\w+)"
RETURN_VALUE_REGEX = r"RETURN_VALUE"

# ─────────────────────────────────────────────────────────────
# Opcode Mapping (version-aware)
# ─────────────────────────────────────────────────────────────
# Python 3.11+ merged LOAD_METHOD into LOAD_ATTR (with low bit flag).
# Python 3.12  added LOAD_SUPER_ATTR, RETURN_CONST, removed LOAD_METHOD entirely.
# Python 3.12  changed POP_JUMP_IF_* to undirected (no _FORWARD / _BACKWARD suffix).
# Python 3.12+ replaced CALL_FUNCTION / CALL_METHOD with the unified CALL opcode.
# Python 3.13  moved some opcodes to pseudo-instructions and added specialization opcodes.
#
# We handle these by normalising newer opcodes to their legacy equivalents during parsing.

# Map of newer opcodes -> legacy equivalents for template generation
OPCODE_ALIASES = {
    # 3.11: LOAD_METHOD merged into LOAD_ATTR
    "LOAD_ATTR":        "LOAD_ATTR",       # may act as LOAD_METHOD if low-bit set
    # 3.12+: unified CALL replaces CALL_FUNCTION and CALL_METHOD
    "CALL":             "CALL_FUNCTION",
    "CALL_KW":          "CALL_FUNCTION_KW",
    "CALL_FUNCTION_EX": "CALL_FUNCTION_EX",
    # 3.12: RETURN_CONST combines LOAD_CONST + RETURN_VALUE
    "RETURN_CONST":     "RETURN_VALUE",
    # 3.12+: LOAD_SUPER_ATTR is a new super() accessor
    "LOAD_SUPER_ATTR":  "LOAD_ATTR",
    # 3.11+: RESUME is a no-op used for tracing
    "RESUME":           None,
    # 3.11+: CACHE entries should be skipped
    "CACHE":            None,
    # 3.11+: PUSH_NULL pushes NULL before a call
    "PUSH_NULL":        None,
    # 3.11+: PRECALL was short-lived (3.11 only, removed in 3.12)
    "PRECALL":          None,
    # 3.11+: COPY_FREE_VARS for closures
    "COPY_FREE_VARS":   None,
    # 3.11+: MAKE_CELL
    "MAKE_CELL":        None,
    # 3.12+: undirected jump variants
    "POP_JUMP_IF_FALSE":   "POP_JUMP_IF_FALSE",
    "POP_JUMP_IF_TRUE":    "POP_JUMP_IF_TRUE",
    "POP_JUMP_IF_NONE":    "POP_JUMP_IF_FALSE",
    "POP_JUMP_IF_NOT_NONE":"POP_JUMP_IF_TRUE",
    # 3.12+: LOAD_FAST_AND_CLEAR used in comprehensions
    "LOAD_FAST_AND_CLEAR": "LOAD_FAST",
    # 3.12+: LOAD_FAST_CHECK
    "LOAD_FAST_CHECK":     "LOAD_FAST",
    # 3.13+: specialization opcodes map back to generic forms
    "BINARY_OP_ADD_INT":          "BINARY_OP",
    "BINARY_OP_ADD_FLOAT":        "BINARY_OP",
    "BINARY_OP_ADD_UNICODE":      "BINARY_OP",
    "BINARY_OP_MULTIPLY_INT":     "BINARY_OP",
    "BINARY_OP_MULTIPLY_FLOAT":   "BINARY_OP",
    "BINARY_OP_SUBTRACT_INT":     "BINARY_OP",
    "BINARY_OP_SUBTRACT_FLOAT":   "BINARY_OP",
    "LOAD_ATTR_INSTANCE_VALUE":   "LOAD_ATTR",
    "LOAD_ATTR_MODULE":           "LOAD_ATTR",
    "LOAD_ATTR_SLOT":             "LOAD_ATTR",
    "LOAD_GLOBAL_MODULE":         "LOAD_GLOBAL",
    "LOAD_GLOBAL_BUILTIN":        "LOAD_GLOBAL",
    "STORE_ATTR_INSTANCE_VALUE":  "STORE_ATTR",
    "STORE_ATTR_SLOT":            "STORE_ATTR",
}

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

    # Call Functions (legacy)
    "CALL_METHOD" : ")",
    "CALL_FUNCTION" : "",

    # Call Functions (3.12+ unified CALL)
    "CALL" : "",

    # If
    "POP_JUMP_IF_FALSE" : "if {} ",
    "POP_JUMP_IF_TRUE" : "if {} ",
    "POP_JUMP_IF_NONE" : "if {} is None ",
    "POP_JUMP_IF_NOT_NONE" : "if {} is not None ",
    "COMPARE_OP" : "{}",
    "CONTAINS_OP" : "{} in ",

    # Loop
    "LOAD_FAST|GET_ITER|FOR_ITER|STORE_FAST" : "for {} in {}:",
    "LOAD_GLOBAL|GET_ITER|FOR_ITER|STORE_FAST" : "for {} in {}:",
    "POP_TOP" : "\n"
}

FINAL_PY_FILE = ".\\finalScript.py"


def normalise_opcode(opcode, version_str=None):
    """Normalise a bytecode opcode name to its canonical/legacy form.

    Returns the normalised name, or None if the opcode should be skipped
    (e.g. CACHE, RESUME).
    """
    if opcode in OPCODE_ALIASES:
        return OPCODE_ALIASES[opcode]
    return opcode


def filter_cache_lines(lines, version_str=None):
    """Remove CACHE instruction lines that appear in Python 3.11+ bytecode output.

    Also removes RESUME and other no-op instructions that clutter the bytecode
    listing but carry no semantic information for template building.
    """
    skip_opcodes = {"CACHE", "RESUME", "PRECALL", "PUSH_NULL",
                    "COPY_FREE_VARS", "MAKE_CELL"}
    filtered = []
    for line in lines:
        match = re.findall(INSTRUCTION_REGEX, line)
        if match and match[0] in skip_opcodes:
            continue
        filtered.append(line)
    return filtered


# ─────────────────────────────────────────────────────────────
# Get bytecodes from pyc file
# ─────────────────────────────────────────────────────────────
def manuallyDecompile(pycFile, fileVersion):
    """Disassemble a .pyc file and print the bytecode to stdout.

    Pipe the result to a file for use with --bcfile --template.
    """
    with open(pycFile, 'rb') as f:
        headerSize = get_header_size(fileVersion)
        pycHeader = f.read(headerSize)
        codeObj = marshal.load(f)

    # For 3.11+ dis.dis() shows CACHE entries; we let them through here
    # since the user may want the raw bytecode. Filtering happens in
    # buildTemplate().
    dis.dis(codeObj)


# ─────────────────────────────────────────────────────────────
# Build template from bytecode file
# ─────────────────────────────────────────────────────────────
def buildTemplate(bytecodeFile, version_str=None):
    """Parse a bytecode listing file and produce a Python source template."""
    with open(bytecodeFile, 'r') as f:
        content = f.read().splitlines()
    with open(FINAL_PY_FILE, 'w') as f:
        f.write(BANNER)

    # Pre-filter lines to remove CACHE / RESUME noise (3.11+)
    if version_str:
        ver = Version(version_str)
        if ver >= Version("3.11"):
            content = filter_cache_lines(content, version_str)

    chunk = {}
    line_numbers = []
    for line in content:
        instruction, argument = "", ""
        if re.findall(PRIVATE_FUNCTION_REGEX, line):
            return

        # End of chunk - start parsing
        if line == '':
            chunk["LINE_NUMBERS"] = line_numbers
            parseChunks(chunk, version_str)
            chunk = {}
            line_numbers = []
            continue

        try:
            raw_instr = re.findall(INSTRUCTION_REGEX, line)
            if raw_instr and raw_instr[0] == "LOAD_CONST":
                if re.findall(RETURN_REGEX, line):
                    chunk["RETURN_VALUE"] = re.findall(RETURN_REGEX, line)[0]
                    continue
        except Exception:
            pass

        # Handle RETURN_CONST (3.12+): treat as LOAD_CONST + RETURN_VALUE
        try:
            raw_instr = re.findall(INSTRUCTION_REGEX, line)
            if raw_instr and raw_instr[0] == "RETURN_CONST":
                arg = ""
                if re.findall(ARGUMENT_REGEX, line):
                    arg = re.findall(ARGUMENT_REGEX, line)[0]
                chunk["LOAD_CONST"] = arg
                chunk["RETURN_VALUE"] = True
                continue
        except Exception:
            pass

        if re.findall(INSTRUCTION_REGEX, line):
            instruction = re.findall(INSTRUCTION_REGEX, line)[0]
            # Normalise newer opcodes to legacy equivalents
            normalised = normalise_opcode(instruction, version_str)
            if normalised is None:
                continue  # Skip no-op opcodes
            instruction = normalised

        if re.findall(ARGUMENT_REGEX, line):
            argument = re.findall(ARGUMENT_REGEX, line)[0]

        if re.findall(FUNCTION_OFFSET_REGEX, line):
            chunk["FUNC_OFFSET"] = re.findall(FUNCTION_OFFSET_REGEX, line)[0].split(',')[0]

        if re.findall(LINE_NUMBER_REGEX, line):
            line_numbers.append(re.findall(LINE_NUMBER_REGEX, line)[0])

        if re.findall(JUMP_TO_REGEX, line):
            chunk["JUMP_TO"] = re.findall(JUMP_TO_REGEX, line)[0]

        # In 3.12+, LOAD_ATTR may act as the old LOAD_METHOD when the low
        # bit of its oparg is set.  The dis output shows this as an extra
        # annotation; we store it so parseChunks can use either key.
        if instruction == "LOAD_ATTR" and "LOAD_METHOD" not in chunk:
            # If the original raw opcode was LOAD_ATTR with method flag,
            # also populate LOAD_METHOD for backward compat in parseChunks.
            chunk["LOAD_METHOD"] = argument

        chunk[instruction] = argument

    # Flush the last chunk if the file doesn't end with a blank line
    if chunk:
        chunk["LINE_NUMBERS"] = line_numbers
        parseChunks(chunk, version_str)


def parseChunks(chunk, version_str=None):
    """Convert a bytecode chunk dict into a line of Python source."""
    instructions = chunk.keys()
    pyLine = ""
    newLine = True

    # In 3.12+, the unified CALL opcode replaces CALL_FUNCTION and CALL_METHOD.
    # We treat CALL the same as CALL_FUNCTION / CALL_METHOD for template purposes.
    has_call = ("CALL_METHOD" in instructions or "CALL_FUNCTION" in instructions
                or "CALL" in instructions)
    has_call_method = "CALL_METHOD" in instructions or "CALL" in instructions

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
    elif has_call_method:
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
        # Handle: expression-level calls without STORE_NAME (3.12+)
        elif "LOAD_NAME" in instructions:
            if "LOAD_METHOD" in instructions:
                pyLine += "{}.{}()".format(chunk["LOAD_NAME"],
                                            chunk["LOAD_METHOD"])
            else:
                pyLine += "{}()".format(chunk["LOAD_NAME"])
        elif "LOAD_FAST" in instructions:
            if "LOAD_METHOD" in instructions:
                pyLine += "{}.{}()".format(chunk["LOAD_FAST"],
                                            chunk["LOAD_METHOD"])
        elif "LOAD_GLOBAL" in instructions:
            if "LOAD_METHOD" in instructions:
                pyLine += "{}.{}()".format(chunk["LOAD_GLOBAL"],
                                            chunk["LOAD_METHOD"])
            else:
                pyLine += "{}()".format(chunk["LOAD_GLOBAL"])

    elif "CALL_FUNCTION" in instructions or "CALL" in instructions:
        newLine = True
        if "LOAD_NAME" in instructions:
            pyLine += "{}()".format(chunk["LOAD_NAME"])
        elif "LOAD_GLOBAL" in instructions:
            pyLine += "{}()".format(chunk["LOAD_GLOBAL"])

    # If statement
    elif "COMPARE_OP" in instructions:
        newLine = True
        if "POP_JUMP_IF_FALSE" in instructions: # Jump to line number if statement is false
            jumpTo = chunk["JUMP_TO"]

        if "LOAD_CONST" in instructions:
            if "LOAD_NAME" in instructions:
                pyLine += "\nif {} == {}:".format(chunk["LOAD_NAME"], chunk["LOAD_CONST"])
            elif "LOAD_FAST" in instructions:
                pyLine += "\nif {} == {}:".format(chunk["LOAD_FAST"], chunk["LOAD_CONST"])

    # 3.12+ None-comparison jumps
    elif "POP_JUMP_IF_NONE" in instructions:
        newLine = True
        if "LOAD_NAME" in instructions:
            pyLine += "\nif {} is None:".format(chunk["LOAD_NAME"])
        elif "LOAD_FAST" in instructions:
            pyLine += "\nif {} is None:".format(chunk["LOAD_FAST"])
    elif "POP_JUMP_IF_NOT_NONE" in instructions:
        newLine = True
        if "LOAD_NAME" in instructions:
            pyLine += "\nif {} is not None:".format(chunk["LOAD_NAME"])
        elif "LOAD_FAST" in instructions:
            pyLine += "\nif {} is not None:".format(chunk["LOAD_FAST"])

    # Create Function
    elif "MAKE_FUNCTION" in instructions:
        newLine = False
        buildFuncOffset = chunk.get("FUNC_OFFSET", "")
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

    # 3.12+: STORE_FAST variable assignment
    elif "STORE_FAST" in instructions:
        newLine = True
        if "LOAD_CONST" in instructions:
            pyLine += "{} = {}".format(chunk["STORE_FAST"], chunk["LOAD_CONST"])
        elif "LOAD_FAST" in instructions:
            pyLine += "{} = {}".format(chunk["STORE_FAST"], chunk["LOAD_FAST"])
        elif "LOAD_GLOBAL" in instructions:
            pyLine += "{} = {}".format(chunk["STORE_FAST"], chunk["LOAD_GLOBAL"])

    with open(FINAL_PY_FILE, 'a') as f:
        f.write(pyLine)
        if newLine:
            f.write("\n")


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print(BANNER)

    parser = argparse.ArgumentParser(description='pycDcode - PYC Bytecode Analysis')
    parser.add_argument('--pyc', help='PYC file')
    parser.add_argument('--bcfile', help='ByteCode file')
    parser.add_argument('--version', help='Python script version (2.7, 3.6, 3.9, 3.11, 3.12, 3.13...)')
    parser.add_argument('--bytecode', help='Return bytecodes', action='store_true')
    parser.add_argument('--template', help='Build script template', action='store_true')
    args = parser.parse_args()

    if args.pyc:
        if args.bytecode:
            version = args.version if args.version else "2.7"
            manuallyDecompile(args.pyc, version)
    if args.bcfile:
        if args.template:
            version = args.version if args.version else None
            buildTemplate(args.bcfile, version)
