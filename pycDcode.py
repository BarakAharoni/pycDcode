# -*- coding: utf-8 -*-
"""
 Python PYC File Analysis

 Use the script as follows:
    1) Get Bytecodes from pyc:  python pycDcode.py --pyc {pyc-file} --bytecode [--version {py-version}] > {output-file}
    2) Build Script Template:   python pycDcode.py --bcfile {bytecode-file} --template [--version {py-version}]
    3) Auto-detect version:     python pycDcode.py --pyc {pyc-file} --info

 If --version is omitted, the version is auto-detected from the PYC magic number.

 Bytecode parsing documentation: https://betterprogramming.pub/analysis-of-compiled-python-files-629d8adbe787

 Copyright (c) 2022 Barak Aharoni.  All Rights Reserved.
"""

import sys
import os
import dis
import marshal
import struct
import logging
import argparse
import re

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
# Logging
# ─────────────────────────────────────────────────────────────
log = logging.getLogger("pycDcode")

# ─────────────────────────────────────────────────────────────
# Version Utilities
# ─────────────────────────────────────────────────────────────

def _parse_version(version_str):
    """Parse a version string like '3.12' into a tuple (3, 12).

    Accepts strings like '3.12', '3.12.1', '2.7'.
    Returns (major, minor) only — patch is ignored for our purposes.
    """
    parts = version_str.strip().split('.')
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        return (major, minor)
    except (ValueError, IndexError):
        raise ValueError(f"Cannot parse version string: {version_str!r}")


def _ver_gte(version_str, target):
    """Check if version_str >= target (both as 'major.minor' strings or tuples)."""
    if isinstance(version_str, str):
        version_str = _parse_version(version_str)
    if isinstance(target, str):
        target = _parse_version(target)
    return version_str >= target


# ─────────────────────────────────────────────────────────────
# PYC Magic Number → Python Version Auto-Detection
# ─────────────────────────────────────────────────────────────
# The magic number is stored as a little-endian 16-bit integer in the first
# two bytes of the .pyc file (bytes 3-4 are always \r\n = 0x0d0a).
#
# Starting with Python 3.11, the scheme is:  base = 2900 + 50*n  for 3.n
# Within each minor version the number increments by 1 for format changes.
#
# We use ranges: (low_magic_inclusive, high_magic_inclusive) → "major.minor"

MAGIC_TO_VERSION = {
    # Python 2.x (selected stable releases)
    (62171, 62211): "2.7",
    # Python 3.0 – 3.10
    (3000, 3131):  "3.0",
    (3141, 3151):  "3.1",
    (3160, 3180):  "3.2",
    (3190, 3230):  "3.3",
    (3250, 3310):  "3.4",
    (3320, 3351):  "3.5",
    (3360, 3379):  "3.6",
    (3390, 3399):  "3.7",
    (3400, 3419):  "3.8",
    (3420, 3425):  "3.9",
    (3430, 3439):  "3.10",
    # Python 3.11+: base = 2900 + 50*n
    # 3.11: base 3450, range 3450-3499
    (3450, 3499):  "3.11",
    # 3.12: base 3500, range 3500-3549
    (3500, 3549):  "3.12",
    # 3.13: base 3550, range 3550-3599
    (3550, 3599):  "3.13",
    # 3.14: base 3600, range 3600-3649 (future-proofing)
    (3600, 3649):  "3.14",
}


def detect_version_from_magic(magic_bytes):
    """Given the first 4 bytes of a .pyc file, return the Python version string.

    Returns None if the magic number is not recognized.
    """
    if len(magic_bytes) < 4:
        return None
    # Magic is a 16-bit little-endian integer in bytes 0-1
    magic_int = struct.unpack('<H', magic_bytes[:2])[0]
    log.debug("PYC magic number: %d (0x%04x)", magic_int, magic_int)

    for (lo, hi), version in MAGIC_TO_VERSION.items():
        if lo <= magic_int <= hi:
            return version
    return None


def read_pyc_header(pyc_path):
    """Read a .pyc file and return (magic_bytes_4, detected_version_or_None)."""
    with open(pyc_path, 'rb') as f:
        magic = f.read(4)
    version = detect_version_from_magic(magic)
    return magic, version


# ─────────────────────────────────────────────────────────────
# PYC Header Sizes
# ─────────────────────────────────────────────────────────────
# Python < 3.0  :  8 bytes  (magic + timestamp)
# Python 3.0-3.2:  8 bytes  (magic + timestamp)
# Python 3.3-3.6: 12 bytes  (magic + timestamp + source size)
# Python 3.7+   : 16 bytes  (magic + flags + timestamp/hash + source size)

def get_header_size(version_str):
    """Return the correct PYC header size for a given Python version string."""
    ver = _parse_version(version_str)
    if ver < (3, 0):
        return 8
    elif ver < (3, 3):
        return 8
    elif ver < (3, 7):
        return 12
    else:
        return 16


# ─────────────────────────────────────────────────────────────
# Precompiled Regex Patterns
# ─────────────────────────────────────────────────────────────
RE_INSTRUCTION    = re.compile(r"\s\d+\s([A-Z_]+)")
RE_ARGUMENT       = re.compile(r"\s\d+\s\((.*)\)")
RE_FUNC_OFFSET    = re.compile(r"at\s(.*),\s")
RE_JUMP_TO        = re.compile(r"\d+\s\w+_JUMP_\w+\s+(\d+)")
RE_LINE_NUMBER    = re.compile(r"\s+(\d+)\s\w+")
RE_RETURN         = re.compile(r">>")
RE_PRIVATE_FUNC   = re.compile(r"Disassembly of <code object (\w+)")
RE_RETURN_VALUE   = re.compile(r"RETURN_VALUE")
# Detect comparison operators from COMPARE_OP argument, e.g. "(==)" or "(!=)"
RE_COMPARE_OP_ARG = re.compile(r"\((==|!=|<|<=|>|>=|in|not in|is|is not)\)")

# ─────────────────────────────────────────────────────────────
# Opcode Normalisation (3.11 / 3.12 / 3.13)
# ─────────────────────────────────────────────────────────────
# Returns the canonical opcode name, or None to skip.

# Opcodes that should be silently dropped (no semantic meaning for templates)
_SKIP_OPCODES = frozenset({
    "CACHE", "RESUME", "PRECALL", "PUSH_NULL",
    "COPY_FREE_VARS", "MAKE_CELL", "PUSH_EXC_INFO",
    "CHECK_EG_MATCH", "PREP_RERAISE_STAR",
    "JUMP_BACKWARD_NO_INTERRUPT",
    "NOP",
    # 3.14 (future-proofing)
    "NOT_TAKEN", "LOAD_CONST_IMMORTAL", "LOAD_CONST_MORTAL",
    "LOAD_SMALL_INT", "POP_ITER", "INSTRUMENTED_POP_ITER",
})

# Opcodes that map to a different canonical name
_OPCODE_ALIASES = {
    # 3.12+: unified CALL replaces CALL_FUNCTION and CALL_METHOD
    "CALL":             "CALL_FUNCTION",
    "CALL_KW":          "CALL_FUNCTION_KW",
    # 3.12: RETURN_CONST = LOAD_CONST + RETURN_VALUE (handled specially)
    "RETURN_CONST":     "RETURN_CONST",
    # 3.12+: new jump variants
    "POP_JUMP_IF_NONE":     "POP_JUMP_IF_NONE",
    "POP_JUMP_IF_NOT_NONE": "POP_JUMP_IF_NOT_NONE",
    # 3.12: LOAD_SUPER_ATTR
    "LOAD_SUPER_ATTR":  "LOAD_ATTR",
    # 3.12+: LOAD_FAST variants
    "LOAD_FAST_AND_CLEAR": "LOAD_FAST",
    "LOAD_FAST_CHECK":     "LOAD_FAST",
    # 3.11: BINARY_OP replaced all BINARY_* and INPLACE_*
    "BINARY_OP":        "BINARY_OP",
}

# 3.13 specialization opcodes → generic form
_SPECIALIZATION_PREFIX_MAP = {
    "BINARY_OP_":       "BINARY_OP",
    "LOAD_ATTR_":       "LOAD_ATTR",
    "LOAD_GLOBAL_":     "LOAD_GLOBAL",
    "STORE_ATTR_":      "STORE_ATTR",
    "LOAD_SUPER_ATTR_": "LOAD_ATTR",
    "CALL_":            "CALL_FUNCTION",
    "COMPARE_OP_":      "COMPARE_OP",
    "FOR_ITER_":        "FOR_ITER",
    "STORE_SUBSCR_":    "STORE_SUBSCR",
    "UNPACK_SEQUENCE_": "UNPACK_SEQUENCE",
    "SEND_":            "SEND",
    "TO_BOOL_":         "TO_BOOL",
}


def normalise_opcode(opcode):
    """Normalise an opcode name to its canonical form.

    Returns the canonical name, or None if the opcode should be skipped.
    """
    if opcode in _SKIP_OPCODES:
        return None

    if opcode in _OPCODE_ALIASES:
        return _OPCODE_ALIASES[opcode]

    # Check specialization prefixes (3.13+)
    for prefix, generic in _SPECIALIZATION_PREFIX_MAP.items():
        if opcode.startswith(prefix):
            return generic

    return opcode


# ─────────────────────────────────────────────────────────────
# INSTRUCTION_DICT (kept for reference / potential future use)
# ─────────────────────────────────────────────────────────────
INSTRUCTION_DICT = {
    "LOAD_GLOBAL|LOAD_METHOD": "{}.{}(",
    "IMPORT_STAR": [r"IMPORT_NAME\s+\d+\s+\((.*?)\)", "from {} import *"],
    "IMPORT_NAME|IMPORT_FROM": [
        r"IMPORT_FROM\s+\d+\s+\((.*?)\).*IMPORT_NAME\s+\d+\s+\((.*?)\)",
        "from {} import {}"
    ],
    "IMPORT_NAME": "import {}",
    "LOAD_FAST|STORE_FAST": "{} = {}",
    "LOAD_GLOBAL|STORE_GLOBAL": "global {}\n{} = {}",
    "LOAD_NAME|STORE_NAME": "{} = {}",
    "CALL_METHOD": ")",
    "CALL_FUNCTION": "",
    "CALL": "",
    "POP_JUMP_IF_FALSE": "if {} ",
    "POP_JUMP_IF_TRUE": "if {} ",
    "POP_JUMP_IF_NONE": "if {} is None ",
    "POP_JUMP_IF_NOT_NONE": "if {} is not None ",
    "COMPARE_OP": "{}",
    "CONTAINS_OP": "{} in ",
    "IS_OP": "{} is ",
    "LOAD_FAST|GET_ITER|FOR_ITER|STORE_FAST": "for {} in {}:",
    "LOAD_GLOBAL|GET_ITER|FOR_ITER|STORE_FAST": "for {} in {}:",
    "POP_TOP": "\n",
}


# ─────────────────────────────────────────────────────────────
# Get bytecodes from pyc file
# ─────────────────────────────────────────────────────────────
def manuallyDecompile(pycFile, fileVersion):
    """Disassemble a .pyc file and print the bytecode to stdout."""
    with open(pycFile, 'rb') as f:
        headerSize = get_header_size(fileVersion)
        pycHeader = f.read(headerSize)
        try:
            codeObj = marshal.load(f)
        except Exception as e:
            log.error("Failed to unmarshal code object: %s", e)
            log.error("This may happen if the .pyc was compiled with a different "
                      "Python version than the one running this script.")
            sys.exit(1)

    log.info("Disassembling %s (Python %s, header %d bytes)", pycFile, fileVersion, headerSize)
    dis.dis(codeObj)


# ─────────────────────────────────────────────────────────────
# Build template from bytecode file
# ─────────────────────────────────────────────────────────────
def _filter_lines(lines, version_str):
    """Remove CACHE / RESUME / noise lines from 3.11+ bytecode output."""
    if version_str and _ver_gte(version_str, "3.11"):
        filtered = []
        for line in lines:
            m = RE_INSTRUCTION.search(line)
            if m and m.group(1) in _SKIP_OPCODES:
                continue
            filtered.append(line)
        return filtered
    return lines


def _extract_compare_op(line):
    """Try to extract the comparison operator from a COMPARE_OP line.

    Returns the operator string (e.g. '==', '!=', 'is') or '==' as default.
    """
    m = RE_COMPARE_OP_ARG.search(line)
    return m.group(1) if m else "=="


def buildTemplate(bytecodeFile, version_str=None):
    """Parse a bytecode listing file and produce a Python source template."""
    if not os.path.isfile(bytecodeFile):
        log.error("Bytecode file not found: %s", bytecodeFile)
        sys.exit(1)

    with open(bytecodeFile, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read().splitlines()

    output_path = os.path.join(os.getcwd(), "finalScript.py")
    with open(output_path, 'w') as f:
        f.write(BANNER)

    log.info("Building template from %s -> %s", bytecodeFile, output_path)

    # Pre-filter noise lines for 3.11+
    content = _filter_lines(content, version_str)

    chunk = {}
    line_numbers = []
    raw_lines = {}  # instruction -> original line text, for operator extraction

    for line in content:
        instruction, argument = "", ""
        if RE_PRIVATE_FUNC.search(line):
            # TODO: in a future version, recurse into nested code objects
            # instead of stopping at the first private function.
            log.info("Reached nested code object, stopping template build.")
            break

        # End of chunk -> parse it
        if line == '':
            chunk["LINE_NUMBERS"] = line_numbers
            chunk["_RAW_LINES"] = raw_lines
            parseChunks(chunk, version_str, output_path)
            chunk = {}
            line_numbers = []
            raw_lines = {}
            continue

        # Extract instruction
        m_instr = RE_INSTRUCTION.search(line)
        if m_instr:
            raw_opcode = m_instr.group(1)

            # Handle RETURN_CONST (3.12+): split into LOAD_CONST + RETURN_VALUE
            if raw_opcode == "RETURN_CONST":
                m_arg = RE_ARGUMENT.search(line)
                arg = m_arg.group(1) if m_arg else ""
                chunk["LOAD_CONST"] = arg
                chunk["RETURN_VALUE"] = True
                continue

            # Handle LOAD_CONST >> (return target marker)
            if raw_opcode == "LOAD_CONST" and RE_RETURN.search(line):
                chunk["RETURN_VALUE"] = True
                continue

            # Normalise
            instruction = normalise_opcode(raw_opcode)
            if instruction is None:
                continue  # skip no-op opcodes
        else:
            continue  # non-instruction line (e.g. header)

        # Extract argument
        m_arg = RE_ARGUMENT.search(line)
        if m_arg:
            argument = m_arg.group(1)

        # Function offset
        m_offset = RE_FUNC_OFFSET.search(line)
        if m_offset:
            chunk["FUNC_OFFSET"] = m_offset.group(1).split(',')[0]

        # Line numbers
        m_lineno = RE_LINE_NUMBER.match(line)
        if m_lineno:
            line_numbers.append(m_lineno.group(1))

        # Jump target
        m_jump = RE_JUMP_TO.search(line)
        if m_jump:
            chunk["JUMP_TO"] = m_jump.group(1)

        # In 3.12+, LOAD_ATTR may act as old LOAD_METHOD.
        # Also store into LOAD_METHOD for backward compat in parseChunks.
        if instruction == "LOAD_ATTR" and "LOAD_METHOD" not in chunk:
            chunk["LOAD_METHOD"] = argument

        chunk[instruction] = argument
        raw_lines[instruction] = line

    # Flush last chunk if file doesn't end with blank line
    if chunk:
        chunk["LINE_NUMBERS"] = line_numbers
        chunk["_RAW_LINES"] = raw_lines
        parseChunks(chunk, version_str, output_path)

    log.info("Template written to %s", output_path)


def parseChunks(chunk, version_str=None, output_path=None):
    """Convert a bytecode chunk dict into a line of Python source."""
    if output_path is None:
        output_path = os.path.join(os.getcwd(), "finalScript.py")

    instructions = set(chunk.keys())
    raw_lines = chunk.get("_RAW_LINES", {})
    pyLine = ""
    newLine = True

    # Unified call detection: CALL_METHOD | CALL_FUNCTION | CALL (3.12+)
    has_call_method = bool(instructions & {"CALL_METHOD", "CALL"})
    has_call_func   = bool(instructions & {"CALL_FUNCTION", "CALL"})

    # ── Imports ──────────────────────────────────────────────
    if "IMPORT_STAR" in instructions:
        pyLine += "from {} import *".format(chunk.get("IMPORT_NAME", "?"))
        newLine = True
    elif "IMPORT_FROM" in instructions:
        pyLine += "from {} import {}".format(
            chunk.get("IMPORT_NAME", "?"), chunk.get("IMPORT_FROM", "?"))
    elif "IMPORT_NAME" in instructions:
        pyLine += "import {}".format(chunk.get("IMPORT_NAME", "?"))
        newLine = True

    # ── Call function / method ───────────────────────────────
    elif has_call_method:
        newLine = True
        if "STORE_NAME" in instructions:
            if "LOAD_NAME" in instructions:
                if "LOAD_METHOD" in instructions:
                    pyLine += "{} = {}.{}()".format(
                        chunk["STORE_NAME"], chunk["LOAD_NAME"], chunk["LOAD_METHOD"])
                else:
                    pyLine += "{} = {}()".format(chunk["STORE_NAME"], chunk["LOAD_NAME"])
            elif "LOAD_GLOBAL" in instructions:
                if "LOAD_METHOD" in instructions:
                    pyLine += "{} = {}.{}()".format(
                        chunk["STORE_NAME"], chunk["LOAD_GLOBAL"], chunk["LOAD_METHOD"])
                else:
                    pyLine += "{} = {}()".format(chunk["STORE_NAME"], chunk["LOAD_GLOBAL"])
        elif "LOAD_NAME" in instructions:
            if "LOAD_METHOD" in instructions:
                pyLine += "{}.{}()".format(chunk["LOAD_NAME"], chunk["LOAD_METHOD"])
            else:
                pyLine += "{}()".format(chunk["LOAD_NAME"])
        elif "LOAD_FAST" in instructions:
            if "LOAD_METHOD" in instructions:
                pyLine += "{}.{}()".format(chunk["LOAD_FAST"], chunk["LOAD_METHOD"])
            else:
                pyLine += "{}()".format(chunk["LOAD_FAST"])
        elif "LOAD_GLOBAL" in instructions:
            if "LOAD_METHOD" in instructions:
                pyLine += "{}.{}()".format(chunk["LOAD_GLOBAL"], chunk["LOAD_METHOD"])
            else:
                pyLine += "{}()".format(chunk["LOAD_GLOBAL"])

    elif has_call_func:
        newLine = True
        if "LOAD_NAME" in instructions:
            pyLine += "{}()".format(chunk["LOAD_NAME"])
        elif "LOAD_GLOBAL" in instructions:
            pyLine += "{}()".format(chunk["LOAD_GLOBAL"])

    # ── Comparison / If ──────────────────────────────────────
    elif "COMPARE_OP" in instructions:
        newLine = True
        # Extract actual operator from the raw line
        op = "=="
        if "COMPARE_OP" in raw_lines:
            op = _extract_compare_op(raw_lines["COMPARE_OP"])

        if "LOAD_CONST" in instructions:
            lhs = chunk.get("LOAD_NAME") or chunk.get("LOAD_FAST") or chunk.get("LOAD_GLOBAL") or "?"
            pyLine += "\nif {} {} {}:".format(lhs, op, chunk["LOAD_CONST"])
        elif "LOAD_FAST" in instructions and "LOAD_NAME" in instructions:
            pyLine += "\nif {} {} {}:".format(chunk["LOAD_NAME"], op, chunk["LOAD_FAST"])

    # ── IS_OP (3.9+): "is" / "is not" ───────────────────────
    elif "IS_OP" in instructions:
        newLine = True
        is_not = chunk.get("IS_OP", "0") == "1"
        op = "is not" if is_not else "is"
        lhs = chunk.get("LOAD_NAME") or chunk.get("LOAD_FAST") or "?"
        rhs = chunk.get("LOAD_CONST") or chunk.get("LOAD_GLOBAL") or "?"
        pyLine += "\nif {} {} {}:".format(lhs, op, rhs)

    # ── CONTAINS_OP (3.9+): "in" / "not in" ─────────────────
    elif "CONTAINS_OP" in instructions:
        newLine = True
        not_in = chunk.get("CONTAINS_OP", "0") == "1"
        op = "not in" if not_in else "in"
        lhs = chunk.get("LOAD_NAME") or chunk.get("LOAD_FAST") or "?"
        rhs = chunk.get("LOAD_CONST") or chunk.get("LOAD_GLOBAL") or "?"
        pyLine += "\nif {} {} {}:".format(lhs, op, rhs)

    # ── POP_JUMP_IF_NONE / POP_JUMP_IF_NOT_NONE (3.12+) ─────
    elif "POP_JUMP_IF_NONE" in instructions:
        newLine = True
        lhs = chunk.get("LOAD_NAME") or chunk.get("LOAD_FAST") or chunk.get("LOAD_GLOBAL") or "?"
        pyLine += "\nif {} is None:".format(lhs)
    elif "POP_JUMP_IF_NOT_NONE" in instructions:
        newLine = True
        lhs = chunk.get("LOAD_NAME") or chunk.get("LOAD_FAST") or chunk.get("LOAD_GLOBAL") or "?"
        pyLine += "\nif {} is not None:".format(lhs)

    # ── Create Function ──────────────────────────────────────
    elif "MAKE_FUNCTION" in instructions:
        newLine = False
        if "STORE_NAME" in instructions:
            pyLine = "\ndef {}():".format(chunk["STORE_NAME"])

    # ── BINARY_OP (3.11+) ───────────────────────────────────
    elif "BINARY_OP" in instructions:
        newLine = True
        # BINARY_OP has an argument like "13 (+)" or just "+"
        op_str = chunk.get("BINARY_OP", "+")
        m = re.search(r'\((.+?)\)', op_str)
        if m:
            op_str = m.group(1)
        if "STORE_FAST" in instructions:
            lhs = chunk.get("LOAD_FAST") or chunk.get("LOAD_NAME") or "?"
            rhs = chunk.get("LOAD_CONST") or "?"
            pyLine += "{} = {} {} {}".format(chunk["STORE_FAST"], lhs, op_str, rhs)
        elif "STORE_NAME" in instructions:
            lhs = chunk.get("LOAD_NAME") or chunk.get("LOAD_FAST") or "?"
            rhs = chunk.get("LOAD_CONST") or "?"
            pyLine += "{} = {} {} {}".format(chunk["STORE_NAME"], lhs, op_str, rhs)

    # ── Variables ────────────────────────────────────────────
    elif "STORE_NAME" in instructions:
        newLine = True
        if "LOAD_CONST" in instructions:
            pyLine += "{} = {}".format(chunk["STORE_NAME"], chunk["LOAD_CONST"])
        elif "LOAD_NAME" in instructions:
            pyLine += "{} = {}".format(chunk["STORE_NAME"], chunk["LOAD_NAME"])
        elif "LOAD_GLOBAL" in instructions:
            pyLine += "{} = {}".format(chunk["STORE_NAME"], chunk["LOAD_GLOBAL"])
    elif "STORE_GLOBAL" in instructions:
        newLine = True
        if "LOAD_CONST" in instructions:
            pyLine += "{} = {}".format(chunk["STORE_GLOBAL"], chunk["LOAD_CONST"])
        elif "LOAD_NAME" in instructions:
            pyLine += "{} = {}".format(chunk["STORE_GLOBAL"], chunk["LOAD_NAME"])
    elif "STORE_FAST" in instructions:
        newLine = True
        if "LOAD_CONST" in instructions:
            pyLine += "{} = {}".format(chunk["STORE_FAST"], chunk["LOAD_CONST"])
        elif "LOAD_FAST" in instructions:
            pyLine += "{} = {}".format(chunk["STORE_FAST"], chunk["LOAD_FAST"])
        elif "LOAD_GLOBAL" in instructions:
            pyLine += "{} = {}".format(chunk["STORE_FAST"], chunk["LOAD_GLOBAL"])
        elif "LOAD_NAME" in instructions:
            pyLine += "{} = {}".format(chunk["STORE_FAST"], chunk["LOAD_NAME"])

    with open(output_path, 'a') as f:
        f.write(pyLine)
        if newLine:
            f.write("\n")


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print(BANNER)

    parser = argparse.ArgumentParser(
        description='pycDcode — PYC Bytecode Analysis (supports Python 2.7 – 3.13)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s --pyc app.pyc --info
  %(prog)s --pyc app.pyc --bytecode > bytecodes.txt
  %(prog)s --pyc app.pyc --bytecode --version 3.12 > bytecodes.txt
  %(prog)s --bcfile bytecodes.txt --template --version 3.12
""")
    parser.add_argument('--pyc', help='PYC file path')
    parser.add_argument('--bcfile', help='Bytecode file path (output of --bytecode)')
    parser.add_argument('--version',
                        help='Python version (e.g. 2.7, 3.11, 3.12, 3.13). '
                             'Auto-detected from PYC magic number if omitted.')
    parser.add_argument('--bytecode', help='Disassemble PYC and print bytecodes',
                        action='store_true')
    parser.add_argument('--template', help='Build script template from bytecode file',
                        action='store_true')
    parser.add_argument('--info', help='Show detected Python version and header info',
                        action='store_true')
    parser.add_argument('--verbose', '-v', help='Enable verbose logging',
                        action='store_true')
    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='[%(levelname)s] %(message)s',
        stream=sys.stderr  # keep stdout clean for --bytecode piping
    )

    # ── --info: show PYC metadata ────────────────────────────
    if args.pyc and args.info:
        magic, detected = read_pyc_header(args.pyc)
        magic_int = struct.unpack('<H', magic[:2])[0]
        print(f"File:           {args.pyc}")
        print(f"Magic number:   {magic_int} (0x{magic_int:04x})")
        print(f"Magic bytes:    {magic.hex()}")
        if detected:
            print(f"Python version: {detected} (auto-detected)")
            print(f"Header size:    {get_header_size(detected)} bytes")
        else:
            print(f"Python version: UNKNOWN (magic {magic_int} not in table)")
        sys.exit(0)

    # ── Resolve version ──────────────────────────────────────
    version = args.version
    if not version and args.pyc:
        _, detected = read_pyc_header(args.pyc)
        if detected:
            version = detected
            log.info("Auto-detected Python %s from PYC magic number", version)
        else:
            log.warning("Could not auto-detect Python version; defaulting to 2.7")
            version = "2.7"
    elif not version:
        version = "2.7"

    # ── --bytecode: disassemble ──────────────────────────────
    if args.pyc and args.bytecode:
        manuallyDecompile(args.pyc, version)

    # ── --template: build source template ────────────────────
    if args.bcfile and args.template:
        buildTemplate(args.bcfile, version)
