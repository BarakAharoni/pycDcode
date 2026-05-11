# -*- coding: utf-8 -*-
"""
pycDcode — PYC to readable Python source decompiler

Uses dis.get_instructions() with stack simulation and pattern-matching
to reconstruct Python source from compiled .pyc files.

Must be run with the SAME Python version that compiled the .pyc
(marshal is version-specific).

Usage:
    python pycDcode.py <file.pyc>                    # decompile to stdout
    python pycDcode.py <file.pyc> -o output.py       # decompile to file
    python pycDcode.py <file.pyc> --info              # show header info
    python pycDcode.py <file.pyc> --bytecode          # raw dis output

 Bytecode parsing documentation: https://betterprogramming.pub/analysis-of-compiled-python-files-629d8adbe787

Copyright (c) 2022 Barak Aharoni.  All Rights Reserved.
"""

import sys
import os
import dis
import marshal
import struct
import types
import argparse
import logging
import textwrap
import io

__version__ = "3.0.0"
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

PY_VERSION = sys.version_info[:2]

# ═════════════════════════════════════════════════════════════
# PYC HEADER / VERSION DETECTION
# ═════════════════════════════════════════════════════════════

MAGIC_RANGES = {
    (62171, 62211): (2, 7),
    (3000, 3131): (3, 0), (3141, 3151): (3, 1), (3160, 3180): (3, 2),
    (3190, 3230): (3, 3), (3250, 3310): (3, 4), (3320, 3351): (3, 5),
    (3360, 3379): (3, 6), (3390, 3399): (3, 7), (3400, 3419): (3, 8),
    (3420, 3425): (3, 9), (3430, 3439): (3, 10),
    (3450, 3499): (3, 11), (3500, 3549): (3, 12), (3550, 3599): (3, 13),
    (3600, 3649): (3, 14),
}

def detect_version(path):
    with open(path, "rb") as f:
        data = f.read(4)
    if len(data) < 2:
        return None
    magic = struct.unpack("<H", data[:2])[0]
    for (lo, hi), ver in MAGIC_RANGES.items():
        if lo <= magic <= hi:
            return ver
    return None

def header_size(ver):
    if ver < (3, 0): return 8
    if ver < (3, 3): return 8
    if ver < (3, 7): return 12
    return 16

def load_code_object(path):
    ver = detect_version(path)
    hdr = 16
    if ver is not None:
        hdr = header_size(ver)
        if ver != PY_VERSION:
            log.warning(
                "PYC was compiled with Python %d.%d but you are running %d.%d — "
                "marshal.load may fail.", *ver, *PY_VERSION)
    with open(path, "rb") as f:
        f.read(hdr)
        return marshal.load(f)


# ═════════════════════════════════════════════════════════════
# UTILITIES
# ═════════════════════════════════════════════════════════════

_BINOP_SYMBOL = {
    0: "+", 1: "&", 2: "//", 3: "<<", 4: "@", 5: "*", 6: "%", 7: "|",
    8: "**", 9: ">>", 10: "-", 11: "/", 12: "^",
    13: "+=", 14: "&=", 15: "//=", 16: "<<=", 17: "@=",
    18: "*=", 19: "%=", 20: "|=", 21: "**=", 22: ">>=",
    23: "-=", 24: "/=", 25: "^=",
}

_LEGACY_BINOPS = {
    "BINARY_POWER": "**", "BINARY_MULTIPLY": "*", "BINARY_MATRIX_MULTIPLY": "@",
    "BINARY_FLOOR_DIVIDE": "//", "BINARY_TRUE_DIVIDE": "/",
    "BINARY_MODULO": "%", "BINARY_ADD": "+", "BINARY_SUBTRACT": "-",
    "BINARY_LSHIFT": "<<", "BINARY_RSHIFT": ">>",
    "BINARY_AND": "&", "BINARY_XOR": "^", "BINARY_OR": "|",
    "INPLACE_POWER": "**=", "INPLACE_MULTIPLY": "*=", "INPLACE_MATRIX_MULTIPLY": "@=",
    "INPLACE_FLOOR_DIVIDE": "//=", "INPLACE_TRUE_DIVIDE": "/=",
    "INPLACE_MODULO": "%=", "INPLACE_ADD": "+=", "INPLACE_SUBTRACT": "-=",
    "INPLACE_LSHIFT": "<<=", "INPLACE_RSHIFT": ">>=",
    "INPLACE_AND": "&=", "INPLACE_XOR": "^=", "INPLACE_OR": "|=",
}

_SKIP = frozenset({
    "RESUME", "CACHE", "PRECALL", "PUSH_NULL", "COPY_FREE_VARS",
    "MAKE_CELL", "NOP", "PUSH_EXC_INFO", "POP_EXCEPT",
    "JUMP_BACKWARD_NO_INTERRUPT", "CHECK_EXC_MATCH", "CHECK_EG_MATCH",
    "PREP_RERAISE_STAR", "END_FOR", "INTERPRETER_EXIT", "NOT_TAKEN",
    "EXTENDED_ARG", "SETUP_ANNOTATIONS", "GEN_START", "ASYNC_GEN_WRAP",
    "RETURN_GENERATOR", "WITH_CLEANUP_START", "WITH_CLEANUP_FINISH",
    "WITH_EXCEPT_START", "CLEANUP_THROW", "EXIT_INIT_CHECK",
    "POP_BLOCK", "POP_EXCEPT", "BEFORE_WITH", "BEFORE_ASYNC_WITH",
    "SETUP_FINALLY", "SETUP_WITH", "SETUP_ASYNC_WITH", "SETUP_EXCEPT",
    "COPY_DICT_WITHOUT_KEYS", "GET_YIELD_FROM_ITER", "MATCH_CLASS",
    "MATCH_MAPPING", "MATCH_SEQUENCE", "MATCH_KEYS", "GET_LEN",
    "POP_ITER", "INSTRUMENTED_POP_ITER",
})

def _is_code(obj):
    return isinstance(obj, types.CodeType)

def _safe_repr(val):
    if val is None: return "None"
    if val is True: return "True"
    if val is False: return "False"
    if val is ...: return "..."
    if isinstance(val, (int, float, complex, str, bytes)):
        return repr(val)
    if isinstance(val, tuple):
        inner = ", ".join(_safe_repr(v) for v in val)
        return "({}{})".format(inner, "," if len(val) == 1 else "")
    if isinstance(val, frozenset):
        if not val: return "frozenset()"
        inner = ", ".join(_safe_repr(v) for v in sorted(val, key=repr))
        return "frozenset({{{}}})".format(inner)
    return repr(val)

def _despecialize(op):
    for pfx in ("BINARY_OP_", "LOAD_ATTR_", "LOAD_GLOBAL_", "STORE_ATTR_",
                 "LOAD_SUPER_ATTR_", "COMPARE_OP_", "FOR_ITER_",
                 "STORE_SUBSCR_", "UNPACK_SEQUENCE_", "SEND_", "TO_BOOL_"):
        if op.startswith(pfx):
            return pfx.rstrip("_")
    # CALL_ specializations (not CALL_FUNCTION etc.)
    if op.startswith("CALL_") and op not in (
            "CALL_FUNCTION", "CALL_FUNCTION_KW", "CALL_FUNCTION_EX",
            "CALL_METHOD", "CALL_KW", "CALL_INTRINSIC_1", "CALL_INTRINSIC_2"):
        return "CALL"
    return op


# ═════════════════════════════════════════════════════════════
# CODE OBJECT UTILITIES
# ═════════════════════════════════════════════════════════════

def _build_arglist(code):
    args = []
    nargs = code.co_argcount
    vn = code.co_varnames
    # positional-or-keyword
    for j in range(nargs):
        args.append(vn[j] if j < len(vn) else "arg{}".format(j))
    # *args
    kwonly = getattr(code, "co_kwonlyargcount", 0)
    has_varargs = bool(code.co_flags & 0x04)
    has_varkw = bool(code.co_flags & 0x08)
    if has_varargs:
        idx = nargs + kwonly
        args.append("*{}".format(vn[idx] if idx < len(vn) else "args"))
    elif kwonly:
        args.append("*")
    for j in range(kwonly):
        idx = nargs + j
        args.append(vn[idx] if idx < len(vn) else "kw{}".format(j))
    if has_varkw:
        idx = nargs + kwonly + (1 if has_varargs else 0)
        args.append("**{}".format(vn[idx] if idx < len(vn) else "kwargs"))
    return ", ".join(args)

def _find_code_by_name(code, name):
    for const in code.co_consts:
        if _is_code(const) and const.co_name == name:
            return const
    return None


# ═════════════════════════════════════════════════════════════
# DECOMPILER CLASS — one code object → source lines
# ═════════════════════════════════════════════════════════════

class Decompiler:

    def __init__(self, code, indent=0, is_class=False):
        self.code = code
        self.indent = indent
        self.is_class = is_class
        self.lines = []
        self.stack = []
        self.insts = list(dis.get_instructions(code))
        self.n = len(self.insts)
        # Track which code-object names we've already emitted as def/class
        self.emitted_funcs = set()

    def ind(self, extra=0):
        return "    " * (self.indent + extra)

    def emit(self, text, extra=0):
        self.lines.append(self.ind(extra) + text)

    def push(self, expr):
        self.stack.append(str(expr))

    def pop(self):
        return self.stack.pop() if self.stack else "_unknown_"

    def peek(self):
        return self.stack[-1] if self.stack else "_unknown_"

    def popn(self, n):
        if n == 0: return []
        items = self.stack[-n:]
        self.stack[-n:] = []
        return items

    # ── main entry ──────────────────────────────────────

    def decompile(self):
        i = 0
        while i < self.n:
            i = self._step(i)
        return self.lines

    def _inst(self, i):
        return self.insts[i] if 0 <= i < self.n else None

    def _lookahead(self, i, count):
        """Return up to `count` non-skipped instructions starting from i."""
        result = []
        j = i
        while len(result) < count and j < self.n:
            inst = self.insts[j]
            op = _despecialize(inst.opname)
            if op not in _SKIP:
                result.append((j, inst, op))
            j += 1
        return result

    # ── instruction dispatcher ──────────────────────────

    def _step(self, i):
        inst = self.insts[i]
        op = _despecialize(inst.opname)
        arg = inst.arg
        val = inst.argval

        if op in _SKIP:
            return i + 1

        # ── IMPORTS (lookahead-based) ────────────────────
        if op == "LOAD_CONST" and i + 1 < self.n:
            ahead = self._lookahead(i, 5)
            return self._try_import(i, ahead) or self._handle(i, inst, op, arg, val)

        return self._handle(i, inst, op, arg, val)

    def _try_import(self, start, ahead):
        """Try to match an import pattern starting at `start`.
        Returns next index if matched, None otherwise."""
        ops = [(op, idx, inst) for idx, inst, op in ahead]
        op_seq = [o[0] for o in ops]
        # ops[n] = (opname, instruction_index, instruction_object)

        # Pattern: LOAD_CONST, LOAD_CONST, IMPORT_NAME [, IMPORT_FROM, STORE, POP_TOP]
        #      or: LOAD_CONST, LOAD_CONST, IMPORT_NAME, STORE_NAME
        if len(ops) >= 3 and op_seq[0] == "LOAD_CONST" and op_seq[1] == "LOAD_CONST" and op_seq[2] == "IMPORT_NAME":
            mod_name = ops[2][2].argval
            fromlist_val = ops[1][2].argval  # None or tuple of names

            # Check for IMPORT_FROM chain
            if len(ops) >= 5 and op_seq[3] == "IMPORT_FROM":
                # from X import a, b, ...
                # Collect all IMPORT_FROM + STORE_* pairs
                names = []
                j_idx = ops[3][1]  # instruction index of first IMPORT_FROM
                j = j_idx
                while j < self.n:
                    jinst = self.insts[j]
                    jop = _despecialize(jinst.opname)
                    if jop in _SKIP:
                        j += 1; continue
                    if jop == "IMPORT_FROM":
                        names.append(jinst.argval)
                        j += 1
                        # next should be STORE_*
                        while j < self.n and _despecialize(self.insts[j].opname) in _SKIP:
                            j += 1
                        if j < self.n and _despecialize(self.insts[j].opname).startswith("STORE_"):
                            store_name = self.insts[j].argval
                            if store_name != names[-1]:
                                names[-1] = "{} as {}".format(names[-1], store_name)
                            j += 1
                    elif jop == "POP_TOP":
                        j += 1; break
                    else:
                        break
                self.emit("from {} import {}".format(mod_name, ", ".join(names)))
                return j

            # Pattern: LOAD_CONST, LOAD_CONST, IMPORT_NAME, STORE_NAME
            if len(ops) >= 4 and op_seq[3].startswith("STORE_"):
                store_name = ops[3][2].argval
                if store_name == mod_name or store_name == mod_name.split(".")[0]:
                    self.emit("import {}".format(mod_name))
                else:
                    self.emit("import {} as {}".format(mod_name, store_name))
                return ops[3][1] + 1

        return None  # no match

    def _handle(self, i, inst, op, arg, val):

        # ── LOAD_CONST ───────────────────────────────────
        if op == "LOAD_CONST" or op in ("LOAD_CONST_IMMORTAL", "LOAD_CONST_MORTAL", "LOAD_SMALL_INT"):
            if _is_code(val):
                self.push("<code:{}>".format(val.co_name))
            else:
                self.push(_safe_repr(val))
            return i + 1

        if op == "RETURN_CONST":
            v = _safe_repr(val)
            if v != "None" or not self.is_class:
                if v != "None":
                    self.emit("return {}".format(v))
                # else: implicit return None at end of function — skip
            return i + 1

        # ── LOAD name variants ───────────────────────────
        if op in ("LOAD_NAME", "LOAD_FAST", "LOAD_DEREF", "LOAD_CLOSURE",
                   "LOAD_CLASSDEREF", "LOAD_FAST_CHECK", "LOAD_FAST_AND_CLEAR",
                   "LOAD_FROM_DICT_OR_GLOBALS", "LOAD_FROM_DICT_OR_DEREF",
                   "LOAD_LOCALS"):
            self.push(val if val else "<?>")
            return i + 1

        if op == "LOAD_GLOBAL":
            self.push(val if val else "<?>")
            return i + 1

        if op in ("LOAD_ATTR", "LOAD_SUPER_ATTR"):
            obj = self.pop()
            self.push("{}.{}".format(obj, val))
            return i + 1

        if op == "LOAD_METHOD":
            obj = self.pop()
            self.push("{}.{}".format(obj, val))
            return i + 1

        if op == "LOAD_BUILD_CLASS":
            self.push("__build_class__")
            return i + 1

        if op == "LOAD_ASSERTION_ERROR":
            self.push("AssertionError")
            return i + 1

        # ── STORE opcodes ────────────────────────────────
        if op in ("STORE_NAME", "STORE_GLOBAL", "STORE_FAST", "STORE_DEREF"):
            v = self.pop()
            name = val
            # Skip __module__ = __name__ / __qualname__ = 'X' in classes
            if self.is_class and name in ("__module__", "__qualname__"):
                return i + 1
            # Skip __doc__ = '...' — docstrings are emitted separately
            if name == "__doc__":
                return i + 1
            # Detect function/class definition
            if v.startswith("<func:") or v.startswith("<class:"):
                tag_name = v.split(":", 1)[1].removesuffix(">")
                self._emit_definition(name, tag_name)
                return i + 1
            self.emit("{} = {}".format(name, v))
            return i + 1

        if op == "STORE_ATTR":
            obj = self.pop()
            v = self.pop()
            self.emit("{}.{} = {}".format(obj, val, v))
            return i + 1

        if op == "STORE_SUBSCR":
            key = self.pop()
            obj = self.pop()
            v = self.pop()
            self.emit("{}[{}] = {}".format(obj, key, v))
            return i + 1

        if op in ("DELETE_NAME", "DELETE_GLOBAL", "DELETE_FAST", "DELETE_DEREF"):
            self.emit("del {}".format(val))
            return i + 1

        if op == "DELETE_ATTR":
            obj = self.pop()
            self.emit("del {}.{}".format(obj, val))
            return i + 1

        if op == "DELETE_SUBSCR":
            key = self.pop()
            obj = self.pop()
            self.emit("del {}[{}]".format(obj, key))
            return i + 1

        # ── IMPORT_NAME / IMPORT_FROM / IMPORT_STAR ──────
        # (These should mostly be caught by _try_import, but handle stragglers)
        if op == "IMPORT_NAME":
            self.pop(); self.pop()  # fromlist, level
            self.push("__import__('{}')".format(val))
            return i + 1

        if op == "IMPORT_FROM":
            self.push("{}.{}".format(self.peek(), val))
            return i + 1

        if op == "IMPORT_STAR":
            mod = self.pop()
            self.emit("from {} import *".format(val or mod))
            return i + 1

        # ── UNARY ────────────────────────────────────────
        if op == "UNARY_POSITIVE":  a = self.pop(); self.push("+{}".format(a)); return i+1
        if op == "UNARY_NEGATIVE":  a = self.pop(); self.push("-{}".format(a)); return i+1
        if op == "UNARY_NOT":       a = self.pop(); self.push("not {}".format(a)); return i+1
        if op == "UNARY_INVERT":    a = self.pop(); self.push("~{}".format(a)); return i+1

        # ── BINARY (legacy pre-3.11) ─────────────────────
        if op in _LEGACY_BINOPS:
            sym = _LEGACY_BINOPS[op]
            rhs = self.pop(); lhs = self.pop()
            if "INPLACE" in op:
                # Look ahead for STORE to emit augmented assignment
                j = i + 1
                while j < self.n and _despecialize(self.insts[j].opname) in _SKIP:
                    j += 1
                # Skip ROT_TWO/ROT_THREE that may appear before STORE
                while j < self.n and _despecialize(self.insts[j].opname) in ("ROT_TWO", "ROT_THREE", "DUP_TOP"):
                    j += 1
                if j < self.n and _despecialize(self.insts[j].opname).startswith("STORE_"):
                    target = self.insts[j].argval
                    self.emit("{} {} {}".format(target, sym, rhs))
                    return j + 1
                self.push("{} {} {}".format(lhs, sym, rhs))
            else:
                self.push("({} {} {})".format(lhs, sym, rhs))
            return i + 1

        # ── BINARY_OP (3.11+) ────────────────────────────
        if op == "BINARY_OP":
            rhs = self.pop(); lhs = self.pop()
            sym = _BINOP_SYMBOL.get(arg, "?op{}?".format(arg))
            if arg is not None and arg >= 13:
                # In-place op: look ahead for STORE to emit augmented assignment
                j = i + 1
                while j < self.n and _despecialize(self.insts[j].opname) in _SKIP:
                    j += 1
                if j < self.n and _despecialize(self.insts[j].opname).startswith("STORE_"):
                    target = self.insts[j].argval
                    self.emit("{} {} {}".format(target, sym, rhs))
                    return j + 1
                # fallback
                self.push("{} {} {}".format(lhs, sym, rhs))
            else:
                self.push("({} {} {})".format(lhs, sym, rhs))
            return i + 1

        if op == "BINARY_SUBSCR":
            key = self.pop(); obj = self.pop()
            self.push("{}[{}]".format(obj, key))
            return i + 1

        if op == "BINARY_SLICE":
            end = self.pop(); start = self.pop(); obj = self.pop()
            self.push("{}[{}:{}]".format(obj, start, end))
            return i + 1

        if op == "STORE_SLICE":
            end = self.pop(); start = self.pop(); obj = self.pop(); v = self.pop()
            self.emit("{}[{}:{}] = {}".format(obj, start, end, v))
            return i + 1

        # ── COMPARE ──────────────────────────────────────
        if op == "COMPARE_OP":
            rhs = self.pop(); lhs = self.pop()
            op_str = val if isinstance(val, str) else "=="
            self.push("({} {} {})".format(lhs, op_str, rhs))
            return i + 1

        if op == "IS_OP":
            rhs = self.pop(); lhs = self.pop()
            self.push("({} {} {})".format(lhs, "is not" if arg else "is", rhs))
            return i + 1

        if op == "CONTAINS_OP":
            rhs = self.pop(); lhs = self.pop()
            self.push("({} {} {})".format(lhs, "not in" if arg else "in", rhs))
            return i + 1

        # ── CALL ─────────────────────────────────────────
        if op in ("CALL_FUNCTION", "CALL", "CALL_METHOD"):
            nargs = arg if arg else 0
            args = self.popn(nargs)
            func = self.pop()

            # Detect __build_class__ call → class definition
            if func == "__build_class__" and len(args) >= 2:
                code_ref = args[0]  # <code:ClassName> or <func:ClassName>
                class_name_repr = args[1]
                bases = args[2:]
                cls_name = code_ref.replace("<code:", "").replace("<func:", "").removesuffix(">")
                bases_str = ", ".join(bases) if bases else ""
                self.push("<class:{}>".format(cls_name))
                return i + 1

            self.push("{}({})".format(func, ", ".join(args)))
            return i + 1

        if op == "CALL_FUNCTION_KW":
            keys = self.pop()
            nargs = arg if arg else 0
            all_args = self.popn(nargs)
            func = self.pop()
            self.push("{}({})".format(func, ", ".join(all_args)))
            return i + 1

        if op == "CALL_FUNCTION_EX":
            if arg and (arg & 1):
                kw = self.pop(); a = self.pop(); func = self.pop()
                self.push("{}(*{}, **{})".format(func, a, kw))
            else:
                a = self.pop(); func = self.pop()
                self.push("{}(*{})".format(func, a))
            return i + 1

        if op == "CALL_KW":
            nargs = arg if arg else 0
            all_args = self.popn(nargs)
            func = self.pop()
            self.push("{}({})".format(func, ", ".join(all_args)))
            return i + 1

        if op == "CALL_INTRINSIC_1":
            a = self.pop()
            self.push("__intrinsic1_{}({})".format(arg, a))
            return i + 1

        if op == "CALL_INTRINSIC_2":
            b = self.pop(); a = self.pop()
            self.push("__intrinsic2_{}({}, {})".format(arg, a, b))
            return i + 1

        # ── MAKE_FUNCTION ────────────────────────────────
        if op == "MAKE_FUNCTION":
            return self._handle_make_function(i, arg)

        # ── BUILD opcodes ────────────────────────────────
        if op == "BUILD_TUPLE":
            items = self.popn(arg)
            if len(items) == 1:
                self.push("({},)".format(items[0]))
            else:
                self.push("({})".format(", ".join(items)))
            return i + 1

        if op == "BUILD_LIST":
            items = self.popn(arg)
            self.push("[{}]".format(", ".join(items)))
            return i + 1

        if op == "BUILD_SET":
            items = self.popn(arg)
            if items:
                self.push("{{{}}}".format(", ".join(items)))
            else:
                self.push("set()")
            return i + 1

        if op == "BUILD_MAP":
            items = self.popn(arg * 2)
            pairs = []
            for j in range(0, len(items), 2):
                pairs.append("{}: {}".format(items[j], items[j+1]))
            self.push("{{{}}}".format(", ".join(pairs)))
            return i + 1

        if op == "BUILD_CONST_KEY_MAP":
            keys_repr = self.pop()
            vals = self.popn(arg)
            try:
                key_tuple = eval(keys_repr)
            except Exception:
                key_tuple = None
            if key_tuple and isinstance(key_tuple, tuple):
                pairs = []
                for j, v in enumerate(vals):
                    k = _safe_repr(key_tuple[j]) if j < len(key_tuple) else "?"
                    pairs.append("{}: {}".format(k, v))
                self.push("{{{}}}".format(", ".join(pairs)))
            else:
                self.push("dict(zip({}, ({})))".format(keys_repr, ", ".join(vals)))
            return i + 1

        if op == "BUILD_STRING":
            parts = self.popn(arg)
            # f-string: parts are string fragments and format() calls
            self.push(" + ".join(parts))
            return i + 1

        if op == "BUILD_SLICE":
            if arg == 2:
                end = self.pop(); start = self.pop()
                self.push("slice({}, {})".format(start, end))
            else:
                step = self.pop(); end = self.pop(); start = self.pop()
                self.push("slice({}, {}, {})".format(start, end, step))
            return i + 1

        if op == "LIST_EXTEND":
            iterable = self.pop()
            lst = self.pop()
            # Pattern: BUILD_LIST 0 + LOAD_CONST (tuple) + LIST_EXTEND → list literal
            if lst == "[]" and iterable.startswith("(") and iterable.endswith(")"):
                # Convert tuple repr to list: (1, 2, 3) → [1, 2, 3]
                inner = iterable[1:-1].rstrip(",").strip()
                self.push("[{}]".format(inner))
            else:
                self.push("[*{}, *{}]".format(lst, iterable) if lst != "[]"
                          else "list({})".format(iterable))
            return i + 1

        if op == "SET_UPDATE":
            iterable = self.pop()
            s = self.pop()
            # Pattern: BUILD_SET 0 + LOAD_CONST (frozenset) + SET_UPDATE → set literal
            if s in ("set()", "{}"):
                if iterable.startswith("frozenset("):
                    # frozenset({1, 2, 3}) → {1, 2, 3}
                    inner = iterable[len("frozenset("):-1]
                    self.push(inner)
                else:
                    self.push("set({})".format(iterable))
            else:
                self.push("{} | {}".format(s, iterable))
            return i + 1

        if op == "DICT_UPDATE":
            v = self.pop(); d = self.pop()
            self.push("{{**{}, **{}}}".format(d, v))
            return i + 1

        if op == "DICT_MERGE":
            v = self.pop(); d = self.pop()
            self.push("{{**{}, **{}}}".format(d, v))
            return i + 1

        if op == "LIST_APPEND":
            v = self.pop()
            self.push(v)
            return i + 1

        if op in ("SET_ADD", "MAP_ADD"):
            v = self.pop()
            self.push(v)
            return i + 1

        if op == "LIST_TO_TUPLE":
            lst = self.pop()
            self.push("tuple({})".format(lst))
            return i + 1

        # ── UNPACK ───────────────────────────────────────
        if op == "UNPACK_SEQUENCE":
            seq = self.pop()
            names = []
            j = i + 1
            count = 0
            while count < arg and j < self.n:
                jinst = self.insts[j]
                jop = _despecialize(jinst.opname)
                if jop in _SKIP:
                    j += 1; continue
                if jop.startswith("STORE_"):
                    names.append(str(jinst.argval))
                    count += 1
                    j += 1
                else:
                    break
            if len(names) == arg:
                self.emit("{} = {}".format(", ".join(names), seq))
                return j
            # fallback
            self.push(seq)
            return i + 1

        if op == "UNPACK_EX":
            seq = self.pop()
            self.push("*unpack_ex({})".format(seq))
            return i + 1

        # ── JUMPS / CONTROL FLOW ─────────────────────────
        if op in ("POP_JUMP_IF_FALSE", "POP_JUMP_FORWARD_IF_FALSE",
                   "POP_JUMP_BACKWARD_IF_FALSE"):
            cond = self.pop()
            self.emit("if {}:".format(cond))
            self.emit("    pass  # branch", 0)
            return i + 1

        if op in ("POP_JUMP_IF_TRUE", "POP_JUMP_FORWARD_IF_TRUE",
                   "POP_JUMP_BACKWARD_IF_TRUE"):
            cond = self.pop()
            self.emit("if not {}:".format(cond))
            self.emit("    pass  # branch", 0)
            return i + 1

        if op in ("POP_JUMP_IF_NONE", "POP_JUMP_FORWARD_IF_NONE"):
            v = self.pop()
            self.emit("if {} is None:".format(v))
            self.emit("    pass  # branch", 0)
            return i + 1

        if op in ("POP_JUMP_IF_NOT_NONE", "POP_JUMP_FORWARD_IF_NOT_NONE"):
            v = self.pop()
            self.emit("if {} is not None:".format(v))
            self.emit("    pass  # branch", 0)
            return i + 1

        if op in ("JUMP_FORWARD", "JUMP_ABSOLUTE", "JUMP_BACKWARD",
                   "JUMP_BACKWARD_QUICK"):
            return i + 1

        if op == "JUMP_IF_TRUE_OR_POP":
            return i + 1

        if op == "JUMP_IF_FALSE_OR_POP":
            return i + 1

        if op == "FOR_ITER":
            iter_expr = self.pop()
            # Strip wrapping iter() if present
            if iter_expr.startswith("iter(") and iter_expr.endswith(")"):
                iter_expr = iter_expr[5:-1]
            # Look ahead for STORE_*
            j = i + 1
            while j < self.n and _despecialize(self.insts[j].opname) in _SKIP:
                j += 1
            if j < self.n and _despecialize(self.insts[j].opname).startswith("STORE_"):
                self.emit("for {} in {}:".format(self.insts[j].argval, iter_expr))
                self.emit("    pass  # loop body follows below", 0)
                return j + 1
            self.emit("for _item in {}:".format(iter_expr))
            self.emit("    pass  # loop body follows below", 0)
            return i + 1

        if op == "GET_ITER":
            obj = self.pop()
            self.push("iter({})".format(obj))
            return i + 1

        if op == "GET_AWAITABLE":
            obj = self.pop()
            self.push("await {}".format(obj))
            return i + 1

        if op == "GET_AITER":
            obj = self.pop()
            self.push("aiter({})".format(obj))
            return i + 1

        if op == "GET_ANEXT":
            obj = self.pop()
            self.push("anext({})".format(obj))
            return i + 1

        # ── RETURN / YIELD ───────────────────────────────
        if op == "RETURN_VALUE":
            v = self.pop()
            if v == "None":
                pass  # implicit return
            else:
                self.emit("return {}".format(v))
            return i + 1

        if op == "YIELD_VALUE":
            v = self.pop()
            self.push("(yield {})".format(v))
            return i + 1

        if op == "YIELD_FROM":
            v = self.pop()
            self.push("(yield from {})".format(v))
            return i + 1

        if op == "SEND":
            v = self.pop()
            self.push("send({})".format(v))
            return i + 1

        # ── RAISE ────────────────────────────────────────
        if op == "RAISE_VARARGS":
            if arg == 0: self.emit("raise")
            elif arg == 1: self.emit("raise {}".format(self.pop()))
            elif arg == 2:
                cause = self.pop(); exc = self.pop()
                self.emit("raise {} from {}".format(exc, cause))
            return i + 1

        if op == "RERAISE":
            return i + 1

        # ── STACK manipulation ───────────────────────────
        if op == "POP_TOP":
            v = self.pop()
            if v and v != "<?>" and not v.startswith("<code:") and not v.startswith("<func:"):
                # Emit expression-statements (function calls, etc.)
                stripped = v.strip()
                if stripped and stripped != "None":
                    self.emit(stripped)
            return i + 1

        if op == "DUP_TOP":
            v = self.peek(); self.push(v); return i + 1

        if op == "DUP_TOP_TWO":
            if len(self.stack) >= 2:
                self.push(self.stack[-2]); self.push(self.stack[-2])
            return i + 1

        if op == "ROT_TWO":
            if len(self.stack) >= 2:
                self.stack[-1], self.stack[-2] = self.stack[-2], self.stack[-1]
            return i + 1

        if op == "ROT_THREE":
            if len(self.stack) >= 3:
                t = self.stack[-1]; self.stack[-1] = self.stack[-2]
                self.stack[-2] = self.stack[-3]; self.stack[-3] = t
            return i + 1

        if op == "ROT_FOUR":
            if len(self.stack) >= 4:
                t = self.stack[-1]
                self.stack[-1] = self.stack[-2]; self.stack[-2] = self.stack[-3]
                self.stack[-3] = self.stack[-4]; self.stack[-4] = t
            return i + 1

        if op == "COPY":
            if arg and len(self.stack) >= arg:
                self.push(self.stack[-arg])
            return i + 1

        if op == "SWAP":
            if arg and len(self.stack) >= arg:
                self.stack[-1], self.stack[-arg] = self.stack[-arg], self.stack[-1]
            return i + 1

        # ── FORMAT_VALUE (f-strings pre-3.12) ────────────
        if op == "FORMAT_VALUE":
            fmt_spec = ""
            if arg and (arg & 0x04):
                fmt_spec = self.pop()
            v = self.pop()
            conv = ""
            if arg:
                c = arg & 0x03
                if c == 1: conv = "!s"
                elif c == 2: conv = "!r"
                elif c == 3: conv = "!a"
            self.push("f'{{{}{}}}'".format(v, conv))
            return i + 1

        if op in ("FORMAT_SIMPLE", "FORMAT_WITH_SPEC", "CONVERT_VALUE"):
            if op == "FORMAT_WITH_SPEC":
                spec = self.pop(); v = self.pop()
                self.push("format({}, {})".format(v, spec))
            elif op == "CONVERT_VALUE":
                v = self.pop()
                self.push("convert({})".format(v))
            else:
                v = self.pop()
                self.push("format({})".format(v))
            return i + 1

        if op == "TO_BOOL":
            return i + 1

        if op == "KW_NAMES":
            self.push(repr(val))
            return i + 1

        if op == "PRINT_EXPR":
            v = self.pop()
            self.emit("print({})".format(v))
            return i + 1

        # ── Catch-all ────────────────────────────────────
        log.debug("Unhandled: %s arg=%s at offset %d", op, arg, inst.offset)
        return i + 1

    # ── MAKE_FUNCTION handler ────────────────────────────

    def _handle_make_function(self, i, flags):
        code_repr = self.pop()
        if flags is None:
            flags = 0
        # Pop optional items pushed before MAKE_FUNCTION
        if flags & 0x08: self.pop()  # closure
        if flags & 0x04: self.pop()  # annotations
        if flags & 0x02: self.pop()  # kw defaults
        if flags & 0x01: self.pop()  # defaults tuple
        name = code_repr.replace("<code:", "").removesuffix(">")
        self.push("<func:{}>".format(name))
        return i + 1

    # ── Lambda inlining ────────────────────────────────

    def _try_inline_lambda(self, code):
        """Try to decompile a lambda's code object as a single expression.
        Returns the expression string, or None if it's too complex."""
        sub = Decompiler(code, indent=0)
        sub.decompile()
        # Lambda body should produce exactly one "return <expr>" line
        # after stripping blanks
        result_lines = [l.strip() for l in sub.lines if l.strip()]
        if len(result_lines) == 1 and result_lines[0].startswith("return "):
            return result_lines[0][7:]
        return None

    # ── Definition emitter ───────────────────────────────

    def _emit_definition(self, store_name, code_name):
        """Emit a function or class definition."""
        child_code = _find_code_by_name(self.code, code_name)
        if child_code is None:
            self.emit("{} = <unresolved:{}>".format(store_name, code_name))
            return

        if code_name in self.emitted_funcs:
            return
        self.emitted_funcs.add(code_name)

        # Lambda: try to inline as "lambda args: expr"
        if code_name == "<lambda>":
            expr = self._try_inline_lambda(child_code)
            if expr is not None:
                self.emit("{} = lambda {}: {}".format(
                    store_name, _build_arglist(child_code), expr))
                return
            # Fall through to def if inline fails

        # Is this a class?
        is_class = False
        child_insts = list(dis.get_instructions(child_code))
        for ci in child_insts[:6]:
            cop = _despecialize(ci.opname)
            if cop in _SKIP: continue
            if cop == "STORE_NAME" and ci.argval == "__module__":
                is_class = True
                break

        if is_class:
            self.emit("")
            self.emit("class {}:".format(store_name))
            # Docstring
            if child_code.co_consts and isinstance(child_code.co_consts[0], str):
                doc = child_code.co_consts[0]
                if doc != store_name:
                    self.emit('    """{}"""'.format(doc))
            # Decompile class body
            sub = Decompiler(child_code, indent=self.indent + 1, is_class=True)
            body = sub.decompile()
            if body:
                self.lines.extend(body)
            else:
                self.emit("    pass")
            self.emit("")
        else:
            # Function
            args_str = _build_arglist(child_code)
            prefix = ""
            if child_code.co_flags & 0x100:
                prefix = "async "

            self.emit("")
            self.emit("{}def {}({}):".format(prefix, store_name, args_str))
            # Docstring
            if child_code.co_consts and isinstance(child_code.co_consts[0], str):
                doc = child_code.co_consts[0]
                self.emit('    """{}"""'.format(doc))
            # Decompile body
            sub = Decompiler(child_code, indent=self.indent + 1)
            body = sub.decompile()
            if body:
                self.lines.extend(body)
            else:
                self.emit("    pass")
            self.emit("")


# ═════════════════════════════════════════════════════════════
# PUBLIC API
# ═════════════════════════════════════════════════════════════

def decompile_pyc(path, output=None):
    code = load_code_object(path)

    # Module docstring
    header = []
    if code.co_consts and isinstance(code.co_consts[0], str):
        doc = code.co_consts[0]
        header.append('"""{}"""'.format(doc))
        header.append("")

    dec = Decompiler(code, indent=0)
    lines = dec.decompile()

    final = header + lines

    # Clean up: collapse consecutive blank lines
    cleaned = []
    prev_blank = False
    for line in final:
        is_blank = line.strip() == ""
        if is_blank and prev_blank:
            continue
        cleaned.append(line.rstrip())
        prev_blank = is_blank
    while cleaned and cleaned[-1] == "":
        cleaned.pop()

    source = "\n".join(cleaned) + "\n"

    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write(source)
        log.info("Written to %s", output)
    else:
        sys.stdout.write(source)

    return source


def show_info(path):
    with open(path, "rb") as f:
        data = f.read(16)
    magic = struct.unpack("<H", data[:2])[0]
    ver = detect_version(path)
    print("File:           {}".format(path))
    print("Magic number:   {} (0x{:04x})".format(magic, magic))
    print("Magic bytes:    {}".format(data[:4].hex()))
    if ver:
        print("Python version: {}.{} (auto-detected)".format(*ver))
        print("Header size:    {} bytes".format(header_size(ver)))
    else:
        print("Python version: UNKNOWN")
    print("Running Python: {}.{}".format(*PY_VERSION))


def show_bytecode(path, output=None):
    code = load_code_object(path)
    buf = io.StringIO()
    dis.dis(code, file=buf)
    text = buf.getvalue()
    if output:
        with open(output, "w") as f:
            f.write(text)
    else:
        print(text)


# ═════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="pycDcode — Decompile .pyc to readable Python source",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              %(prog)s app.pyc                    # decompile to stdout
              %(prog)s app.pyc -o recovered.py    # decompile to file
              %(prog)s app.pyc --info             # show PYC header info
              %(prog)s app.pyc --bytecode         # raw dis output
        """))
    parser.add_argument("pyc", help="Path to .pyc file")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    parser.add_argument("--info", action="store_true", help="Show PYC header info")
    parser.add_argument("--bytecode", action="store_true", help="Raw bytecode disassembly")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    parser.add_argument("--version", action="version", version="pycDcode {}".format(__version__))
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="[%(levelname)s] %(message)s", stream=sys.stderr)

    if not os.path.isfile(args.pyc):
        sys.exit("Error: file not found: {}".format(args.pyc))

    if args.info:
        show_info(args.pyc); return
    if args.bytecode:
        show_bytecode(args.pyc, args.output); return

    decompile_pyc(args.pyc, args.output)


if __name__ == "__main__":
    main()
