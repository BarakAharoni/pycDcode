# pycDcode
Python PYC file analysis and forensics using bytecode decompilation.

```
                   ___             _                         
      _ __ _  _ __|   \ __ ___  __| |___                     
     | '_ \ || / _| |) / _/ _ \/ _` / -_)                    
     | .__/\_, \__|___/\__\___/\__,_\___|                    
     |_|   |__/                                              
                                                            
```

Let’s see how a Python script works under the hood and how to use `pycDcode` to automate that process!

# Background
When compiling a Python script (`.py`), you’ll end up with a compiled Python (`.pyc`, `.pyo`). The file is not as readable as its predecessor, since it is a bytecode sequence. Don’t worry, if you know the way, you can revert it to a readable Python script.

# Our case study
In this writeup, we will analyze a short script named `demo_script.py`:

```
# Imports
from random import Random
from sys import *
import os
# Constants
START_BANNER = "Hello you, have fun with this demo script!"
END_BANNER = "Goodbye."
# Get a random number between 1-6
def new_num():
    rnd_num = Random().randint(1,6)
    return rnd_num
# Rotate the input string by a random number (1-6)
def rot(inp):
    rotted = []
        rot_num = 0
        for i in inp:
            rot_num = new_num()
            rotted.append(chr(ord(i) + rot_num))
    return rotted
    
def main():
    print(START_BANNER)
    inp = argv[1]
    final = rot(inp)
    final = "".join(final)
    print(final)
    print(END_BANNER)
if __name__ == "__main__":
    main()
```
 
 There are several tools to compile Python scripts, the most common of which are `PyInstaller` and `Py2Exe`. Every tool compiles Python scripts differently, yet it can be identified generally.
 
 # How to Identify Compiled Python?
 The first step in file analysis is to identify its type. Luckily, it’s pretty simple to find out if an executable file is a compiled Python, using the following method:
 - Use the resource section (part of the PE file format) to locate compiled Python identifiers, such as the widely known icon.
 ![image](https://user-images.githubusercontent.com/97598628/170483845-9f7c7788-7f47-493b-9acb-5b949cf94002.png)

- Use the `strings` tool (from `SysInternals Suite`) that contains Python information like:
```
“Could not load python dll”
PY2EXE_VERBOSE
PyInstaller
“PYTHONSCRIPT”
strings.exe -a “.\dist\demo_script.exe” > strings.txt
```
![image](https://user-images.githubusercontent.com/97598628/170483927-aaca774f-b267-48ca-a960-f04d0bb82f5a.png)

- Detect that the file is probably packed — PyInstaller for example is recognized as a packer since it wraps the source code at the new executable.

# How to determine which python version is being used?
Every Python version is a little different from the other. This is critical as there are many differences between versions.
- Open the executable file in a hex editor (like 010Editor, HxD …).
- Scroll down to the end of the file.
- Locate a string that identifiers the Python version: `PythonXX.dll`.
![image](https://user-images.githubusercontent.com/97598628/170484064-0f659c73-aa63-412a-b023-ccb7d3fa223d.png)

# Convert EXE to PYC
To revert from an executable file to a Python script, it needs to be converted in the following order:
![image](https://user-images.githubusercontent.com/97598628/170484133-2f3bf65d-31e1-45c2-8794-85b1466a6eb3.png)

Several tools decompile executable files to the `.pyc` file:
- `python unpy2exe.py {file.exe}`
- `python pyinstxtractor.py {file.exe}`

These tools will output several files, some of which are used by the tools themselves, so they can be ignored.
The file we are looking for is the one that is named the same as the original file, with a .pyc suffix.
For example, the main file of `file.exe` is `file.pyc`.

## Automatic decompile PYC
Now, all it takes is decompiling the `.pyc` file which results in the original Python script. To do so, we’ll use the following tools:

- Uncompyle6 — Relevant to Python version 2.6–3.8.
- Decompyle3.
- Easy Python decompiler.
- 
There are several situations where the tools will not work properly. This can be due to incompatible Python versions or missing dependencies.
In those and other unforeseen cases, we will need to do that on our own!

## Manually decompile PYC files
After extracting the main `.pyc` file, we are going to convert it to a readable Python script using default modules only.

The module `dis` supports the analysis of CPython bytecode by disassembling it into a code object, or into an object from which a code object can be obtained, such as a function or module.
This module also contains a lot of information about the bytecode’s instructions.

The module `marshal` allows to read and write specific Python values in a binary format. And also support reading and writing the “pseudo-compiled” code for Python modules of `.pyc` files.

The following script extracts the bytecode into a readable structure that allows rewriting of the original Python script:

```
import sys
import dis, marshal
pyc_path = sys.argv[1]
with open(pyc_path, 'rb') as f:
    # First 16 bytes comprise the pyc header (python 3.6+), else 8 bytes.
    pyc_header = f.read(16)
    code_obj = marshal.load(f) # Suite to code object
dis.dis(code_obj)
```

For comfort, pipe the output to a text file:
`manually_decompile.py demo_script.pyc > dis.txt`

![image](https://user-images.githubusercontent.com/97598628/170484518-7f89baee-2b48-4c06-bdd4-ea7e85dfcdf6.png)

## Output explanation
- Section number — every section is separated with a spacebar and will be numbered accordingly. Each section is a line in the original Python script.
- Line number in the current section — this line number will be reset for every function.
- Instruction — the instruction that will be executed.
- Relevant to conditions — contains the line number where the condition ends.
- Parameter —the relevant parameter according to the instruction.

### Instruction information
To understand the disassemble output, you can view the module's documentation.

The bytecode analysis API allows pieces of Python code to be wrapped in a bytecode object that provides easy access to details of the compiled code.
https://docs.python.org/3/library/dis.html

```
LOAD_FAST — load a local variable.
BINARY_ADD — add the last value to the previous one.
CALL_FUNCTION — call a function
And so on…
```
Now we need to parse the output of `dis.txt` and rewrite the legitimate .py script —which should result in a script identical to the original one.

## Identify Python script structure from bytecodes
### Imports
Imported modules can usually be found at the beginning of the code, due to their uses later in the script.
Main instructions: `IMPORT_STAR`, `IMPORT_FROM`, `IMPORT_NAME`.

- `IMPORT_NAME` — import module.
- `IMPORT_FROM` — combine with the previous instruction, and get from X import Y.
- `IMPORT_STAR` — import * from module.

For example, for the following part of the code:
![image](https://user-images.githubusercontent.com/97598628/170484883-48b38473-a1a4-4b7e-967d-9651e3a3a210.png)

We get:
```
from random import Random
from sys import *
import os
```

### Constants
Constant variables usually are found immediately after the modules.
Main instructions: `LOAD_CONST` combined with `STORE_NAME`.

- `LOAD_CONST` — load a global variable.
- `STORE_NAME` — the variable that stores the input value.
![image](https://user-images.githubusercontent.com/97598628/170484989-7cbcf70d-8143-4871-b443-1ae165cea030.png)

Converts to:
```
START_BANNER = "Hello you, have fun with this demo script!"
END_BANNER = "Goodbye."
```

### Defining functions
In this section, there will be only the function’s names and not the content and algorithms. Due to the relation to functions is like to a constant object in the code. It can help us understand the flow of the code.

It can be identified by the string `(<code object {FUNC_NAME} at {OFFSET}, file “{SCRIPT_NAME}”, line {LINE_NUMBER}>)`.
Immediately after, the instruction `MAKE_FUNCTION` appears with a constant variable that contains its name.
![image](https://user-images.githubusercontent.com/97598628/170485220-2f9797a7-c4d1-4e0b-809c-622bf893f497.png)

Is converted to:

```
def new_num():
def rot():
def main():
```

The content of each function can be filled by jumping to the correct offset (the line number will be reset and we can compare the function’s name). Every section and instruction that will be found in this zone belongs to the specific function (indented in the original script).
We can recognize the end of the function, by the `RETURN_VALUE` instruction. Thus, like a stack, the value that will be loaded to the previous instruction (like `LOAD_CONST`), will be the return value of the function.

As a Python convention, the content of the function needs to be indented appropriately.

For example, the `new_num` function will appear as follows:
![image](https://user-images.githubusercontent.com/97598628/170485337-d58c111c-d899-46dc-82f0-e4a45873517a.png)

### Conditions
We can identify conditions like if-else statements with the instructions: `POP_JUMP_IF_ELSE`, `POP_JUMP_IF_TRUE`, etc.
Pay attention to the purpose of the instruction — jump if true or if false and so on. Also, notice the number next to the instruction, that points to the line to jump to when the condition is performed. That line is marked with the sign `‘>>’`.
Furthermore, the instruction `COMPARE_OP` contains the Boolean condition’s operator, and the variables in that section are the variables to compare with.
![image](https://user-images.githubusercontent.com/97598628/170485443-c962cf44-4d73-4858-88f9-044f57e594e6.png)

The sharp-eyed will notice that this is the known ‘main’ condition:

```
if __name__ == “__main__”:
    main()
```
 
### Functions calls
To recognize calls to functions inside the code, we’ll search for the relevant instructions: `CALL_METHOD`, `CALL_FUNCTION`, etc.
For example, combining the instruction `LOAD_GLOBAL`, right after `LOAD_METHOD` and eventually, `CALL_METHOD` will indicate to` global.method()`.

- `LOAD_METHOD` — variable.method.
- `CALL_METHOD` — make the call to the method: `()`.
If there are more methods or parameters, they’ll input into a stack-based logic (LIFO).

For example, we will revert a line from the `new_num` function mentioned earlier:
![image](https://user-images.githubusercontent.com/97598628/170485619-46f57ac8-913f-41ad-b412-db43ee27c8bf.png)

The result will be:

`
rnd_num = Random().randint(1,6)
`

### Loops
Knowing how to handle loops in the code is key to understanding the code.
We can identify it by the instructions:

- `FOR_ITER` — for loop that ends at the line in the parameter field (to line).
- `GET_ITER` — the iteration variable from the inerrable one.

Let’s examine this part of the code:
![image](https://user-images.githubusercontent.com/97598628/170485730-f534f694-1ade-42c9-946c-1eccf4da14d2.png)

We can see it becomes:

```
for i in inp:
    rot_num = new_num()
    rotted.append(chr(ord(i) + rot_num))
return rotted
```

The variable `i` is the iterator variable and `inp` is the iterable variable that the loop is based on. Everything inside the `>>` sign is indented inside the loop.

In the end, we can see the return with the variable rotted.


# How to use the tool
```
1) Get Bytecodes from pyc:  
  python pycDcode.py --pyc {pyc-file} --bytecode --version {py-version} > {output-file}
3) Build Script Template:
  python pycDcode.py --bcfile {bytecode-file} --template
```

Copyright (c) 2022 Barak Aharoni.  All Rights Reserved.
