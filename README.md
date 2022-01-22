# pycDcode
Python PYC file analysis and forensics using bytecode decompilation.

```
                   ___             _                         
      _ __ _  _ __|   \ __ ___  __| |___                     
     | '_ \ || / _| |) / _/ _ \/ _` / -_)                    
     | .__/\_, \__|___/\__\___/\__,_\___|                    
     |_|   |__/                                              
                                                            
```

# How to use the tool
```
1) Get Bytecodes from pyc:  
  python pycDcode.py --pyc {pyc-file} --bytecode --version {py-version} > {output-file}
3) Build Script Template:
  python pycDcode.py --bcfile {bytecode-file} --template
```

# Extra
For more information about compiled python analysis see my writeup at medium:
https://betterprogramming.pub/analysis-of-compiled-python-files-629d8adbe787
