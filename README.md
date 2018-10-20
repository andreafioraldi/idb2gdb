# idb2gdb
Load function names from an IDA Pro database inside GDB

## commands

+ `idb_load <IDB file>` Load function names from an IDA Pro database
+ `idb_list` List all function names and addresses associated to the IDB
+ `idb_solve <name>` Solve an IDB name to its address
+ `idb_break <name>` Set a breakpoint from an IDB name
+ `idb_clean` Delete all loaded names

## function

+ `$idb("function_name")` GDB function to solve an IDB name to its address

e.g. `b *$idb("main")` set a breakpoint on main

## install

```
python3 -m pip install python-idb
echo 'source /path/to/idb2gdb.py' >> ~/.gdbinit
```
