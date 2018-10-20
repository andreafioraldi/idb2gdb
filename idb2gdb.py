__author__ = "Andrea Fioraldi"
__copyright__ = "Copyright 2018, Andrea Fioraldi"
__license__ = "BSD 2-Clause"
__email__ = "andreafioraldi@gmail.com"

import idb
import gdb

def _image_base():
    try:
        mappings = gdb.execute("info proc mappings", to_string=True)
        first_num_pos = mappings.find("0x")
        return int(mappings[first_num_pos: mappings.find(" ", first_num_pos)], 16)
    except:
        return 0

_ida_names = {}

class IdbloadCommand(gdb.Command):
    '''
    Load function names from an IDA Pro database
    '''

    def __init__(self):
        super(IdbloadCommand, self).__init__("idb_load", gdb.COMPLETE_FILENAME)

    def invoke(self, arg, from_tty):
        global _ida_names
        self.dont_repeat()
        
        with idb.from_file(arg) as db:
            api = idb.IDAPython(db)
            base = api.idaapi.get_imagebase()
            for ea in api.idautils.Functions():
                _ida_names[api.idc.GetFunctionName(ea)] = ea - base
                

class IdblistCommand(gdb.Command):
    '''
    List all function names and addresses associated to the IDB
    '''

    def __init__(self):
        super(IdblistCommand, self).__init__("idb_list", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        global _ida_names
        self.dont_repeat()
        
        if len(_ida_names) == 0:
            return
        
        base_addr = _image_base()
        long_size = gdb.lookup_type("long").sizeof * 2
        
        max_name_len = max(map(len, list(_ida_names)))
        for name in sorted(_ida_names, key=lambda n: _ida_names[n]):
            print("0x" + ("%x" % (base_addr + _ida_names[name])).zfill(long_size) + " (base+0x%x)" % _ida_names[name] + "    " + name.ljust(max_name_len, " ")   )


class IdbsolveCommand(gdb.Command):
    '''
    Solve an IDB function name to its address
    '''

    def __init__(self):
        super(IdbsolveCommand, self).__init__("idb_solve", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        global _ida_names
        self.dont_repeat()
        
        try:
            print("0x%x" % (_image_base() + _ida_names[arg]))
        except KeyError:
            print("error: name %s not found" % arg)

class IdbbreakCommand(gdb.Command):
    '''
    Set a breakpoint from an IDB function name
    '''

    def __init__(self):
        super(IdbbreakCommand, self).__init__("idb_break", gdb.COMMAND_BREAKPOINTS)

    def invoke(self, arg, from_tty):
        global _ida_names
        self.dont_repeat()
        
        try:
            addr = _image_base() + _ida_names[arg]
        except KeyError:
            print("error: name %s not found" % arg)
            return
        
        gdb.execute("break *0x%x" % addr)

class IdbcleanCommand(gdb.Command):
    '''
    Delete all loaded names
    '''

    def __init__(self):
        super(IdbcleanCommand, self).__init__("idb_clean", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        global _ida_names
        self.dont_repeat()
        
        _ida_names = {}


class IdbFunction(gdb.Function):
    '''
    Function to solve IDB function names to its address
    '''

    def __init__(self):
        super(IdbFunction, self).__init__("idb")

    def invoke(self, arg):
        global _ida_names
        
        try:
            return (_image_base() + _ida_names[arg.string()])
        except KeyError:
            print("error: name %s not found" % arg)



IdbloadCommand()
IdblistCommand()
IdbsolveCommand()
IdbbreakCommand()
IdbcleanCommand()
IdbFunction()
