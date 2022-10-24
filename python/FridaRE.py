#!/bin/env python3
#
# Frida wrapper for javascript generation
#

import frida
import sys
import random
import json

class JSObj:
    def __init__(self):
        self.objs = []
        self.hdr = ''
        self.bdy = ''
        self.ftr = ''
        self.syms = []
        
    def header(self):
        return self.hdr

    def body(self):
        return self.bdy

    def footer(self):
        return self.ftr

    def setSyms (self, syms):
        self.syms = syms

    def getSyms (self):
        return self.syms
    
    def clearSyms (self):
        self.syms = []
    
    def __str__(self):
        # Grab export syms if object is correct
        if issubclass (type (self), JSExportSyms):
            syms = self.exportSyms ()
        else:
            syms = self.getSyms ()
        _ = ''
        _ += self.header ()
        #_ += '\t'
        _ += self.body ()
        for obj in self.objs:
            # Set syms for subclass
            obj.setSyms (syms)
            if issubclass (type(obj), JSWrap):
                #_ += str (obj).replace ('\n', '\n\t')
                _ += str (obj)
            else:
                _ += obj.header ()
                _ += obj.body ()
                _ += obj.footer ()
            # Clear symbols
            obj.clearSyms ()
            
        _ += self.footer ()
        return _
    
    def add (self, obj):
        self.objs.append (obj)
        
class JSWrap (JSObj):
    ''' Abstract class to wrap code '''
    def __init__(self):
        super().__init__()


class JSExportSyms (JSWrap):
    ''' For classes that can export symbols '''
    def __init__(self):
        super().__init__()

    def exportSyms (self):
        ''' Must be overridden '''
        raise RuntimeError ('JSExportSyms must override exportSyms()')
    
class JSMatch (JSWrap):
    ''' Match variable with const '''
    def __init__(self, var, const='', regex=''):
        super().__init__()
        self.var = var
        if regex:
            self.regex = f'/{regex}/'
        else:
            self.regex = f'/{const}/'

        # Set header and footer
        self.hdr = f'if (this.{var}.match({self.regex})) {{\n'
        self.ftr = '}\n'
        
''' 
RPC class takes exported symbols and sends to python handler

It then converts to JSON and sends to python client using a unique
pipe. It can also recv JS code and execute it dynamically in JS env.

JSON/dict format is:
 {[['name', this.var], ['name', this.var]]}

'''
class RPC (JSObj):
    ''' Remote procedure call python <=> javascript '''
    def __init__(self, name, cb=None, bidir=False):
        super().__init__()
        self.bidir = bidir
        self.uid = hex (id (self))
        self.op = f'op_{random.randint(0,2**32)}'
        self.fn = f'fn_{random.randint(0,2**32)}'
        self.cb = cb
        self.name = name
        # Register with FridaRE global
        FridaRE.register (self.uid, self)
        
    def send(self):
        ''' Generate code to send JSON from JS => python '''
        self.vlist = self.getSyms ()
        args =  self.vlist.copy()
        args.insert (0, ['id', f'{self.uid}'])
        args.insert (1, ['name', f'\'{self.name}\''])
        code = [f'\'{nm}\',{var}' for nm, var in args]
        code = '{' + ','.join (code) + '}'
        code = f'send(JSON.stringify({code}));\n'
        return code
    
    def recv(self):
        ''' Generate code to recv JS function from python and execute '''
        self.vlist = self.getSyms ()
        fn_list = ','.join ([f'\'{nm}\'' for nm, _ in self.vlist])
        fn_args = ','.join ([f'{var}' for _, var in self.vlist])
        code = f'const {self.op} = recv(\'{self.uid}\', value => {{\n'
        code +=f'  {self.fn}_body = value.payload;\n'
        code +=f'}});\n'
        code +=f'{self.op}.wait();\n'
        code +=f'let {self.fn} = new Function ({fn_list},{self.fn}_body);\n'
        code +=f'{self.fn} ({fn_args});\n'
        return code

    def send_recv(self):
        ''' Generate send and recv code '''
        return self.send() + self.recv()
    
    def uid(self):
        ''' Return unique id for RPC object '''
        return self.uid

    def callback(self, cb):
        self.cb = cb

    def _callback(self, d):
        if self.cb:
            return self.cb (d)
        else:
            return None

    def body(self):
        _ = self.send ()
        if self.bidir:
            _ += self.recv ()
        return _

class JSVar:
    def __init__(self):
        pass
    
    @staticmethod
    def Read (type_str):
        if type_str == 'char*':
            return 'Memory.readCString'
        elif type_str == 'void*':
            return 'ptr'
        
class HookFn (JSExportSyms):
    def __init__(self, fn, sigs, lib=None):
        self.enter_obj = None
        self.exit_obj = None
        self.lib = f'\'{lib}\'' if lib != None else 'none'
        self.lib_var = f'hook_{random.randint(0, 2**32)}'
        self.hdr = f'let {self.lib_var} = Module.findExportByName ({self.lib}, \'{fn}\');\n'
        self.hdr += f'Interceptor.attach ({self.lib_var}, {{\n'
        self.hdr += 'onEnter (args) {\n'
        self.bdy = '\n},\nonLeave (retval) {\n'
        self.ftr = '}\n});\n'
        self.sigs = [sig.split(' ') for sig in sigs]
        # Add return val
        self.sigs[len (self.sigs)-1].insert (0, 'retval')
        
    def onEnter(self, obj):
        self.enter_obj = obj
        
    def onExit(self, obj):
        self.exit_obj = obj

    # Handled separately with overridden __str__ fn
    def exportSyms (self):
        return []
    
    def enterSyms(self):
        return [[nm, f'this.{nm}'] for nm, sig in self.sigs[:-1]]

    def exitSyms(self):
        return self.enterSyms() + [[f'{self.sigs[-1][0]}', f'this.{self.sigs[-1][0]}']]

    def genOnEnter(self):
        _ = ''
        for n, sig in enumerate (self.sigs[:-1]):
            access = JSVar.Read(sig[1])
            _ += f'this.{sig[0]} = {access}(args[{n}]);\n'
        return _
    
    def genOnExit(self):
        sig = self.sigs[-1]
        access = JSVar.Read(sig[1])
        return f'this.{sig[0]} = {access}(retval);\n'
    
    def __str__(self):
        _ = self.header()
        syms = self.exportSyms ()
        if self.enter_obj:
            _ += self.genOnEnter ()
            self.enter_obj.setSyms (self.enterSyms())
            _ += str(self.enter_obj)
            self.enter_obj.clearSyms ()
        _ += self.body ()
        if self.exit_obj:
            _ += self.genOnExit ()
            self.exit_obj.setSyms (self.exitSyms())
            _ += str(self.exit_obj)
            self.exit_obj.clearSyms ()
        _ += self.footer ()
        return _

class FridaRE:
    ''' Wrapper around frida python API '''

    # Store callback objs
    objs = {}
    
    def __init__ (self, target):
        if target:
            self.session = frida.attach (target)

    @staticmethod
    def register (uid, obj):
        FridaRE.objs[uid] = obj

    def onMessage (self, message, data):
        # Decode RPC send message
        if message['type'] == 'send':
            # Convert from JSON to python dict
            d = json.loads (message['payload'])
            # Get object ID
            uid = d['id']
            obj = Frida.objs[uid]
            del d['id']
            # Call callback
            resp = obj._callback (d)
            # Send response if bidirectional
            if obj.isBiDir ():
                self.script.post ({'type' : uid, 'payload' : resp})
        else:
            print("[%s] => %s" % (message, data))

        def run (self, obj):
            self.script = self.session.create_script (str (obj))
            self.script.on ('message', self.onMessage)
            self.script.load ()
            print("[!] Ctrl+Z/Ctrl+D to detach\n")
            sys.stdin.read ()
            self.session.detach ()
                
