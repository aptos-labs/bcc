from rust_demangler.rust import RustDemangler

def demangle(inp_str: str):
    robj = RustDemangler()
    return robj.demangle(inp_str)
