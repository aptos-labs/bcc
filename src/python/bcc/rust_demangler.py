#! /usr/bin/python3
import re

# Known Rust mangling translations
unescaped ={'SP':'@' , 'BP': '*' , 'RF': '&' , 'LT': '<' , 'GT':'>' , 'LP':'(' , 'RP':')' , 'C':',',
        'u20':' ' , 'u5b':'[', 'u5d':']', 'u7e':'~', 'u7b':'{', 'u7d':'}', 'u27':'\\\\'}

def rust_demangle(inpstr: str) -> str:
    """ Demangle the given string

    Args:
        inpstr (str): String to be demangled
    """
    tmp = inpstr;

    ## Remove Prefix
    inpstr = re.sub("\A\s+", "", inpstr)
    inpstr = re.sub("\A_*ZN\d*_*","", inpstr)

    ## Remove llvm suffix
    if ".llvm." in inpstr:
        inpstr = inpstr[:inpstr.find(".llvm.")]

    ## Remove redundant _
    if inpstr.startswith("_$"):
        inpstr = inpstr[1:]

    inpstr = re.sub("[\d:]_\$", ":$", inpstr)

    ## Translate sequences
    for k in unescaped:
        s = "\$" + k + "\$"
        inpstr = re.sub(s, unescaped[k], inpstr)
    inpstr = re.sub("\.\.", "::", inpstr)
    inpstr = re.sub("\d{2}h[a-f0-9]{16}E\s*$", "", inpstr)

    ## Replace digit sequences with ::
    if re.search("\D\d{1,3}\D", inpstr):
        tmp = inpstr;
        verbose = False
        for mo in re.finditer("(\D)(\d{1,3})(\D)", tmp):
            if not (re.match("u\d{2}\W", mo.group(0)) or mo.group(3) in ">)" or mo.group(2) == '512'):
                #print(f"^^{mo.group(0)} {mo.group(1)} {mo.group(2)} {mo.group(3)}")
                if mo.group(3) == ":":
                    s = mo.group(1) + "::"
                else:
                    s = mo.group(1) + "::" + mo.group(3)
                #print(f"^^{tmp}  ==>> {inpstr}")
                inpstr = re.sub(mo.group(0), s, inpstr)
        #if verbose:
        #    print(f"{tmp}  ==>> {inpstr}")
    #inpstr = re.sub(">\d+", ">::", inpstr)


    #print(f"{tmp}  ==>> {inpstr}")
    return inpstr

def dehash(inpstr: str) -> str:
    return re.sub("::h[a-f0-9]{16}\s*$", "", inpstr)
