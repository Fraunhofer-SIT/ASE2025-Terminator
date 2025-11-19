from idautils import *
from idaapi import *
from idc import *
import ida_kernwin

#targetea = 0

out_file_name = ida_kernwin.ask_file(True, 'func_bounds.txt', 'Select output file')

baseaddr = idaapi.get_imagebase()

with open(out_file_name, 'w') as f:
    # The outermost loop can probably be removed
    for segea in Segments():
        for funcea in Functions(segea, get_segm_end(segea)):
            funcName = get_func_name(funcea)
            # That’s pretty cool here! How to compute the “effective address” of my offset of interest, though?
            #func_contains(funcea, targetea)
            for (startea, endea) in Chunks(funcea):
                f.write("%s: %#010x   %#010x   %6d\n" % (funcName, startea - baseaddr, endea - baseaddr, endea - startea))