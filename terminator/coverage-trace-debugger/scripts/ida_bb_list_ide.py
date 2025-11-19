from idautils import Segments, Functions
import idaapi
import idc
import ida_kernwin
import ida_pro
import sys
from ida_bb_list import obtain_bb_list

out_file_name = ida_kernwin.ask_file(True, 'bb_list.txt', 'Select output file')

obtain_bb_list(out_file_name)
