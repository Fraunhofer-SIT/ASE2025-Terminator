
from idautils import Segments, Functions
import idaapi
import idc
import ida_kernwin
import ida_pro
import os
import sys
import argparse
import traceback

from ida_bb_list import obtain_bb_list

parser = argparse.ArgumentParser(description='Write the list of basic blocks of a binary to a file.')
parser.add_argument('--log', type=str, required=False, default='ida_pro_log.txt')
parser.add_argument('--out', dest='output', type=str, required=False, default='ida_pro_out.bin')
args = parser.parse_args(idc.ARGV[1:])

if args.log:
    log_file = open(args.log, 'w', encoding='utf-8')
    log = lambda *x: print(*x)
    
else:
    log = print

log("[*] Working dir is %s" % os.getcwd())
log("[*] Log is %s" % args.log)
log("[*] Out is %s" % args.output)

obtain_bb_list(args.output, log)
log_file.close()
ida_pro.qexit(0)
