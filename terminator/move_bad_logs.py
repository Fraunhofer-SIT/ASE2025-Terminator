
import argparse
from dataclasses import dataclass
import datetime
import os
import hashlib
import itertools
import json
import logging
import math
import re
import shutil
import statistics
import subprocess
import tempfile
import time

import binary
import candidates
import drcov
import iopaths
import traces

def main(options):
    output_dir = os.path.abspath(options.output_dir)
    log_dir = os.path.join(output_dir, 'log')
    bad_dir = os.path.join(output_dir, 'bad')

    for log_file_dir in iopaths.subdirs(log_dir):
        needle = os.path.join(log_file_dir, 'covtrace_globalized.bin')
        if not os.path.isfile(needle):
            _, name = os.path.split(log_file_dir)
            iopaths.ensure_dir(bad_dir)
            destination = os.path.join(bad_dir, name)
            print("[*] Moving bad log dir %s to %s" % (name, destination))
            shutil.move(log_file_dir, destination)

# Entry point: parse arguments and call main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=(
        "None"
    ))

    parser.add_argument("--output-dir", required=False, default=None, help="Root of the output directory created by compute_traces.py.")

    def data_type(x):
        if x in ['covtrace', 'trace', 'drcov', 'dbg-covtrace']:
            return x
        else:
            raise Exception("Bad data type")

    parser.add_argument("--data-type", required=False, type=data_type, default='covtrace')

    args = parser.parse_args()

    main(args)
