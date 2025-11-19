
import logging
import os
import re
import subprocess
import psutil
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

@dataclass
class ParseResult:
    mod_table : Dict[int, Dict[str, Any]]
    bb_table : Dict[int, Dict[str, Any]]
    tail_map : Dict[int, int]
    target_mod_id : int

@dataclass
class MapToTailResult:
    trace : List[int]
    unmapped : bool

def load_from(directory : str) -> ParseResult:
    path = locate_in(directory)
    if path is None:
        raise Exception("Couldn’t load drcov from %s" % directory)

    return parse(path)

def parse(log_file_path : str) -> ParseResult:
    """Parse a single drcov log file, extracting module and BB table as well as 
       a mapping between each BB and its smallest contained BB"""

    logging.debug('Loading drcov log file from %s' % log_file_path)

    with open(log_file_path, 'r') as log_file:
        log = log_file.read()

    pattern = re.compile('^drcov\.(.+)\.(\d+)\.(\d+)\.proc\.log$')
    _, log_file_name = os.path.split(log_file_path)
    match = pattern.match(log_file_name)
    if not match:
        raise Exception('Cannot obtain target filename from log filename %s.' % log_file_name)

    target_file_name = match.group(1)
    logging.debug('Target filename appears to be %s' % target_file_name)

    verify_log_file_assumptions(log)
    module_table = obtain_module_table_from_log(log, target_file_name)
    bb_table = obtain_bb_table_from_log(module_table, log)
    tm = tail_map(bb_table)

    target_mod_id = next((mod_id for mod_id in module_table if target_file_name in module_table[mod_id]['path']), None)

    return ParseResult(module_table, bb_table, tm, target_mod_id)

def locate_in(directory):
    """Find a drcov log file that fits to the target filename"""

    pattern = re.compile('drcov(.+)\\.log')
    candidate = None

    for filename in os.listdir(directory):
        if pattern.match(filename) != None:
            if candidate == None:
                candidate = filename
            else:
                logging.warning("There is more than one drcov log file. I don’t know which to select.")
                break

    if candidate is None:
        return None

    return os.path.join(directory, candidate)

def map_to_tail(tail_map : Dict[int, int], trace : List[int]) -> MapToTailResult:
    do_unmapped_exist = False
    new_trace = []

    for x in trace:
        if not x in tail_map:
            do_unmapped_exist = True
        else:
            new_trace = new_trace + tail_map[x]

    return MapToTailResult(new_trace, do_unmapped_exist)

# The rest is internal

def verify_log_file_assumptions(log):
    """Verify our assumptions on the log file format"""

    # if -1 == log[0:200].find('DRCOV VERSION: 2\nDRCOV FLAVOR: drcov\nModule Table: version 4'):
    #     print("[--] Error!")
    #     print(log[0:200])
    #     exit(1)

    # if -1 == log[0:200].find('Columns: id, containing_id, start, end, entry, offset, checksum, timestamp, path'):
    #     print("[--] Error!")
    #     print(log[0:200])
    #     exit(1)

    #assert -1 != log[0:200].find('DRCOV VERSION: 2\nDRCOV FLAVOR: drcov\nModule Table: version 4')
    #assert -1 != log[0:200].find('Columns: id, containing_id, start, end, entry, offset, checksum, timestamp, path')
    assert -1 != log[0:200].find('DRCOV VERSION: 3\nDRCOV FLAVOR: drcov\nModule Table: version 5')
    assert -1 != log[0:200].find('Columns: id, containing_id, start, end, entry, offset, preferred_base, checksum, timestamp, path')

def obtain_module_table_from_log(log, target_filename):
    """Read the module table from a log string"""

    # .index raises an exception if the string is not found.
    position_of_module_table_start = log.index("path") + 5
    position_of_module_table_end = log.index("BB Table:") - 1

    raw_module_table = log[position_of_module_table_start : position_of_module_table_end]
    module_table = {}

    for raw_module_line in raw_module_table.split('\n'):
        module_id, module = parse_module_line(raw_module_line)
        module_table[module_id] = module

    return module_table

def parse_module_line(raw_module_line):
    """Read module information from a string"""

    columns = [x.strip() for x in raw_module_line.split(',')]

    module_id = int(columns[0])
    containing_id = int(columns[1])
    start = int(columns[2], 16)
    end = int(columns[3], 16)
    entry = int(columns[4], 16)
    offset = int(columns[5], 16)
    #preferred_base = int(columns[6], 16)
    checksum = int(columns[7], 16)
    timestamp = int(columns[8], 16)
    path = columns[9]

    module = {
        'module_id': module_id,
        'containing_id': containing_id,
        'start': start,
        'end': end,
        'entry': entry,
        'offset': offset,
        'checksum': checksum,
        'timestamp': timestamp,
        'path': path,
        'nb_blocks': 0,
    }

    return module_id, module

def obtain_bb_table_from_log(module_table, log):
    """Read the basic block table from a log string"""

    bb_table_indicator = 'module id, start, size:\n'
    position_of_bb_table_indicator = log.index(bb_table_indicator)
    position_of_bb_table_start = position_of_bb_table_indicator + len(bb_table_indicator)

    raw_bb_table = log[position_of_bb_table_start:]
    bb_table = {}

    pattern = re.compile('module\\[([ \\d]+)\\]: (0x[0-9a-f]+),\\s*(\\d+)')

    mod_ix = {}
    unknown_modules = set()

    for line in raw_bb_table.split('\n'):
        match = pattern.match(line)

        if match != None:
            module_id = int(match.group(1))

            if not module_id in module_table:
                if not module_id in unknown_modules:
                    if module_id == 65535:
                        # This happens fairly often.
                        logging.debug("Unknown module %d" % module_id)
                    else:
                        logging.warning("Unknown module %d" % module_id)

                    unknown_modules.add(module_id)
                continue

            offset = int(match.group(2), 16)
            size = int(match.group(3))
            module_start = module_table[module_id]['start']
            address = module_start + offset
            end = offset + size - 1
            id = (module_table[module_id]['path'], offset)

            if id in bb_table:
                bb_table[id]['count'] += 1
                if bb_table[id]['end'] != end:
                    logging.warning('Basic block %#018x in module %d changed end from %#018x to %#018x' % (offset, module_id, bb_table[id]['end'], end))

                continue

            index = mod_ix[module_id] if module_id in mod_ix else 0
            mod_ix[module_id] = index + 1

            # The global index is the actual premiere order, while index is the 
            # premiere order relative to the module. Each module has its own 
            # premiere orders starting from 1.
            global_idx = len(bb_table)

            bb_table[id] = {
                'id': id,
                'index': index,
                'global_index': global_idx,
                'address': address,
                'count': 1,
                'module_id': module_id,
                'offset': offset,
                'size': size,
                'end': end,
            }

    for module_id, number in mod_ix.items():
        if module_id in module_table:
            module_table[module_id]['nb_blocks'] = number

    return bb_table

def tail_map_offsets(module_table, bb_table):
    tm = tail_map(bb_table)
    tmo = {}
    orig_bb_table = {bb['address']: bb for _, bb in bb_table.itmes()}

    for abs1, abs2 in tm.items():
        mod1 = module_table[orig_bb_table[abs1]]
        off1 = orig_bb_table[abs1]['offset']
        id1 = (mod1['path'], off1)

        mod2 = module_table[orig_bb_table[abs2]]
        off2 = orig_bb_table[abs2]['offset']
        id2 = (mod2['path'], off2)

        tmo[id1] = id2

    return tmo

def tail_map(bb_table):
    """Map each basic block to the smallest basic block it contains, which might be itself"""

    ordered_bb_list = sorted(bb_table.values(), key=lambda x: x['address']);
    list_of_adjacent_bbs = zip(ordered_bb_list, ordered_bb_list[1:])

    # bb => [bb]
    ancestors_map = {}
    # bb => bb
    smallest_descendant_map = {}

    for tuple_of_adjacent_bbs in list_of_adjacent_bbs:
        bb1 = tuple_of_adjacent_bbs[0]
        bb2 = tuple_of_adjacent_bbs[1]

        smallest_descendant_map[bb1['address']] = bb1['address']
        smallest_descendant_map[bb2['address']] = bb2['address']

        if bb1['module_id'] != bb2['module_id']:
            continue

        if not bb1['address'] in ancestors_map:
            ancestors_map[bb1['address']] = []

        assert(bb1['offset'] <= bb2['offset'])

        if bb1['offset'] <= bb2['offset'] <= bb1['end']:
            if bb2['end'] != bb1['end']:
                logging.debug(
                    "Weird intersection detected in module %d: [%s, %s] and [%s, %s]. This need not be an error; highly optimized code tends to have these intersections." % (
                        bb1['module_id'],
                        hex(bb1['offset']),
                        hex(bb1['end']),
                        hex(bb2['offset']),
                        hex(bb2['end'])
                ))
                pass
            
            # Some were found in ntdll.dll – ignore?
            #assert bb2['end'] == bb1['end'], "Weird cut detected: [%s, %s] and [%s, %s]" % (hex(bb1['offset']), hex(bb1['end']), hex(bb2['offset']), hex(bb2['end']))
            
            ancestors_map[bb2['address']] = ancestors_map[bb1['address']] + [bb1]

            for ancestor in ancestors_map[bb2['address']]:
                smallest_descendant_map[ancestor['address']] = bb2['address']

    return smallest_descendant_map

def lookup_offset(bb_table, offset):
    for abs_addr, bb in bb_table.items():
        if bb['offset'] <= offset <= bb['offset'] + bb['size']:
            return bb

    return None

def lookup_module(mod_table, predicate, default=None):
    for mod_id, mod in mod_table.items():
        if predicate(mod):
            return mod_id

    return default

def run_drcov(dynamorio_dir, working_dir, target_path, input_path, timeout_delay):
    """Executes the target with DynamoRIO on a specified input file"""

    target_dir, target_filename = os.path.split(target_path)
    # Create temporary directory

    if working_dir is None:
        working_dir = target_dir

    with tempfile.TemporaryDirectory() as log_dir:

        #
        # Step 1: Run drrun in a new process (this script does not wait for the 
        # process to terminate)
        #

        target_dir, target_name = os.path.split(target_path)
        drrun_invoke_args = [
            os.path.join(dynamorio_dir, "drrun.exe"),
            "-t", "drcov",
            "-logdir", log_dir,
            "-dump_text",
            "--", target_path, input_path
        ]

        cmd = subprocess.list2cmdline(drrun_invoke_args)
        logging.info("[*] Running drrun with drcov to collect coverage with\n    %s" % cmd)
        process_drrun = subprocess.Popen(
              cmd
            , cwd=working_dir
            , shell=False
        )

        #
        # Step 2: Wait for a user-specified time before terminating. We assume that 
        # all the interesting parsing work by the target process is completed in the
        # meanwhile.
        #

        time.sleep(timeout_delay)
#        if process_drrun.poll() is None:
#            try:
#                process_drrun.wait(timeout_delay)
#                must_kill = False
#            except subprocess.TimeoutExpired:
#                must_kill = True
#                pass
#        else:
#            must_kill = False
        #time.sleep(timeout_delay)
        
        #
        # Step 3: Send a nudge signal to drrun (which is configured to terminute on 
        # such signals, see the command line argument "-nudge_kills" above)
        #

        nudge_invoke_args = [os.path.join(dynamorio_dir, "drconfig.exe"), "-nudge", target_filename, "0", "1"]
        logging.info("[*] Sending a nudge signal to terminate drrun with\n    %s" % subprocess.list2cmdline(nudge_invoke_args))

        # Other than subprocess.Popen, subprocess.Run waits for the process to 
        # finish.
        process_nudge = subprocess.run(
              nudge_invoke_args
            , cwd=working_dir
            , shell=False
        )

        time.sleep(0.5);

        procs = { p.pid: p.info for p in psutil.process_iter(['name']) if target_name in p.info['name'] }

        if process_nudge.returncode != 0:
            logging.warning('Nudge did not work?')

        if len(procs) > 0:
            logging.warning('There is still a process with a name containing %s' %  target_name)

            logging.info("Killing with TASKKILL…")
            subprocess.run("TASKKILL /F /IM " + target_name)

        result = load_from(log_dir)
        return result

def run_drcov_2(dynamorio_dir, working_dir, target_path, input_path, timeout_delay):
    """Executes the target with DynamoRIO on a specified input file"""

    target_dir, target_filename = os.path.split(target_path)
    
    if working_dir is None:
        working_dir = target_dir

    with tempfile.TemporaryDirectory() as log_dir:

        #
        # Step 1: Run drrun in a new process (this script does not wait for the 
        # process to terminate)
        #

        target_dir, target_name = os.path.split(target_path)
        drrun_invoke_args = [
            os.path.join(dynamorio_dir, "drrun.exe"),
            "-t", "drcov",
            "-logdir", log_dir,
            "-dump_text",
            "--", target_path, input_path
        ]

        cmd = subprocess.list2cmdline(drrun_invoke_args)
        logging.debug("Running drrun with drcov to collect coverage with\n    %s" % cmd)
        process_drrun = subprocess.Popen(
              cmd
            , cwd=working_dir
            , shell=False
        )

        #
        # Step 2: Wait for a user-specified time before terminating. We assume that 
        # all the interesting parsing work by the target process is completed in the
        # meanwhile.
        #

        try:
            process_drrun.wait(timeout_delay)
            logging.debug("drrun terminated before timeout")
            must_kill = False
        except subprocess.TimeoutExpired:
            logging.debug("drrun DID NOT terminate before timeout")
            must_kill = True
            pass
        
        #
        # Step 3: Send a nudge signal to drrun (which is configured to terminute on 
        # such signals, see the command line argument "-nudge_kills" above)
        #

        if must_kill:
            nudge_invoke_args = [os.path.join(dynamorio_dir, "drconfig.exe"), "-nudge", target_filename, "0", "1"]
            logging.debug("Sending a nudge signal to terminate drrun with\n    %s" % subprocess.list2cmdline(nudge_invoke_args))

            # Other than subprocess.Popen, subprocess.Run waits for the process to 
            # finish.
            process_nudge = subprocess.run(
                  nudge_invoke_args
                , cwd=working_dir
                , shell=False
            )

            procs = { p.pid: p.info for p in psutil.process_iter(['name']) if target_name in p.info['name'] }

            if process_nudge.returncode != 0:
                logging.warning('Nudge did not work?')

            if len(procs) > 0:
                logging.warning('There is still a process with a name containing %s' %  target_name)

                logging.debug("Killing with TASKKILL…")
                subprocess.run("TASKKILL /F /IM " + target_name)

        # Sleep so that drcov can write the file...
        for i in range(0, 5):
            try:
                result = load_from(log_dir)
                return result
            except:
                sleep(0.5)

        result = load_from(log_dir)
        return result
