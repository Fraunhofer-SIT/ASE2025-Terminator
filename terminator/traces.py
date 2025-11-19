
import iopaths

import bisect
from dataclasses import dataclass
import json
import logging
import numpy as np
import os
import re
import tqdm
from typing import Any, Callable, Dict, List, Optional

@dataclass
class OffsetTrace:
    offsets: List[int]
    module_ids: List[int]
    n: int
    module_table: Dict[int, Dict[str, Any]]

@dataclass
class TimedOffsetTrace:
    offsets: List[int]
    module_ids: List[int]
    times: List[int]
    n: int
    module_table: Dict[int, Dict[str, Any]]

@dataclass
class NewTrace:
    offsets: List[int]
    module_ids: List[int]
    times: List[int]
    sizes: List[int]
    n: int
    module_table: Dict[int, Dict[str, Any]]

@dataclass
class DbgCovTrace:
    offsets: List[int]
    file_offsets: List[int]
    module_ids: List[int]
    thread_ids: List[int]
    times: List[int]
    sizes: List[int]
    n: int
    module_table: Dict[int, Dict[str, Any]]

@dataclass
class AbsoluteTrace:
    trace : List[int]

@dataclass
class TimedAbsoluteTrace:
    times : List[int]
    trace : List[int]

@dataclass
class ThreadLifeTime:
    lifetime : int
    resolution : int

def read_trace(filename):
    return AbsoluteTrace(np.fromfile(filename, dtype=np.uint64).ravel())

def write_trace(filename, trace):
    trace.tofile(filename)

def load_timed_trace_in(dir_path):
    path = locate_timed_trace(dir_path)
    if path is None:
        raise Exception("Could not locate timed trace in %s" % dirpath)

    return read_timed_trace(path)

def locate_timed_trace(dir_path):
    return iopaths.find_file_by_pattern(dir_path, '\d+_thread_trace_\d+\\.bin')

def locate_timed_trace_ex(dir_path):
    pattern = '(\d+)_thread_trace_(\d+)\\.bin'

    path = iopaths.find_file_by_pattern(dir_path, pattern)
    if path is None:
        return None

    _, name = os.path.split(path)
    repattern = re.compile(pattern)
    match = repattern.match(name)
    if not match:
        raise Exception("Unexpected")

    return path, int(match.group(1)), int(match.group(2))

def read_timed_trace(filename) -> TimedAbsoluteTrace:
    logging.debug("Loading timed trace from %s" % filename)

    data = np.fromfile(filename, dtype=np.uint64)
    data_2_rows = np.reshape(data, (len(data) // 2, 2)).T

    return TimedAbsoluteTrace(data_2_rows[0,:].ravel(), data_2_rows[1,:].ravel())

def write_timed_trace(filename, timed_trace):
    # Each row consists of (time_i, trace_i). I wrote that down successfully at 
    # the first attempt (not).
    data = np.reshape(np.transpose(np.stack([timed_trace.times, timed_trace.trace])), (len(timed_trace.times), 2))
    data.tofile(filename)

def read_new_trace_from(dirpath) -> NewTrace:
    trace_path = iopaths.find_file_by_pattern(dirpath, 'covtrace_globalized.bin')
    mod_tab_path = iopaths.find_file_by_pattern(dirpath, 'covtrace_globalized_modtab.json')

    if trace_path is None or mod_tab_path is None:
        raise Exception("Not found: %s" % dirpath)

    with open(mod_tab_path, 'r') as file:
        content = file.read()
    mod_tab = json.loads(content)

    dt = np.dtype([('module_id', np.uint32), ('offset', np.uint32), ('size', np.uint32), ('time', np.int64)])
    data = np.fromfile(trace_path, dtype=dt)
    trace = NewTrace(data['offset'], data['module_id'], data['time'], data['size'], len(data['offset']), mod_tab)

    return trace

def read_dbgcov_trace_from(dirpath, only_first_thread=True) -> NewTrace:
    trace_path = iopaths.find_file_by_pattern(dirpath, 'covtrace_globalized.bin')
    mod_tab_path = iopaths.find_file_by_pattern(dirpath, 'covtrace_globalized_modtab.json')

    if trace_path is None or mod_tab_path is None:
        raise Exception("Not found: %s" % dirpath)

    with open(mod_tab_path, 'r') as file:
        content = file.read()
    mod_tab = json.loads(content)

    dt = np.dtype([('module_id', np.uint32), ('offset', np.uint32), ('file_offset', np.uint32), ('size', np.uint32), ('time', np.uint64), ('thread_id', np.uint32), ])
    data = np.fromfile(trace_path, dtype=dt)
    
    #trace = DbgCovTrace(data['offset'], data['file_offset'], data['module_id'], data['thread_id'], data['time'], data['size'], len(data['offset']), mod_tab)

    if only_first_thread:
        logging.warning("Filtering trace: only entries from first thread %d survive!" % data['thread_id'][0])
        c = data['thread_id'] == data['thread_id'][0]
    else:
        # A boolean array of True values with the same size as data['thread_id']. There is probably 
        # a simpler way to construct this.
        # c = data['thread_id'] >= 0 or data['thread_id'] <= 0
        c = np.ones_like(data['thread_id'], dtype=bool)
    
    trace = DbgCovTrace(data['offset'][c], data['file_offset'][c], data['module_id'][c], data['thread_id'][c], data['time'][c], data['size'][c], len(data['offset'][c]), mod_tab)

    return trace

def build_offset_trace(trace: List[int], mod_tab: Dict[int, Dict[str, Any]]):
    n = len(trace)
    offsets = np.zeros(n, dtype=np.uint64)
    module_ids = np.zeros(n, dtype=np.uint64)
    nb_unknown_addr = 0
    typical_unknown_module_id = None

    # Sort modules by address space
    sorted_modules = sorted(
        [(x['start'], x['end'], mod_id) for mod_id, x in mod_tab.items()],
        key=lambda x: x[0]
    )

    # sorted_modules_without_gap = []
    # for x, y in zip(sorted_modules[0:-2], sorted_modules[1:]):
    #     sorted_modules_without_gap.append(x)
    #     if x[1] + 1 < y[0]:
    #         sorted_modules_without_gap.append((x[1] + 1, y[0] - 1, typical_unknown_module_id))

    # # Prepend unkonwn module
    # if sorted_modules_without_gap[0][0] > 0:
    #     sorted_modules_without_gap.insert(0, (0, sorted_modules_without_gap[0][0] - 1, typical_unknown_module_id))

    # # Append unknown module
    # sorted_modules_without_gap.append((sorted_modules_without_gap[-1][1] + 1, sorted_modules_without_gap[-1][1] + 2, typical_unknown_module_id))

    # sorted_starts_without_gap = []
    # for start, end, mod_id in sorted_modules_without_gap:
    #     sorted_starts_without_gap.append(start)

    todo = np.ones(n, dtype=bool)
    for start, end, mid in sorted_modules:
        idx = ((start <= trace) & (trace <= end))
        offsets[idx] = trace[idx] - start
        module_ids[idx] = mid
        todo[idx] = False

    if any(todo):
        logging.warning("There were %d unknown addresses" % np.count_nonzero(todo))
        module_ids[todo] = 0
        offsets[todo] = trace[todo]

    # offsets2 = np.copy(offsets)
    # module_ids2 = np.copy(module_ids)
    # for i in tqdm.tqdm(range(0, n), desc="Translating"):
    #     # mid = None
    #     # start = None
    #     # for mod_id, mod in mod_tab.items():
    #     #     if mod['start'] <= trace[i] <= mod['end']:
    #     #         mid = mod_id
    #     #         start = mod['start']
    #     #         break
        
    #     index = bisect.bisect_left(sorted_starts_without_gap, trace[i])
    #     mid = sorted_modules_without_gap[index - 1][2]
    #     start = sorted_modules_without_gap[index - 1][0]

    #     # if not mid == mid2 or (not mid is None and not start == start2):
    #     #     print(json.dumps(sorted_modules_without_gap, indent=2))
    #     #     print(sorted_starts_without_gap)
    #     #     print("Dis is bad")
    #     #     print(index)
    #     #     print(trace[i])
    #     #     print("%s != %s" % (str(mid), str(mid2)))
    #     #     print("%s != %s" % (str(start), str(start2)))
    #     #     assert(mid == mid2)
    #     #     assert(start == start2)

    #     if mid is None:
    #         #print("Unknown address number %d: %#018x" % (i, trace[i]))
    #         nb_unknown_addr += 1
    #         module_ids[i] = 0
    #         offsets[i] = trace[i]
    #         continue
        
    #     module_ids[i] = mid
    #     offsets[i] = trace[i] - start

    # if nb_unknown_addr > 0:
    #     logging.warning("There were %d unknown addresses" % nb_unknown_addr)

    # if not np.array_equal(offsets, offsets2) or not np.array_equal(module_ids, module_ids2):
    #     print("shi.)")

    # exit(1)

    return OffsetTrace(offsets, module_ids, n, mod_tab)

#def write_offset_trace(directory, trace):
#    np.tofile(trace.offsets, os.path.join(prefix, '_offsets.bin'))
#    np.tofile(trace.module_ids, os.path.join(prefix, '_modids.bin'))

def read_or_build_offset_trace_in(directory, timed=False):
    logging.debug("Reading or building offset trace in %s…" % directory)

    tt_path = locate_timed_trace(directory)
    if tt_path is None:
        tt_path = iopaths.find_file_by_pattern_or_die(directory, '(\d+)_thread_trace_(\d+)_offsets\\.bin')
        #raise Exception("Could not locate timed trace in %s" % directory)

    logging.debug("Timed trace located is %s" % tt_path)

    _, tt_file = os.path.split(tt_path)
    pattern = re.compile('(\d+)_thread_trace_(\d+)\\.bin')
    match = pattern.match(tt_file)
    if not match:
        pattern = re.compile('(\d+)_thread_trace_(\d+)_offsets\\.bin')
        match = pattern.match(tt_file)
        if not match:
            raise Exception("Unexpected non-match for %s in %s" % (tt_file, directory))

    path_offsets = os.path.join(directory, '%s_thread_trace_%s_offsets.bin' % (match.group(1), match.group(2)))
    path_modids = os.path.join(directory, '%s_thread_trace_%s_modids.bin' % (match.group(1), match.group(2)))
    path_times = os.path.join(directory, '%s_thread_trace_%s_times.bin' % (match.group(1), match.group(2)))
    mod_tab = load_custom_module_table_in(directory, 'trace')

    if os.path.isfile(path_offsets) and os.path.isfile(path_modids):
        logging.debug("Found offset and mod files %s and %s" % (path_offsets, path_modids))

        offsets = np.fromfile(path_offsets, dtype=np.uint64)
        modids = np.fromfile(path_modids, dtype=np.uint64)
        trace = OffsetTrace(offsets, modids, len(offsets), mod_tab)
        
        if timed:
            if os.path.isfile(path_times):
                times = np.fromfile(path_times, dtype=np.uint64)
            else:
                timed_trace = read_timed_trace(tt_path)
                times = timed_trace.times
                times.tofile(path_times)

            trace = TimedOffsetTrace(offsets, modids, times, len(offsets), mod_tab)
    else:
        timed_trace = read_timed_trace(tt_path)
        trace = build_offset_trace(timed_trace.trace, mod_tab)
        trace.offsets.tofile(path_offsets)
        trace.module_ids.tofile(path_modids)

        if timed:
            times = timed_trace.times
            times.tofile(path_times)
            trace = TimedOffsetTrace(trace.offsets, trace.module_ids, times, len(trace.offsets), mod_tab)

    if len(trace.offsets) != len(trace.module_ids):
        logging.error("read_or_build_offset_trace_in: Module IDs len %d != %d offsets len" % (len(trace.module_ids), len(trace.offsets)))
    if timed and len(trace.offsets) != len(trace.times):
        logging.error("read_or_build_offset_trace_in: Times len %d != %d offsets len" % (len(trace.times), len(trace.offsets)))

    return trace

def read_or_build_globalized_offset_trace_in(directory, global_mod_tab, local_to_global_mod_id, timed=False):
    logging.debug("Reading or building globalized offset trace in %s…" % directory)

    trace = read_or_build_offset_trace_in(directory, timed)

    tt_path = iopaths.find_file_by_pattern(directory, '(\d+)_thread_trace_(\d+)_global_modids\\.bin')
    if not tt_path is None:
        logging.debug("Globalized trace located is %s" % tt_path)
        global_modids = np.fromfile(tt_path, dtype=np.uint64)
        if timed:
            trace = TimedOffsetTrace(trace.offsets, global_modids, trace.times, len(trace.offsets), global_mod_tab)
        else:
            trace = OffsetTrace(trace.offsets, global_modids, len(trace.offsets), global_mod_tab)

        if len(trace.offsets) != len(global_modids):
            logging.error("read_or_build_globalized_offset_trace_in (1): Global module IDs len %d != %d offsets len" % (len(global_modids), len(trace.offsets)))
        if timed and len(trace.offsets) != len(trace.times):
            logging.error("read_or_build_globalized_offset_trace_in (1): Times len %d != %d offsets len" % (len(trace.times), len(trace.offsets)))

        return trace

    tt_path = iopaths.find_file_by_pattern_or_die(directory, '(\d+)_thread_trace_(\d+)_offsets\\.bin')
    _, tt_file = os.path.split(tt_path)
    pattern = re.compile('(\d+)_thread_trace_(\d+)_offsets\\.bin')
    match = pattern.match(tt_file)
    if not match:
        raise Exception("Unexpected non-match for %s in %s" % (tt_file, directory))

    path_global_modids = os.path.join(directory, '%s_thread_trace_%s_global_modids.bin' % (match.group(1), match.group(2)))

    # Now translate

    global_modids = np.copy(trace.module_ids)
    for k, v in local_to_global_mod_id.items():
        global_modids[trace.module_ids == k] = v
    #np.array([local_to_global_mod_id[x] for x in trace.module_ids], dtype=np.uint64)
    global_modids.tofile(path_global_modids)

    if len(trace.offsets) != len(global_modids):
        logging.error("read_or_build_globalized_offset_trace_in (2): Global module IDs len %d != %d offsets len" % (len(global_modids), len(trace.offsets)))
    if timed and len(trace.offsets) != len(trace.times):
        logging.error("read_or_build_globalized_offset_trace_in (2): Times len %d != %d offsets len" % (len(trace.times), len(trace.offsets)))

    if timed:
        return TimedOffsetTrace(trace.offsets, global_modids, trace.times, len(trace.offsets), global_mod_tab)
    else:
        return OffsetTrace(trace.offsets, global_modids, len(trace.offsets), global_mod_tab)

def write_timed_offset_trace(trace, directory, client_id=0, thread_id=0):
    path_offsets = os.path.join(directory, '%s_thread_trace_%s_offsets.bin' % (str(client_id), str(thread_id)))
    path_modids = os.path.join(directory, '%s_thread_trace_%s_modids.bin' % (str(client_id), str(thread_id)))
    path_times = os.path.join(directory, '%s_thread_trace_%s_times.bin' % (str(client_id), str(thread_id)))
    path_modtab = os.path.join(directory, '%s_trace_modules.txt' % (str(client_id)))

    trace.offsets.tofile(path_offsets)
    trace.module_ids.tofile(path_modids)
    trace.times.tofile(path_times)
    write_custom_module_table(trace.module_table, directory, client_id, 'trace')

def write_offset_trace(trace, directory, client_id=0, thread_id=0):
    path_offsets = os.path.join(directory, '%s_thread_trace_%s_offsets.bin' % (str(client_id), str(thread_id)))
    path_modids = os.path.join(directory, '%s_thread_trace_%s_modids.bin' % (str(client_id), str(thread_id)))
    path_modtab = os.path.join(directory, '%s_trace_modules.txt' % (str(client_id)))

    trace.offsets.tofile(path_offsets)
    trace.module_ids.tofile(path_modids)
    write_custom_module_table(trace.module_table, directory, client_id, 'trace')

def locate_thread_life_time(dir_path):
    return iopaths.find_file_by_pattern('\d+_threads\\.txt')

def read_thread_life_time(file_path):
    with open(file_path) as file:
        data = file.read()

    pattern1 = re.compile('Resolution is 1/(\d+)')
    pattern = re.compile('\s*\d+\s*from\s*\d+ to\s*\d+ for\s*(\d+)')

    for line in data.split('\n'):
        match1 = pattern1.match(line)
        if not match1 is None:
            reso = int(match1.group(1))
            continue

        match = pattern.match(line)
        if not match is None:
            life = int(match.group(1))
            continue

    return ThreadLifeTime(life, reso)

def load_custom_module_table_in(directory, substr):
    path = locate_custom_module_table(directory, substr)
    if path is None:
        raise Exception('Could not locate custom module table with substring %s in %s' % (substr, directory))

    return read_custom_module_table(path);

def locate_custom_module_table(directory, substr):
    return iopaths.find_file_by_pattern(directory, '\d+_%s_modules\.txt' % substr)

def read_custom_module_table(path):
    logging.debug('Loading custom module table from %s' % path)

    with open(path, 'r') as file:
        log = file.read()

    mod_table = {}

    for line in log.split('\n'):
        if not line:
            continue

        columns = line.split('\t')
        if not len(columns) == 4:
            continue

        mod_id = len(mod_table) + 1
        start = int(columns[0], 16)
        tracked = True if columns[1].lower() == 'true' else False
        end = int(columns[2], 16)
        path = columns[3]

        mod_table[mod_id] = {
            'id': mod_id,
            'start': start,
            'tracked': tracked,
            'end': end,
            'path': path
        }

    return mod_table

def read_custom_module_table_with_id(path):
    logging.debug('Loading custom module table with ID from %s' % path)

    with open(path, 'r') as file:
        log = file.read()

    mod_table = {}

    for line in log.split('\n'):
        if not line:
            continue

        columns = line.split('\t')
        if not len(columns) == 5:
            continue

        mod_id = int(columns[0])
        start = int(columns[1], 16)
        tracked = True if columns[2].lower() == 'true' else False
        end = int(columns[3], 16)
        path = columns[4]

        mod_table[mod_id] = {
            'id': mod_id,
            'start': start,
            'tracked': tracked,
            'end': end,
            'path': path
        }

    return mod_table

def write_custom_module_table(mod_table, directory, client_id, substr):
    path = os.path.join(directory, '%s_%s_modules.txt' % (str(client_id), substr))

    with open(path, 'w') as file:
        mod_ids = sorted(mod_table.keys())
        for mod_id in mod_ids:
            mod = mod_table[mod_id]
            # 7ff6f6640000    true    7ff6f697c000    C:\Users\kolvenba\Projekte\xpdf-4.02\builds\build-relwithdebinfo\xpdf-qt\xpdf.exe
            file.write('%x\t%s\t%x\t%s\n' % (mod['start'], str(mod['tracked']).lower(), mod['end'], mod['path']))

def lookup_module(mod_table, predicate, default=None):
    for mod_id, mod in mod_table.items():
        if predicate(mod):
            return mod_id

    return default
