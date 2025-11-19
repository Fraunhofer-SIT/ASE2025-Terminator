
#import cfg
import drcov
import iopaths
import traces
#import visualization

import collections
import copy
import dataclasses
from dataclasses import dataclass
import functools
import hashlib
import itertools
import json
import logging
import math
import matplotlib.pyplot as plt
import numpy as np
import os
import re
import statistics
import subprocess
import time
import tqdm
import networkx as nx
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

@dataclass(frozen=True)
class Candidate:
    module_path: str
    offset: int
    index_premieres_abs: Tuple[int, ...]
    index_premieres_rel: Tuple[int, ...]
    coverage_premieres: Tuple[int, ...]

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        if self.module_path == other.module_path and self.offset == other.offset:
            return True

        return False

@dataclass(frozen=True, eq=True)
class BasicBlock:
    module_path: str
    offset: int
    info: Dict[str, Any]

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        if self.module_path == other.module_path and self.offset == other.offset:
            return True

        return False
    
    def __hash__(self):
        return hash((self.module_path, self.offset))

def blocks_to_str(blocks: List[BasicBlock]):
    scand = sorted(blocks, key=lambda x: x.module_path)
    sgroup = itertools.groupby(scand, lambda x: x.module_path)

    name = ''
    for k, g in sgroup:
        _, mname = os.path.split(k)
        name += '_' + mname
        
        for v in sorted([x.offset for x in g]):
            name += '_%08x' % v

    name = name[1:]

    return name

@dataclass(frozen=True, eq=True)
class Solution:
    name: str
    blocks: Set[BasicBlock]
    info: Dict[str, Any]

    def __str__(self):
        sblock = sorted(blocks, key=lambda x: x.module_path)
        sgroup = itertools.groupby(sblock, lambda x: x.module_path)

        name = ''
        for k, g in sgroup:
            _, mname = os.path.split(k)
            name += '_' + mname
            
            for v in sorted([x.offset for x in g]):
                name += '_%08x' % v

        return self.name + name

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        if self.name == other.name and self.blocks == other.blocks:
            return True

        return False

    def __hash__(self):
        return hash((self.name, self.blocks))

    def blocks_to_str(self):
        return list(blocks_to_str(self.blocks))

def effective_blocks_name(blocks):
    s1 = blocks_to_str(blocks)
    s2 = s1.encode('utf-8')
    hash256 = hashlib.sha256(s2).hexdigest()

    return str(len(blocks)) + '_' + hash256[0:16]

def effective_solution_name(solution):
    return effective_blocks_name(solution.blocks)

def load_solution(path):
    with open(path, 'r') as file:
        content = json.loads(file.read())

    if content == None:
        return None

    solution = read_solution(content)

    return solution

def write_solution(path, solution):
    with open(path, 'w') as file:
        content = json.dumps(solution, cls=MyJSONEncoder, indent=2)
        file.write(content)

def read_solution(content):
    solution = Solution(
        content['name'],
        frozenset([BasicBlock(x['module_path'], x['offset'], x['info']) for x in content['blocks']]),
        content['info'],
    )

    return solution

class MyJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set) or isinstance(obj, frozenset):
            return list(obj)
        elif isinstance(obj, Candidate):
            return {
                'module_path': obj.module_path,
                'offset': '%#010x' % obj.offset,
            }
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif dataclasses.is_dataclass(obj):
            return dataclasses.asdict(obj)

        return json.JSONEncoder.default(self, obj)

#--------------------------------------------------------------------------------
#
# Last discovered
#
#--------------------------------------------------------------------------------

def last_discovered(output_path, min_size):

    log_dir_path = os.path.join(output_path, "log")
    
    # Map trace path to a single candidate basic block absolute address
    candidates = {}

    # Maps trace path to BB table
    basic_blocks = {}

    mod_table = None

    # For each trace, collect the basic block discovered last.
    for name in os.listdir(log_dir_path):
        path = os.path.join(log_dir_path, name)

        if not os.path.isdir(path):
            continue

        drcov_log = drcov.obtain_log_path(path)
        if drcov_log is None:
            logging.error("No drcov log file found in %s" % path)
            continue

        result = drcov.parse(drcov_log)
        mod_table = result.mod_table
        logging.debug("Target module ID is %d, path is %s." % (result.target_mod_id, result.mod_table[result.target_mod_id]['path']))

        if len(result.bb_table) == 0:
            logging.error("Empty basic block table for in %s" % drcov_log)
            continue

        # Look up the module_id of our target so that we can focus on the basic 
        # blocks of our target.
        module_basic_blocks = {
            bb_abs_addr: info
            for (bb_abs_addr, info) in result.bb_table.items()
            if info['module_id'] == result.target_mod_id
            and info['size'] >= min_size
        }

        basic_blocks[name] = module_basic_blocks;

        latest = max(module_basic_blocks.items(), key=lambda x: x[1]['index'])

        if not latest[0] in candidates:
            candidates[latest[0]] = latest[1]

    if len(candidates) == 0:
        logging.error(
            "No candidate found in %s. This means there were no basic blocks from the target module and indicates an error in the data. Maybe you mispelled the target?"
            % output_path
        )

        return None

    if len(candidates) > 1:
        logging.warning("Expected single candidate, found %d" % len(candidates))

        # Now check whether at least all candidates are common and discovered 
        # relatively lately.

        good_candidates = {}
        for abs_addr, info in candidates.items():
            for name, module_basic_blocks in basic_blocks.items():
                if abs_addr in module_basic_blocks:
                    index = module_basic_blocks[abs_addr]['index']
                    logging.debug("Candidate %#018x has position %d / %d and count %d in %s." % (abs_addr, index, len(module_basic_blocks) - 1, info['count'], name))
                    good_candidates[abs_addr] = module_basic_blocks[abs_addr]
                else:
                    logging.debug("Candidate %#018x not found in %s." % (abs_addr, name))

        if len(good_candidates) >= 1:
            logging.debug("There are %d good candidates:" % len(good_candidates))
            logging.debug("    %s" % str(['%#010x' % x['offset'] for _, x in good_candidates.items()]))

        candidates = good_candidates

    # That's the Python special way of returning an element of a set.
    for k, v in candidates.items():
        logging.info("The last-discovered candidate is %#010x" % v['offset'])
        return v['offset']

#--------------------------------------------------------------------------------
#
# Coverage cap
#
#--------------------------------------------------------------------------------

def coverage_cap(output_path: str, min_size, cap_tol = 0.95, only_from_exe = False, filter = None):
    if filter is None or filter == 'overall':
        filter = lambda x: True
        filter_name = 'overall'

    log_dir_path = os.path.join(output_path, 'log')
    all_virgins_positions = {}

    # A set of basic blocks that are no virgins
    disqualified = set()

    global_mod_ids = {}
    global_mod_tab = {}
    global_mods = {}
    local_to_global_mod_ids = {}

    nb_traces = 0
    nb_traces_max = 0

    #———————————————————————————————————————————————————————————————————————————
    #
    # Compute the local-to-global module mapping.
    #
    # The order in which modules are loaded is not guaranteed in Windows. 
    # That’s why every trace might have different IDs for the same modules. In 
    # order to compare the traces, we have to globalize the module IDs.
    #
    #———————————————————————————————————————————————————————————————————————————

    path_mappings = os.path.join(log_dir_path, 'mapping.json')
    if os.path.isfile(path_mappings):
        with open(path_mappings, 'r') as file:
            content = file.read()
        mappings = json.loads(content)
        content = None
        global_mod_ids = mappings['global_mod_ids']
        global_mod_tab = { int(k): v for k, v in mappings['global_mod_tab'].items() }
        global_mods = { int(k): v for k, v in mappings['global_mods'].items() }
        local_to_global_mod_ids = { k: { int(kk): vv for kk, vv in v.items() } for k, v in mappings['local_to_global_mod_ids'].items()}
        mappings = None
    else:
        for trace_index, dirpath in enumerate(iopaths.subdirs(log_dir_path)):
            mod_tab = traces.load_custom_module_table_in(dirpath, 'trace')

            local_to_global_mod_id = {}
            for mid, info in mod_tab.items():
                if not info['path'] in global_mod_ids:
                    gmid = len(global_mod_ids) + 1
                    global_mod_ids[info['path']] = {
                        'id': gmid,
                        'path': info['path']
                    }
                    global_mod_tab[gmid] = {
                        'id': gmid,
                        'path': info['path']
                    }

                    global_mods[gmid] = info['path']

                local_to_global_mod_id[mid] = global_mod_ids[info['path']]['id']
                local_to_global_mod_id[0] = 0

            local_to_global_mod_ids[dirpath] = local_to_global_mod_id

        mappings = {
            'global_mod_ids': global_mod_ids,
            'global_mod_tab': global_mod_tab,
            'global_mods': global_mods,
            'local_to_global_mod_ids': local_to_global_mod_ids,
        }
        content = json.dumps(mappings, cls=MyJSONEncoder)
        with open(path_mappings, 'w') as file:
            file.write(content)
        content = None
        mappings = None

    global_mod_tab[0] = {
        'id': 0,
        'path': None,
    }

    #———————————————————————————————————————————————————————————————————————————
    #
    # Compute the globalized traces.
    #
    #———————————————————————————————————————————————————————————————————————————
    
    for trace_index, dirpath in enumerate(iopaths.subdirs(log_dir_path)):
        trace = traces.read_or_build_globalized_offset_trace_in(dirpath, global_mod_tab, local_to_global_mod_ids[dirpath])
        trace = None

    #———————————————————————————————————————————————————————————————————————————
    #
    # Compute the total intersection of all traces.
    #
    #———————————————————————————————————————————————————————————————————————————

    if filter == 'diff':
        total_intersection_path = os.path.join(log_dir_path, 'intersection.json')
        if os.path.isfile(total_intersection_path):
            with open(total_intersection_path, 'r') as file:
                content = file.read()
            parsed = json.loads(content)
            total_intersection = frozenset([tuple(x) for x in parsed])
            parsed = None
            content = None
        else:
            total_intersection = None
            for trace_index, dirpath in enumerate(iopaths.subdirs(log_dir_path)):
                trace = traces.read_or_build_globalized_offset_trace_in(dirpath, global_mod_tab, local_to_global_mod_ids[dirpath])
                trace_set = set([(x, y) for x, y in zip(trace.module_ids, trace.offsets)])
                if total_intersection is None:
                    total_intersection = trace_set
                else:
                    total_intersection = total_intersection & trace_set
                trace = None
                logging.debug("Total intersection now has %d elements, after an intersection with %d elements" % (len(total_intersection), len(trace_set)))

            content = json.dumps(total_intersection, cls=MyJSONEncoder)
            with open(total_intersection_path, 'w') as file:
                file.write(content)
            content = None
            if total_intersection is None:
                total_intersection = []
                
            total_intersection = frozenset(total_intersection)

        filter = lambda x: not x in total_intersection
        filter_name = 'diff_' + str(cap_tol)
        logging.info("Total intersection has %d elements" % (len(total_intersection)))

        if not total_intersection:
            return None
    else:
        total_intersection = None

    for trace_index, dirpath in enumerate(iopaths.subdirs(log_dir_path)):
        nb_skipped_bbs = 0
        nb_traces_max += 1
        logging.debug('Processing trace no %d: %s…' % (trace_index, dirpath))

        drcov_result = drcov.load_from(dirpath)
        trace = traces.read_or_build_globalized_offset_trace_in(dirpath, global_mod_tab, local_to_global_mod_ids[dirpath])
        graph = read_or_build_coverage_graph(dirpath, trace, filter, filter_name)

        #times = range(0, len(graph))
        #values = [100 * x / graph[-1] for x in graph]
        #plt.figure(figsize=(19.20,10.80))
        #plt.plot(np.append(times, times[-1] + 1), values + [100], color='blue')
        #plt.show()

        cap = next((i for i, x in enumerate(graph) if x >= cap_tol * graph[-1]), None)
        if cap is None:
            raise Exception('Something bad has happened')
            continue

        logging.debug("%.1f%% cap reached at position %d of %d (%.0f%%)" % (100*cap_tol, cap, len(trace.offsets), 100 * cap / len(trace.offsets)))

        #
        # Find first-timers after the coverage cap has been reached.
        #

        # The order does not matter for the prefix, so let’s take a set for much 
        # better performance.
        tuples = zip(trace.module_ids[:cap-1], trace.offsets[:cap-1])
        prefix = set(tuples)
        suffix = zip(trace.module_ids[cap:], trace.offsets[cap:])
        disqualified = disqualified.union(prefix)

        virgins_in_tail = []
        done_virgins = set()
        #for i, x in tqdm.tqdm(enumerate(suffix), desc="Per-trace virgins"):
        for i, x in enumerate(suffix):
            if x not in disqualified and x[0] != 0 and x not in done_virgins:
                virgins_in_tail += [(x, cap + i)]
                done_virgins.add(x)

        logging.debug("There are %d virgins in the tail" % len(virgins_in_tail))

        # Iterate over all virgins found in the tail and collect only those that 
        # are large enough.
        nb_large_virgins = 0
        nb_skipped_bbs_size = 0
        for x, i in virgins_in_tail:
            gmid = x[0]
            offset = x[1]
            y = (gmid, offset)
            
            id = (global_mods[gmid], offset)
            if not id in drcov_result.bb_table:
                nb_skipped_bbs += 1
                continue

            size = drcov_result.bb_table[id]['size']
            if size < min_size:
                nb_skipped_bbs_size += 1
                continue

            if not y in all_virgins_positions:
                all_virgins_positions[y] = []
                
            all_virgins_positions[y] += [(trace_index, i, i / len(trace.offsets), graph[i])]
            nb_large_virgins += 1

        logging.debug("Did not find %d BBs in drcov table" % nb_skipped_bbs)
        logging.debug("There are %d virgins of sufficient size in the tail" % nb_large_virgins)

        if nb_skipped_bbs >= len(virgins_in_tail):
            logging.warning("No virgin in the tail was known to drcov: %s" % dirpath)

        if nb_large_virgins <= 0:
            logging.warning("There are 0 virgins of sufficient size in the tail! Trace: %s" % dirpath)
            return None

        nb_traces += 1

    #
    # Clear virgins that appear too early in another trace
    #

    found = []
    candidates = []

    for x, positions in tqdm.tqdm(all_virgins_positions.items(), desc="Removing non-global virgins"):
        if not x in disqualified:
            if not only_from_exe or global_mods[x[0]].endswith('.exe'):
                if len(positions) == 0:
                    #logging.warning("No positions recorded for address %#010x in module %d" % (x[1], x[0]))
                    continue

                candidates.append({
                    'address': x,
                    'positions': positions,
                    'original_positions': positions,
                    'frequency': len(positions)
                })

    logging.debug("Second pass: only %d candidates remain and %d have been dropped" % (len(candidates), len(all_virgins_positions) - len(candidates)))
    del all_virgins_positions

    if len(candidates) <= 0:
        logging.error("Did not find any candidate")
        return None

    #
    # Find a set cover: find a selection of candidates so that for each trace, 
    # at least one candidate appears as a virgin in the coverage-cap tail.
    #

    covered_traces = set()
    objective = lambda x: statistics.mean([rel for _, _, rel, _ in x['positions']])

    while len(covered_traces) < nb_traces:
        logging.debug("Current number of candidates: %d" % len(candidates))
        # Sort descendingly by multiplying with -elem[1]
        candidates.sort(key=lambda x: -x['frequency'])
        cand = None

        for k, g in itertools.groupby(candidates, lambda x: x['frequency']):
            cur_cands = sorted(list(g), key=objective)
            cand = cur_cands[0]

            # We’re only interested in the first group
            break

        if cand is None:
            logging.warning("No candidate found!")
            return None

        found.append(cand)

        for ti, _, _, _ in cand['positions']:
            covered_traces.add(ti)
        
        logging.debug("Current number of covered traces: %d" % len(covered_traces))

        if len(covered_traces) < nb_traces:
            for x in candidates:
                x['positions'] = [(ti, abs, rel, cov) for ti, abs, rel, cov in x['positions'] if ti not in covered_traces]
                x['frequency'] = len(x['positions'])

            candidates = [x for x in candidates if x['frequency'] > 0]

    def to_basic_block(x):
        gmid = x['address'][0]
        path = global_mods[gmid]
        offset = x['address'][1]
        index_premieres_abs = [y[1] for y in x['positions']]
        index_premieres_rel = [y[2] for y in x['positions']]
        coverage_premieres = [y[3] for y in x['positions']]
        
        return BasicBlock(path, offset, {
            'index_premieres_abs': tuple(index_premieres_abs),
            'index_premieres_rel': tuple(index_premieres_rel),
            'coverage_premieres': tuple(coverage_premieres), 
            }
        )

    blocks = frozenset([to_basic_block(x) for x in found])

    logging.info("For %.1f%% coverage, the minimum-mean virgin set-cover is:" % (100*cap_tol))
    for i, x in enumerate(found):
        mean = statistics.mean([rel for _, _, rel, _ in x['original_positions']])
        logging.info("  %d.) %#010x in module %d (%s) with a mean premiere at position %.0f%%"
            % (i, x['address'][1], x['address'][0], blocks[i].module_path, 100*mean)
        )

    if filter_name == 'overall':
        name = 'trace_overall_%.6f' % cap_tol
    else:
        name = 'trace_differing_%.6f' % cap_tol

    return Solution(name, blocks, {})

def coverage_graph(trace, filter = None):
    if filter is None:
        return coverage_graph_fast(trace)

    seen = set()
    graph = np.zeros(len(trace.offsets), dtype=np.int64)

    #for x in tqdm.tqdm(zip(trace.module_ids, trace.offsets), desc="Coverage graph"):
    if len(trace.module_ids) != len(trace.offsets):
        logging.warning("Module ID len %d != %d offset len" % (len(trace.module_ids), len(trace.offsets)))

    for i, x in enumerate(zip(trace.module_ids, trace.offsets)):
        if not x in seen and filter(x):
            seen.add(x)

        graph[i] = len(seen)

    return graph

# def coverage_graph_antiset(trace, filter = None):
#     if filter is None:
#         return coverage_graph_fast(trace)

#     seen = set()
#     graph = np.zeros(len(trace.offsets), dtype=np.int64)

#     modids = np.isin(trace.module_ids, [x[0] for x in filter])
#     offsets = np.isin(trace.offsets, [x[1] for x in filter])
#     both = ~(modids & offsets)

#     for i, x in enumerate(zip(trace.module_ids, trace.offsets)):
#         if not x in seen:
#             seen.add(x)

def coverage_graph_fast(trace):
    seen = set()
    graph = np.zeros(len(trace.offsets), dtype=np.uint64)

    if len(trace.module_ids) != len(trace.offsets):
        logging.warning("Module ID len %d != %d offset len" % (len(trace.module_ids), len(trace.offsets)))
        
    #for x in tqdm.tqdm(zip(trace.module_ids, trace.offsets), desc="Coverage graph"):
    for i, x in enumerate(zip(trace.module_ids, trace.offsets)):
        if not x in seen:
            seen.add(x)

        graph[i] = len(seen)

    return graph

def read_or_build_coverage_graph(dirpath, trace, filter, filter_name):
    fname = 'coverage_graph_%s.bin' % filter_name
    cgpath = iopaths.find_file_by_pattern(dirpath, fname)
    if not cgpath is None:
        return np.fromfile(cgpath, dtype=np.uint64)

    cgpath = os.path.join(dirpath, fname)
    graph = np.asarray(coverage_graph(trace, filter), dtype=np.int64)
    graph.tofile(cgpath)

    return graph

#--------------------------------------------------------------------------------
#
# Coverage cap covtrace
#
#--------------------------------------------------------------------------------

def coverage_cap_covtrace(output_path: str, min_size, cap_tol = 0.95, only_from_exe = False, filter = None):
    if filter is None or filter == 'overall':
        filter = lambda x: True
        filter_name = 'overall'

    log_dir_path = os.path.join(output_path, 'log')
    all_virgins_positions = {}

    # A set of basic blocks that are no virgins
    disqualified = set()

    nb_traces = 0
    nb_traces_max = 0

    #———————————————————————————————————————————————————————————————————————————
    #
    # Compute the total intersection of all traces.
    #
    #———————————————————————————————————————————————————————————————————————————

    if filter == 'diff':
        total_intersection_path = os.path.join(log_dir_path, 'intersection.json')
        if os.path.isfile(total_intersection_path):
            with open(total_intersection_path, 'r') as file:
                content = file.read()
            parsed = json.loads(content)
            # translate lists to tuples
            total_intersection = frozenset([tuple(x) for x in parsed])
            parsed = None
            content = None
        else:
            total_intersection = None
            for trace_index, dirpath in enumerate(iopaths.subdirs(log_dir_path)):
                trace = traces.read_new_trace_from(dirpath)
                trace_set = set([(mid, offset) for mid, offset in zip(trace.module_ids, trace.offsets)])

                if total_intersection is None:
                    total_intersection = trace_set
                else:
                    total_intersection = total_intersection & trace_set
                
                logging.debug("Total intersection now has %d elements, after an intersection with %d elements" % (len(total_intersection), len(trace_set)))

            content = json.dumps(total_intersection, cls=MyJSONEncoder)
            with open(total_intersection_path, 'w') as file:
                file.write(content)
            content = None
            if total_intersection is None:
                total_intersection = []
                
            total_intersection = frozenset(total_intersection)

        filter = lambda x: not x in total_intersection
        filter_name = 'diff_' + str(cap_tol)
        logging.info("Total intersection has %d elements" % (len(total_intersection)))

        if not total_intersection:
            return None
    else:
        total_intersection = None

    sizes = {}
    global_mod_tab = None

    for trace_index, dirpath in enumerate(iopaths.subdirs(log_dir_path)):
        nb_skipped_bbs = 0
        nb_traces_max += 1
        logging.debug('Processing trace no %d: %s…' % (trace_index, dirpath))

        if global_mod_tab is None:
            with open(os.path.join(dirpath, 'covtrace_globalized_modtab.json'), 'r') as file:
                global_mod_tab = json.loads(file.read())

        time_start = time.time()
        trace = traces.read_new_trace_from(dirpath)
        time_elapsed = time.time() - time_start
        logging.debug("[?] trace read elapsed: %s" % time_elapsed)

        time_start = time.time()
        for gmid, offset, size in zip(trace.module_ids, trace.offsets, trace.sizes):
            key = (gmid, offset)
            if key in sizes:
                if sizes[key] != size:
                    logging.error("Inconsistent size: %d vs %d" % (size, sizes[key]))
            else:
                sizes[key] = size
        time_elapsed = time.time() - time_start
        logging.debug("[?] size update elapsed: %s" % time_elapsed)
        
        time_start = time.time()
        bb_list = [(gmid, offset) for gmid, offset in zip(trace.module_ids, trace.offsets) if filter((gmid, offset))]
        time_elapsed = time.time() - time_start
        logging.debug("[?] bb_list elapsed: %s" % time_elapsed)

        graph = range(1, len(bb_list) + 1)
        cap = math.ceil(cap_tol*len(bb_list))

        #
        # Find first-timers after the coverage cap has been reached.
        #

        # The order does not matter for the prefix, so let’s take a set for much 
        # better performance.
        time_start = time.time()
        tuples = [(x[0], x[1]) for x in bb_list[:cap-1]]
        prefix = set(tuples)
        suffix = [(x[0], x[1]) for x in bb_list[cap:]]
        disqualified = disqualified.union(prefix)
        time_elapsed = time.time() - time_start
        logging.debug("[?] tuples elapsed: %s" % time_elapsed)

        time_start = time.time()
        virgins_in_tail = []
        done_virgins = set()
        #for i, x in tqdm.tqdm(enumerate(suffix), desc="Per-trace virgins"):
        for i, x in enumerate(suffix):
            if x not in disqualified and x[0] != 0 and x not in done_virgins:
                virgins_in_tail += [(x, cap + i)]
                done_virgins.add(x)

        time_elapsed = time.time() - time_start
        logging.debug("[?] virgins elapsed: %s" % time_elapsed)
        logging.debug("There are %d virgins in the tail" % len(virgins_in_tail))

        # Iterate over all virgins found in the tail and collect only those that 
        # are large enough.
        time_start = time.time()
        nb_large_virgins = 0
        nb_skipped_bbs_size = 0
        for x, i in virgins_in_tail:
            gmid = x[0]
            offset = x[1]
            y = (gmid, offset)
            
            size = sizes[y]
            if size < min_size:
                nb_skipped_bbs_size += 1
                continue

            if not y in all_virgins_positions:
                all_virgins_positions[y] = []
                
            all_virgins_positions[y] += [(trace_index, i, i / trace.n, graph[i])]
            nb_large_virgins += 1

        time_elapsed = time.time() - time_start
        logging.debug("[?] good virgins elapsed: %s" % time_elapsed)

        logging.debug("Did not find %d BBs in drcov table" % nb_skipped_bbs)
        logging.debug("There are %d virgins of sufficient size in the tail" % nb_large_virgins)

        if nb_skipped_bbs >= len(virgins_in_tail):
            logging.warning("No virgin in the tail was known to drcov: %s" % dirpath)

        if nb_large_virgins <= 0:
            logging.warning("There are 0 virgins of sufficient size in the tail! Trace: %s" % dirpath)
            return None

        nb_traces += 1

    global_mod_id_to_path = { info['id']: path for path, info in global_mod_tab.items() }

    #
    # Clear virgins that appear too early in another trace
    #

    found = []
    candidates = []

    for x, positions in tqdm.tqdm(all_virgins_positions.items(), desc="Removing non-global virgins"):
        if not x in disqualified:
            if not only_from_exe or global_mod_id_to_path[x[0]].endswith('.exe'):
                if len(positions) == 0:
                    #logging.warning("No positions recorded for address %#010x in module %d" % (x[1], x[0]))
                    continue

                candidates.append({
                    'address': x,
                    'positions': positions,
                    'original_positions': positions,
                    'frequency': len(positions)
                })

    logging.debug("Second pass: only %d candidates remain and %d have been dropped" % (len(candidates), len(all_virgins_positions) - len(candidates)))
    del all_virgins_positions

    if len(candidates) <= 0:
        logging.error("Did not find any candidate")
        return None

    #
    # Find a set cover: find a selection of candidates so that for each trace, 
    # at least one candidate appears as a virgin in the coverage-cap tail.
    #

    covered_traces = set()
    objective = lambda x: statistics.mean([rel for _, _, rel, _ in x['positions']])

    while len(covered_traces) < nb_traces:
        logging.debug("Current number of candidates: %d" % len(candidates))
        # Sort descendingly by multiplying with -elem[1]
        candidates.sort(key=lambda x: -x['frequency'])
        cand = None

        for k, g in itertools.groupby(candidates, lambda x: x['frequency']):
            cur_cands = sorted(list(g), key=objective)
            cand = cur_cands[0]

            # We’re only interested in the first group
            break

        if cand is None:
            logging.warning("No candidate found!")
            return None

        found.append(cand)

        for ti, _, _, _ in cand['positions']:
            covered_traces.add(ti)
        
        logging.debug("Current number of covered traces: %d" % len(covered_traces))

        if len(covered_traces) < nb_traces:
            for x in candidates:
                x['positions'] = [(ti, abs, rel, cov) for ti, abs, rel, cov in x['positions'] if ti not in covered_traces]
                x['frequency'] = len(x['positions'])

            candidates = [x for x in candidates if x['frequency'] > 0]

    def to_basic_block(x):
        gmid = x['address'][0]
        path = global_mod_id_to_path[gmid]
        offset = x['address'][1]
        index_premieres_abs = [y[1] for y in x['positions']]
        index_premieres_rel = [y[2] for y in x['positions']]
        coverage_premieres = [y[3] for y in x['positions']]
        mean = statistics.mean([rel for _, _, rel, _ in x['original_positions']])
        
        return BasicBlock(path, offset, {
            'index_premieres_abs': tuple(index_premieres_abs),
            'index_premieres_rel': tuple(index_premieres_rel),
            'coverage_premieres': tuple(coverage_premieres),
            'mean_premiere': mean,
            }
        )

    blocks = frozenset([to_basic_block(x) for x in found])

    logging.info("For %.1f%% coverage, the minimum-mean virgin set-cover is:" % (100*cap_tol))
    for i, x in enumerate(blocks):
        logging.info("  %d.) %#010x in module %d (%s) with a mean premiere at position %.0f%%"
            % (i, x.offset, global_mod_tab[x.module_path]['id'], x.module_path, 100*x.info['mean_premiere'])
        )

    if filter_name == 'overall':
        name = 'trace_overall_%.6f' % cap_tol
    else:
        name = 'trace_differing_%.6f' % cap_tol
        
    return Solution(name, blocks, {})

#--------------------------------------------------------------------------------
#
# Flexible coverage cap covtrace
#
#--------------------------------------------------------------------------------

def flexible_coverage_cap_covtrace(
        output_path: str,
        min_size: int,
        cap_tol_overall=0,
        weight_overall=1,
        cap_tol_differing=0,
        weight_differing=1,
        only_from_exe=False,
        objective='smallest_earliest',
        accept_mod_path=None,
        read_trace=traces.read_new_trace_from,
        ub_o=1,
        ub_d=1,
        ub_t=math.inf,
    ):

    if cap_tol_overall is None:
        cap_tol_overall = 0
    if cap_tol_differing is None:
        cap_tol_differing = 0

    if accept_mod_path is None:
        accept_mod_path = lambda x: True

    log_dir_path = os.path.join(output_path, 'log')
    all_virgins_positions = {}

    # A set of basic blocks that are no virgins
    disqualified = set()

    nb_traces = 0
    nb_traces_max = 0

    #———————————————————————————————————————————————————————————————————————————
    #
    # Compute the total intersection of all traces.
    #
    #———————————————————————————————————————————————————————————————————————————

    total_intersection_path = os.path.join(log_dir_path, 'intersection.json')
    if os.path.isfile(total_intersection_path):
        with open(total_intersection_path, 'r') as file:
            content = file.read()
        parsed = json.loads(content)
        # translate lists to tuples
        total_intersection = frozenset([tuple(x) for x in parsed])
        parsed = None
        content = None
    else:
        total_intersection = None
        for trace_index, dirpath in enumerate(iopaths.subdirs(log_dir_path)):
            trace = read_trace(dirpath)
            trace_set = set([(mid, offset) for mid, offset in zip(trace.module_ids, trace.offsets)])

            if total_intersection is None:
                total_intersection = trace_set
            else:
                total_intersection = total_intersection & trace_set
            
            logging.debug("Total intersection now has %d elements, after an intersection with %d elements" % (len(total_intersection), len(trace_set)))

        content = json.dumps(total_intersection, cls=MyJSONEncoder)
        with open(total_intersection_path, 'w') as file:
            file.write(content)
        content = None
        if total_intersection is None:
            total_intersection = []
            
        total_intersection = frozenset(total_intersection)

    logging.info("Total intersection has %d elements" % (len(total_intersection)))

    #———————————————————————————————————————————————————————————————————————————
    #
    # Obtain the timings
    #
    #———————————————————————————————————————————————————————————————————————————
    
    timings = {}
    re_time = re.compile('Terminating, because\s+elapsed \(running\)\s*(\d+)\s+elapsed \(total\)\s*(\d+)\s+halted\s*(\d+)\s+is greater than\s+timeout\s*(\d+)', re.MULTILINE)
    
    for trace_index, dirpath in enumerate(iopaths.subdirs(log_dir_path)):
        timings[dirpath] = {
            'total': 0,
        }
        
        time_path = os.path.join(dirpath, 'time.txt')
        if not os.path.isfile(time_path):
            logging.warning("No timing information in %s" % dirpath)
            continue
            
        with open(time_path, 'r') as file:
            content = file.read()
            
        m = re_time.search(content)
        if not m:
            logging.warning("Unexpected timing information in %s" % dirpath)
            continue
    
        timings[dirpath]['total'] = int(m.group(2))

    #———————————————————————————————————————————————————————————————————————————
    #
    # Compute the tails
    #
    #———————————————————————————————————————————————————————————————————————————

    sizes = {}
    global_mod_tab = None

    # Maps a basic block ID (module_id, offset) to a list of appearances in the 
    # traces. An appearance is in terms of certain metrics, like the position of 
    # its premiere, the in-trace coverage at that point, and the in-trace 
    # difference coverage at that point.
    appearances = {}

    for trace_index, dirpath in enumerate(iopaths.subdirs(log_dir_path)):
        nb_skipped_bbs = 0
        nb_traces_max += 1
        logging.debug('Processing trace no %d: %s…' % (trace_index, dirpath))

        # Load the globalized module table, but only during the first iteration.
        if global_mod_tab is None:
            with open(os.path.join(dirpath, 'covtrace_globalized_modtab.json'), 'r') as file:
                global_mod_tab = json.loads(file.read())

        # Read the coverage trace
        trace = read_trace(dirpath)
        #logging.debug('Trace no %d has length %d' % (trace_index, len(trace.offsets)))

        # Load the sizes of the basic blocks in the trace into the global sizes 
        # array. Also check that the sizes between the traces are consistent.
        for gmid, offset, size in zip(trace.module_ids, trace.offsets, trace.sizes):
            key = (gmid, offset)
            if key in sizes:
                if sizes[key] != size:
                    logging.error("Inconsistent size: %d vs %d" % (size, sizes[key]))
            else:
                sizes[key] = size

        # Translate the coverage trace to a list of basic block IDs.        
        bb_list = [(gmid, offset) for gmid, offset in zip(trace.module_ids, trace.offsets)]

        # The coverage graph is trivial.
        overall_graph = [i / len(bb_list) for i in range(1, len(bb_list) + 1)]
        differing_graph = np.cumsum([1 if x not in total_intersection else 0 for x in bb_list])
        if differing_graph[-1] != 0:
            differing_graph = differing_graph / differing_graph[-1]

        if cap_tol_overall:
            overall_cap_bound = next((i for i, x in enumerate(overall_graph) if x >= cap_tol_overall), len(bb_list))
        else:
            overall_cap_bound = 0

        #logging.debug("Cap tol coverall: %s" % str(overall_cap_bound))

        if cap_tol_differing:
            differing_cap_bound = next((i for i, x in enumerate(differing_graph) if x >= cap_tol_differing), len(bb_list))
        else:
            differing_cap_bound = 0
            
        if ub_o >= 1:
            overall_cap_bound_l = len(bb_list)
        else:
            overall_cap_bound_l = next((i for i, x in zip(range(len(bb_list)-1,-1,-1), overall_graph[::-1]) if x <= ub_o), 0)
            
        if ub_d >= 1:
            differing_cap_bound_l = len(bb_list)
        else:
            differing_cap_bound_l = next((i for i, x in zip(range(len(bb_list)-1,-1,-1), differing_graph[::-1]) if x <= ub_d), 0)

        if ub_t == math.inf:
            time_cap_bound_l = len(bb_list)
        else:
            # times in the traces are nanoseconds, i.e., 1e-9 seconds. We want milliseconds, i.e., 1e-3.
            time_cap_bound_l = next((i for i, x in zip(range(len(bb_list)-1,-1,-1), trace.times[::-1]) if 1e-6 * (x - trace.times[0]) <= ub_t), 0)

        abs_lower_bound = max(overall_cap_bound, differing_cap_bound)
        abs_upper_bound = min(overall_cap_bound_l, differing_cap_bound_l, time_cap_bound_l)

        #logging.debug('abs_lower_bound: %f' % abs_lower_bound)
        #logging.debug('abs_upper_bound: %f' % abs_upper_bound)

        for i, x in enumerate(bb_list[abs_lower_bound:abs_upper_bound], abs_lower_bound):
            gmid = x[0]
            offset = x[1]
            ocov = overall_graph[i]
            dcov = differing_graph[i]

            if not x in appearances:
                appearances[x] = []

            appearances[x].append({
                'input': dirpath,
                'overall_coverage': ocov,
                'differing_coverage': dcov,
                'time': (trace.times[i] - trace.times[0]) * 1e-6,
            })

        # The order does not matter for the prefix, so let’s take a set for much 
        # better performance.
        if abs_lower_bound > 0:
            prefix = set([x for x in bb_list[:abs_lower_bound-1]])
        else:
            prefix = set([])
            
        if abs_upper_bound < len(bb_list):
            suffix = set([x for x in bb_list[abs_upper_bound+1:]])
        else:
            suffix = set([])
        
        disqualified = disqualified.union(prefix)
        disqualified = disqualified.union(suffix)
        logging.debug('Adding %d prefix and %d suffix elements to the disqualified set to a total of %d elements' % (len(prefix), len(suffix), len(disqualified)))
        
        del trace
        del bb_list
        del overall_graph
        del differing_graph
        del prefix
        del suffix

        nb_traces += 1

    global_mod_id_to_path = { info['id']: path for path, info in global_mod_tab.items() }
    #logging.debug(json.dumps(global_mod_id_to_path, indent=2))
    #logging.debug("Disqualified: %d" % len(disqualified))

    found = []
    candidates = []

    #
    # Compute tail map: basic block might contain other basic blocks because of 
    # fall-through logic. For each basic block, identify the first region that 
    # is large enough (honoring min_size) without touching parts of contained 
    # basic blocks. The reason is that the contained basic blocks might be 
    # executed first and we do not want to mess with the instructions by 
    # partially overwriting them.
    #

    map_bb_to_best_tail = {}
    save_sizes = {}
    # Sorted by (module_id, offset)
    sorted_bbs = sorted([x for x in sizes])
    # group by module
    for k, g in itertools.groupby(sorted_bbs, key=lambda x: x[0]):
        # sort by end address
        sorted_g = sorted(list(g), key=lambda x: (x[1] + sizes[x], x[1]))
        for kk, gg in itertools.groupby(sorted_g, key=lambda x: x[1] + sizes[x]):
            gg_list = sorted(list(gg), key=lambda x: x[1])
            last = gg_list[-1]
            for x, nx in zip(gg_list, gg_list[1:]):
                save_sizes[x] = nx[1] - x[1]
            save_sizes[last] = sizes[last]
            
            map_bb_to_best_tail[last] = last
            for i in reversed(range(0, len(gg_list) - 1)):
                prev = gg_list[i + 1]
                cur = gg_list[i]

                if save_sizes[cur] >= min_size:
                    map_bb_to_best_tail[cur] = cur
                else:
                    map_bb_to_best_tail[cur] = map_bb_to_best_tail[prev]

            #if len(gg_list) > 1:
            #    print(['%#08x (%d, %d) -> %#08x (%d, %d)' % (x[1], sizes[x], save_sizes[x], map_bb_to_best_tail[x][1], sizes[map_bb_to_best_tail[x]], save_sizes[map_bb_to_best_tail[x]]) for x in gg_list])
            

    #with open('foo.txt', 'w') as file:
    #    file.write(json.dumps(map_bb_to_smallest_tail, indent=2, cls=MyJSONEncoder))

    accepted_mod_ids = set([x['id'] for path, x in global_mod_tab.items() if accept_mod_path(path)])
    #logging.debug(str(accepted_mod_ids))
    #print(accepted_mod_ids)
    #exit(1)

    #logging.debug("Appearances: %d" % len(appearances))

    for x, appearance in appearances.items():
        #if sizes[x] < min_size:
        if save_sizes[x] < min_size:
            #logging.debug("Clearing %s because of size" % str(x))
            continue

        if x in disqualified:
            #logging.debug("Clearing %s because disqualified" % str(x))
            continue

        if not x[0] in global_mod_id_to_path:
            #logging.debug("Clearing %s because module id %d unknown" % (str(x), x[0]))
            continue

        if only_from_exe and not global_mod_id_to_path[x[0]].endswith('.exe'):
            #logging.debug("Clearing %s because not from exe" % str(x))
            continue

        if not x[0] in accepted_mod_ids:
            #logging.debug("Clearing %s because not accepted mod" % str(x))
            continue

        sorted_overall = sorted([a['overall_coverage'] for a in appearance])
        sorted_differing = sorted([a['differing_coverage'] for a in appearance])

        candidates.append({
            'bb': x,
            'inputs': set([a['input'] for a in appearance]),
            'inputs_left': set([a['input'] for a in appearance]),
            #'lowest_overall': min([a['overall_coverage'] for a in appearance]),
            #'lowest_differing': min([a['differing_coverage'] for a in appearance]),
            'appearances': appearance,
            'overall_coverages_asc': sorted_overall,
            'differing_coverages_asc': sorted_differing,
            'combined_coverages_asc': sorted([weight_overall*o + weight_differing*d for o, d in zip(sorted_overall, sorted_differing)]),
            'combined_coverages_desc': sorted([-(weight_overall*o + weight_differing*d) for o, d in zip(sorted_overall, sorted_differing)]),
            'time_min': min(a['time'] for a in appearance),
            'time_max': max(a['time'] for a in appearance),
            'time_avg': sum(a['time'] for a in appearance) / len(appearance),
        })

    logging.debug("Second pass: only %d candidates remain" % (len(candidates)))

    #
    # Find a set cover: find a selection of candidates so that for each trace, 
    # at least one candidate appears as a virgin in the coverage-cap tail.
    #

    solution = []
    covered_traces = set()

#    print(set([inp for x in candidates for inp in x['inputs']]))

    if objective is None or objective == 'smallest_latest':
        #objective_fun = lambda inputs, lowest_overall, lowest_differing: (len(inputs), weight_overall*lowest_overall + weight_differing*lowest_differing)
        objective_fun = lambda x: (len(x['inputs_left']), x['combined_coverages_asc'])
    elif objective == 'latest_smallest':
        #objective_fun = lambda inputs, lowest_overall, lowest_differing: (weight_overall*lowest_overall + weight_differing*lowest_differing, len(inputs))
        objective_fun = lambda x: (x['combined_coverages_asc'], len(x['inputs_left']))
    elif objective == 'smallest_earliest':
        #objective_fun = lambda inputs, lowest_overall, lowest_differing: (len(inputs), -(weight_overall*lowest_overall + weight_differing*lowest_differing))
        objective_fun = lambda x: (len(x['inputs_left']), x['combined_coverages_desc'])
    elif objective == 'earliest_smallest':
        #objective_fun = lambda inputs, lowest_overall, lowest_differing: (-(weight_overall*lowest_overall + weight_differing*lowest_differing), len(inputs))
        objective_fun = lambda x: (x['combined_coverages_desc'], len(x['inputs_left']))
    else:
        raise Exception('orly')

    while len(covered_traces) < nb_traces:
        logging.debug("Current size of solution: %d" % len(solution))
        logging.debug("Current number of covered traces: %d" % len(covered_traces))
        
        if len(candidates) <= 0:
            logging.error("Did not find a solution!")
            return None

        # Sort by lower bound on coverage; tie breaker is number of inputs
        candidates = sorted(
            candidates,
            key=objective_fun
            #key=lambda x: objective_fun(x['inputs'], x['lowest_overall'], x['lowest_differing'])
        )

        cand = candidates[-1]
        if cand is None:
            logging.warning("No candidate found!")
            return None

        solution.append(cand)

        for iname in cand['inputs']:
            covered_traces.add(iname)
        
        if len(covered_traces) < nb_traces:
            new_candidates = []
            for x in candidates:
                inputs_left = [iname for iname in x['inputs'] if not iname in covered_traces]
                if not inputs_left:
                    continue

                x['inputs_left'] = inputs_left
                new_candidates.append(x)

            candidates = new_candidates

    def to_basic_block(x):
        gmid = x['bb'][0]
        path = global_mod_id_to_path[gmid]
        offset = x['bb'][1]
        
        return BasicBlock(path, offset, {
            'nb_inputs': len(x['inputs']),
            'size': sizes[x['bb']],
            'save_size': save_sizes[x['bb']],
            'overall_coverages_asc': x['overall_coverages_asc'],
            'differing_coverages_asc': x['differing_coverages_asc'],
            'combined_coverages_asc': x['combined_coverages_asc'],
            'appearances': appearances[x['bb']],
            'time_min': x['time_min'],
            'time_max': x['time_max'],
            'time_avg': x['time_avg'],
            }
        )

    blocks = frozenset([to_basic_block(x) for x in solution])

    logging.info("For %.1f%% overall and %.1f%% differing bound, the solution is:" % (100*cap_tol_overall, 100*cap_tol_differing))
    for i, x in enumerate(blocks):
        logging.info(
            "  {i}.) {offset:#010x} in module {module_id} ({module_name}) sized {size} bytes with a minimum overall coverage of {ocov:.0f}% and minimum differing coverage of {dcov:.0f}%".format(
                i=i+1,
                offset=x.offset,
                module_id=global_mod_tab[x.module_path]['id'],
                module_name=os.path.split(x.module_path)[1],
                size=x.info['size'],
                ocov=100*min(x.info['overall_coverages_asc']),
                dcov=100*min(x.info['differing_coverages_asc']),
            )
        )

    name = 'covtrace_overall_%.6f_differing_%.6f_%s' % (cap_tol_overall, cap_tol_differing, objective)
        
    return Solution(name, blocks, {
        'cap_tol_overall': cap_tol_overall,
        'cap_tol_differing': cap_tol_differing,
        'ub_o': ub_o,
        'ub_d': ub_d,
        'weight_overall': weight_overall,
        'weight_differing': weight_differing,
        'objective': objective,
        'only_from_exe': only_from_exe,
        'min_size': min_size,
        'exe_name': effective_blocks_name(blocks) + '.exe',
        'min_overall_coverage': min([min(x.info['overall_coverages_asc']) for x in blocks]),
        'min_differing_coverage': min([min(x.info['differing_coverages_asc']) for x in blocks]),
        'max_overall_coverage': max([max(x.info['overall_coverages_asc']) for x in blocks]),
        'max_differing_coverage': max([max(x.info['differing_coverages_asc']) for x in blocks]),
        'min_time': min(x.info['time_min'] for x in blocks),
        'max_time': max(x.info['time_max'] for x in blocks),
        'sizes': [int(x.info['size']) for x in blocks],
        })

#--------------------------------------------------------------------------------
#
# Coverage cap
#
#--------------------------------------------------------------------------------

def coverage_cap_omegafast(output_path: str, min_size, cap_tol = 0.95, only_from_exe = False, filter = None, pred_accept_mod_path = lambda x: True):
    if filter is None or filter == 'overall':
        filter = lambda x: True
        filter_name = 'overall'

    log_dir_path = os.path.join(output_path, 'log')
    all_virgins_positions = {}

    # A set of basic blocks that are no virgins
    disqualified = set()

    global_path_to_info = {}
    global_id_to_info = {}

    nb_traces = 0
    nb_traces_max = 0

    #———————————————————————————————————————————————————————————————————————————
    #
    # Compute the local-to-global module mapping.
    #
    # The order in which modules are loaded is not guaranteed in Windows. 
    # That’s why every trace might have different IDs for the same modules. In 
    # order to compare the traces, we have to globalize the module IDs.
    #
    #———————————————————————————————————————————————————————————————————————————

    path_mappings = os.path.join(log_dir_path, 'mapping.json')
    if os.path.isfile(path_mappings):
        with open(path_mappings, 'r') as file:
            content = file.read()
        mappings = json.loads(content)
        content = None
        global_path_to_info = mappings['global_path_to_info']
        global_id_to_info = { int(k): v for k, v in mappings['global_id_to_info'].items() }
        mappings = None
    else:
        for trace_index, dirpath in enumerate(iopaths.subdirs(log_dir_path)):
            result = drcov.load_from(dirpath)

            local_to_global_mod_id = {}
            for mid, info in result.mod_table.items():
                if not info['path'] in global_path_to_info:
                    gmid = len(global_path_to_info) + 1
                    global_path_to_info[info['path']] = {
                        'id': gmid,
                        'path': info['path']
                    }
                    global_id_to_info[gmid] = {
                        'id': gmid,
                        'path': info['path']
                    }

        mappings = {
            'global_path_to_info': global_path_to_info,
            'global_id_to_info': global_id_to_info,
        }
        content = json.dumps(mappings, cls=MyJSONEncoder)
        with open(path_mappings, 'w') as file:
            file.write(content)
        content = None
        mappings = None

    global_id_to_info[0] = {
        'id': 0,
        'path': None,
    }

    #———————————————————————————————————————————————————————————————————————————
    #
    # Compute the total intersection of all traces.
    #
    #———————————————————————————————————————————————————————————————————————————

    if filter == 'diff':
        total_intersection_path = os.path.join(log_dir_path, 'intersection.json')
        if os.path.isfile(total_intersection_path):
            with open(total_intersection_path, 'r') as file:
                content = file.read()
            parsed = json.loads(content)
            total_intersection = frozenset([tuple(x) for x in parsed])
            parsed = None
            content = None
        else:
            total_intersection = None
            for trace_index, dirpath in enumerate(iopaths.subdirs(log_dir_path)):
                result = drcov.load_from(dirpath)
                trace_set = set([
                    (
                        global_path_to_info[result.mod_table[bb['module_id']]['path']]['id'],
                        bb['offset']
                    )
                    for bid, bb in result.bb_table.items()
                    if pred_accept_mod_path(result.mod_table[bb['module_id']]['path'])
                ])

                if total_intersection is None:
                    total_intersection = trace_set
                else:
                    total_intersection = total_intersection & trace_set
                
                logging.debug("Total intersection now has %d elements, after an intersection with %d elements" % (len(total_intersection), len(trace_set)))

            content = json.dumps(total_intersection, cls=MyJSONEncoder)
            with open(total_intersection_path, 'w') as file:
                file.write(content)
            content = None
            if total_intersection is None:
                total_intersection = []
                
            total_intersection = frozenset(total_intersection)

        filter = lambda x: not x in total_intersection
        filter_name = 'diff_' + str(cap_tol)
        logging.info("Total intersection has %d elements" % (len(total_intersection)))

        if not total_intersection:
            return None
    else:
        total_intersection = None

    for trace_index, dirpath in enumerate(iopaths.subdirs(log_dir_path)):
        nb_skipped_bbs = 0
        nb_traces_max += 1
        logging.debug('Processing trace no %d: %s…' % (trace_index, dirpath))

        time_start = time.time()
        drcov_result = drcov.load_from(dirpath)
        time_elapsed = time.time() - time_start
        logging.debug("[?] drcov elapsed: %s" % time_elapsed)
        
        time_start = time.time()
        bb_list = [
            (
                global_path_to_info[drcov_result.mod_table[bb['module_id']]['path']]['id'],
                bb['offset'],
                bb['index']
            )
            for bid, bb in drcov_result.bb_table.items()
            if pred_accept_mod_path(drcov_result.mod_table[bb['module_id']]['path'])
        ]
        bb_list = [x for x in bb_list if filter((x[0], x[1]))]
        time_elapsed = time.time() - time_start
        logging.debug("[?] bb_list elapsed: %s" % time_elapsed)

        time_start = time.time()
        bb_list = sorted(bb_list, key=lambda x: x[2])
        time_elapsed = time.time() - time_start
        logging.debug("[?] bb_list sort elapsed: %s" % time_elapsed)

        graph = range(1, len(bb_list) + 1)
        cap = math.ceil(cap_tol*len(bb_list))

        #
        # Find first-timers after the coverage cap has been reached.
        #

        # The order does not matter for the prefix, so let’s take a set for much 
        # better performance.
        time_start = time.time()
        tuples = [(x[0], x[1]) for x in bb_list[:cap-1]]
        prefix = set(tuples)
        suffix = [(x[0], x[1]) for x in bb_list[cap:]]
        disqualified = disqualified.union(prefix)
        time_elapsed = time.time() - time_start
        logging.debug("[?] tuples elapsed: %s" % time_elapsed)

        time_start = time.time()
        virgins_in_tail = []
        done_virgins = set()
        #for i, x in tqdm.tqdm(enumerate(suffix), desc="Per-trace virgins"):
        for i, x in enumerate(suffix):
            if x not in disqualified and x[0] != 0 and x not in done_virgins:
                virgins_in_tail += [(x, cap + i)]
                done_virgins.add(x)

        time_elapsed = time.time() - time_start
        logging.debug("[?] virgins elapsed: %s" % time_elapsed)
        logging.debug("There are %d virgins in the tail" % len(virgins_in_tail))

        # Iterate over all virgins found in the tail and collect only those that 
        # are large enough.
        time_start = time.time()
        nb_large_virgins = 0
        nb_skipped_bbs_size = 0
        for x, i in virgins_in_tail:
            gmid = x[0]
            offset = x[1]
            y = (gmid, offset)
            
            id = (global_id_to_info[gmid]['path'], offset)
            if not id in drcov_result.bb_table:
                nb_skipped_bbs += 1
                continue

            size = drcov_result.bb_table[id]['size']
            if size < min_size:
                nb_skipped_bbs_size += 1
                continue

            if not y in all_virgins_positions:
                all_virgins_positions[y] = []
                
            all_virgins_positions[y] += [(trace_index, i, i / len(drcov_result.bb_table), graph[i])]
            nb_large_virgins += 1

        time_elapsed = time.time() - time_start
        logging.debug("[?] good virgins elapsed: %s" % time_elapsed)

        logging.debug("Did not find %d BBs in drcov table" % nb_skipped_bbs)
        logging.debug("There are %d virgins of sufficient size in the tail" % nb_large_virgins)

        if nb_skipped_bbs >= len(virgins_in_tail):
            logging.warning("No virgin in the tail was known to drcov: %s" % dirpath)

        if nb_large_virgins <= 0:
            logging.warning("There are 0 virgins of sufficient size in the tail! Trace: %s" % dirpath)
            return frozenset()

        nb_traces += 1

    #
    # Clear virgins that appear too early in another trace
    #

    found = []
    candidates = []

    for x, positions in tqdm.tqdm(all_virgins_positions.items(), desc="Removing non-global virgins"):
        if not x in disqualified:
            if not only_from_exe or global_id_to_info[x[0]]['path'].endswith('.exe'):
                if len(positions) == 0:
                    #logging.warning("No positions recorded for address %#010x in module %d" % (x[1], x[0]))
                    continue

                candidates.append({
                    'address': x,
                    'positions': positions,
                    'original_positions': positions,
                    'frequency': len(positions)
                })

    logging.debug("Second pass: only %d candidates remain and %d have been dropped" % (len(candidates), len(all_virgins_positions) - len(candidates)))
    del all_virgins_positions

    if len(candidates) <= 0:
        logging.error("Did not find any candidate")
        return None

    #
    # Find a set cover: find a selection of candidates so that for each trace, 
    # at least one candidate appears as a virgin in the coverage-cap tail.
    #

    covered_traces = set()
    objective = lambda x: statistics.mean([rel for _, _, rel, _ in x['positions']])

    while len(covered_traces) < nb_traces:
        logging.debug("Current number of candidates: %d" % len(candidates))
        # Sort descendingly by multiplying with -elem[1]
        candidates.sort(key=lambda x: -x['frequency'])
        cand = None

        for k, g in itertools.groupby(candidates, lambda x: x['frequency']):
            cur_cands = sorted(list(g), key=objective)
            cand = cur_cands[0]

            # We’re only interested in the first group
            break

        if cand is None:
            logging.warning("No candidate found!")
            return None

        found.append(cand)

        for ti, _, _, _ in cand['positions']:
            covered_traces.add(ti)
        
        logging.debug("Current number of covered traces: %d" % len(covered_traces))

        if len(covered_traces) < nb_traces:
            for x in candidates:
                x['positions'] = [(ti, abs, rel, cov) for ti, abs, rel, cov in x['positions'] if ti not in covered_traces]
                x['frequency'] = len(x['positions'])

            candidates = [x for x in candidates if x['frequency'] > 0]

    def to_basic_block(x):
        gmid = x['address'][0]
        path = global_mods[gmid]
        offset = x['address'][1]
        index_premieres_abs = [y[1] for y in x['positions']]
        index_premieres_rel = [y[2] for y in x['positions']]
        coverage_premieres = [y[3] for y in x['positions']]
        mean = statistics.mean([rel for _, _, rel, _ in x['original_positions']])
        
        return BasicBlock(path, offset, {
            'index_premieres_abs': tuple(index_premieres_abs),
            'index_premieres_rel': tuple(index_premieres_rel),
            'coverage_premieres': tuple(coverage_premieres),
            'mean_premiere': mean,
            'module_id': gmid,
            }
        )

    blocks = frozenset([to_basic_block(x) for x in found])

    logging.info("For %.1f%% coverage, the minimum-mean virgin set-cover is:" % (100*cap_tol))
    for i, x in enumerate(blocks):
        mean = statistics.mean([rel for _, _, rel, _ in x['original_positions']])
        logging.info("  %d.) %#010x in module %d (%s) with a mean premiere at position %.0f%%"
            % (i, x.offset, x.info['module_id'], x.module_path, 100*x['info']['mean_premiere'])
        )

    if filter_name == 'overall':
        name = 'drcov_overall_%.6f' % cap_tol
    else:
        name = 'drcov_differing_%.6f' % cap_tol
        
    return Solution(name, blocks, {})

#--------------------------------------------------------------------------------
#
# Flexible coverage cap covtrace
#
#--------------------------------------------------------------------------------

def flexible_coverage_cap_drcov(
        output_path: str,
        min_size: int,
        cap_tol_overall=0,
        weight_overall=1,
        cap_tol_differing=0,
        weight_differing=1,
        only_from_exe=False,
        objective='smallest_earliest',
        accept_mod_path=None,
    ):

    if cap_tol_overall is None:
        cap_tol_overall = 0
    if cap_tol_differing is None:
        cap_tol_differing = 0

    if accept_mod_path is None:
        accept_mod_path = lambda x: True

    log_dir_path = os.path.join(output_path, 'log')
    all_virgins_positions = {}

    # A set of basic blocks that are no virgins
    disqualified = set()

    nb_traces = 0
    nb_traces_max = 0

    # Maps a module path to a dictionary with 'id' and 'path' keys
    global_path_to_info = None

    # Maps a global module ID to a dictionary with 'id' and 'path' keys
    global_id_to_info = None

    #———————————————————————————————————————————————————————————————————————————
    #
    # Compute the local-to-global module mapping.
    #
    # The order in which modules are loaded is not guaranteed in Windows. 
    # That’s why every trace might have different IDs for the same modules. In 
    # order to compare the traces, we have to globalize the module IDs.
    #
    #———————————————————————————————————————————————————————————————————————————

    path_mappings = os.path.join(log_dir_path, 'mapping.json')
    if os.path.isfile(path_mappings):
        with open(path_mappings, 'r') as file:
            content = file.read()
        mappings = json.loads(content)
        content = None
        global_path_to_info = mappings['global_path_to_info']
        # Translate string keys to int keys
        global_id_to_info = { int(k): v for k, v in mappings['global_id_to_info'].items() }
        mappings = None
    else:
        global_path_to_info = {}
        global_id_to_info = {}

        for trace_index, dirpath in enumerate(iopaths.subdirs(log_dir_path)):
            result = drcov.load_from(dirpath)

            local_to_global_mod_id = {}
            for mid, info in result.mod_table.items():
                if not info['path'] in global_path_to_info:
                    gmid = len(global_path_to_info) + 1
                    global_path_to_info[info['path']] = {
                        'id': gmid,
                        'path': info['path']
                    }
                    global_id_to_info[gmid] = {
                        'id': gmid,
                        'path': info['path']
                    }

        mappings = {
            'global_path_to_info': global_path_to_info,
            'global_id_to_info': global_id_to_info,
        }
        content = json.dumps(mappings, cls=MyJSONEncoder)
        with open(path_mappings, 'w') as file:
            file.write(content)
        content = None
        mappings = None

    global_id_to_info[0] = {
        'id': 0,
        'path': None,
    }

    #———————————————————————————————————————————————————————————————————————————
    #
    # Compute the total intersection of all traces.
    #
    #———————————————————————————————————————————————————————————————————————————
    
    total_intersection_path = os.path.join(log_dir_path, 'intersection.json')
    if os.path.isfile(total_intersection_path):
        with open(total_intersection_path, 'r') as file:
            content = file.read()
        parsed = json.loads(content)
        total_intersection = frozenset([tuple(x) for x in parsed])
        parsed = None
        content = None
    else:
        total_intersection = None
        for trace_index, dirpath in enumerate(iopaths.subdirs(log_dir_path)):
            result = drcov.load_from(dirpath)
            trace_set = set([
                (
                    global_path_to_info[result.mod_table[bb['module_id']]['path']]['id'],
                    bb['offset']
                )
                for bid, bb in result.bb_table.items()
                if accept_mod_path(result.mod_table[bb['module_id']]['path'])
            ])

            if total_intersection is None:
                total_intersection = trace_set
            else:
                total_intersection = total_intersection & trace_set
            
            logging.debug("Total intersection now has %d elements, after an intersection with %d elements" % (len(total_intersection), len(trace_set)))

        content = json.dumps(total_intersection, cls=MyJSONEncoder)
        with open(total_intersection_path, 'w') as file:
            file.write(content)
        content = None
        if total_intersection is None:
            total_intersection = []
            
        total_intersection = frozenset(total_intersection)

    logging.info("Total intersection has %d elements" % (len(total_intersection)))

    #———————————————————————————————————————————————————————————————————————————
    #
    # Find all appearances
    #
    #———————————————————————————————————————————————————————————————————————————

    sizes = {}

    # Maps a basic block ID (module_id, offset) to a list of appearances in the 
    # traces. An appearance is in terms of certain metrics, like the position of 
    # its premiere, the in-trace coverage at that point, and the in-trace 
    # difference coverage at that point.
    appearances = {}

    for trace_index, dirpath in enumerate(iopaths.subdirs(log_dir_path)):
        nb_skipped_bbs = 0
        nb_traces_max += 1
        logging.debug('Processing trace no %d: %s…' % (trace_index, dirpath))

        # Read the current coverage log file
        drcov_result = drcov.load_from(dirpath)

        # Translate the coverage data to a list of basic block IDs and information.
        bb_list_fat = [
            (
                global_path_to_info[drcov_result.mod_table[bb['module_id']]['path']]['id'],
                bb['offset'],
                bb['size'],
                bb['global_index']
            )
            for bid, bb in drcov_result.bb_table.items()
            if accept_mod_path(drcov_result.mod_table[bb['module_id']]['path'])
        ]

        # We use (gmid, offset) everywhere else. Reduce the fat list to this 
        # format, so that we can compare more easily.
        bb_list = [(gmid, offset) for gmid, offset, size, index in bb_list_fat]

        # Load the sizes of the basic blocks in the trace into the global sizes 
        # array. Also check that the sizes between the traces are consistent.
        for gmid, offset, size, index in bb_list_fat:
            key = (gmid, offset)
            if key in sizes:
                if sizes[key] != size:
                    logging.error("Inconsistent size: %d vs %d" % (size, sizes[key]))
            else:
                sizes[key] = size

        # The coverage graph is trivial.
        overall_graph = [i / len(bb_list) for i in range(1, len(bb_list) + 1)]
        differing_graph = np.cumsum([1 if x not in total_intersection else 0 for x in bb_list])
        if differing_graph[-1] != 0:
            differing_graph = differing_graph / differing_graph[-1]

        if cap_tol_overall:
            overall_cap_bound = next((i for i, x in enumerate(overall_graph) if x >= cap_tol_overall), len(bb_list))
        else:
            overall_cap_bound = 0

        if cap_tol_differing:
            differing_cap_bound = next((i for i, x in enumerate(differing_graph) if x >= cap_tol_differing), len(bb_list))
        else:
            differing_cap_bound = 0

        abs_lower_bound = max(overall_cap_bound, differing_cap_bound)

        for i, x in enumerate(bb_list[abs_lower_bound:], abs_lower_bound):
            gmid = x[0]
            offset = x[1]
            ocov = overall_graph[i]
            dcov = differing_graph[i]

            if not x in appearances:
                appearances[x] = []

            appearances[x].append({
                'input': dirpath,
                'overall_coverage': ocov,
                'differing_coverage': dcov,
            })

        # The order does not matter for the prefix, so let’s take a set for much 
        # better performance.
        if abs_lower_bound > 0:
            prefix = set([x for x in bb_list[:abs_lower_bound-1]])
        else:
            prefix = set([])
            
        disqualified = disqualified.union(prefix)

        nb_traces += 1

    #———————————————————————————————————————————————————————————————————————————
    #
    # Compute a tail map
    #
    #———————————————————————————————————————————————————————————————————————————

    map_bb_to_best_tail = {}
    save_sizes = {}
    sorted_bbs = sorted([x for x in sizes])

    # group by module
    for k, g in itertools.groupby(sorted_bbs, key=lambda x: x[0]):
        # sort by end address
        sorted_g = sorted(list(g), key=lambda x: (x[1] + sizes[x], x[1]))
        for kk, gg in itertools.groupby(sorted_g, key=lambda x: x[1] + sizes[x]):
            gg_list = sorted(list(gg), key=lambda x: x[1])
            last = gg_list[-1]
            for x, nx in zip(gg_list, gg_list[1:]):
                save_sizes[x] = nx[1] - x[1]
            save_sizes[last] = sizes[last]
            
            map_bb_to_best_tail[last] = last
            for i in reversed(range(0, len(gg_list) - 1)):
                prev = gg_list[i + 1]
                cur = gg_list[i]

                if save_sizes[cur] >= min_size:
                    map_bb_to_best_tail[cur] = cur
                else:
                    map_bb_to_best_tail[cur] = map_bb_to_best_tail[prev]
            
    #———————————————————————————————————————————————————————————————————————————
    #
    # Filter out bad blocks
    #
    #———————————————————————————————————————————————————————————————————————————

    found = []
    candidates = []

    accepted_mod_ids = set([info['id'] for path, info in global_path_to_info.items() if accept_mod_path(path)])

    for x, appearance in appearances.items():
        #if sizes[x] < min_size:
        if save_sizes[x] < min_size:
            continue

        if x in disqualified:
            continue

        if not x[0] in global_id_to_info:
            continue

        if only_from_exe and not global_id_to_info[x[0]]['path'].endswith('.exe'):
            continue

        if not x[0] in accepted_mod_ids:
            continue

        sorted_overall = sorted([a['overall_coverage'] for a in appearance])
        sorted_differing = sorted([a['differing_coverage'] for a in appearance])

        candidates.append({
            'bb': x,
            'inputs': set([a['input'] for a in appearance]),
            'inputs_left': set([a['input'] for a in appearance]),
            #'lowest_overall': min([a['overall_coverage'] for a in appearance]),
            #'lowest_differing': min([a['differing_coverage'] for a in appearance]),
            'appearances': appearance,
            'overall_coverages_asc': sorted_overall,
            'differing_coverages_asc': sorted_differing,
            'combined_coverages_asc': sorted([weight_overall*o + weight_differing*d for o, d in zip(sorted_overall, sorted_differing)]),
            'combined_coverages_desc': sorted([-(weight_overall*o + weight_differing*d) for o, d in zip(sorted_overall, sorted_differing)]),
        })

    logging.debug("Second pass: only %d candidates remain" % (len(candidates)))

    #
    # Find a set cover: find a selection of candidates so that for each trace, 
    # at least one candidate appears as a virgin in the coverage-cap tail.
    #

    solution = []
    covered_traces = set()

#    print(set([inp for x in candidates for inp in x['inputs']]))

    if objective is None or objective == 'smallest_latest':
        #objective_fun = lambda inputs, lowest_overall, lowest_differing: (len(inputs), weight_overall*lowest_overall + weight_differing*lowest_differing)
        objective_fun = lambda x: (len(x['inputs_left']), x['combined_coverages_asc'])
    elif objective == 'latest_smallest':
        #objective_fun = lambda inputs, lowest_overall, lowest_differing: (weight_overall*lowest_overall + weight_differing*lowest_differing, len(inputs))
        objective_fun = lambda x: (x['combined_coverages_asc'], len(x['inputs_left']))
    elif objective == 'smallest_earliest':
        #objective_fun = lambda inputs, lowest_overall, lowest_differing: (len(inputs), -(weight_overall*lowest_overall + weight_differing*lowest_differing))
        objective_fun = lambda x: (len(x['inputs_left']), x['combined_coverages_desc'])
    elif objective == 'earliest_smallest':
        #objective_fun = lambda inputs, lowest_overall, lowest_differing: (-(weight_overall*lowest_overall + weight_differing*lowest_differing), len(inputs))
        objective_fun = lambda x: (x['combined_coverages_desc'], len(x['inputs_left']))
    else:
        raise Exception('orly')
         
    #———————————————————————————————————————————————————————————————————————————
    #
    # Compute a solution as a set cover
    #
    #———————————————————————————————————————————————————————————————————————————

    while len(covered_traces) < nb_traces:
        logging.debug("Current size of solution: %d" % len(solution))
        logging.debug("Current number of covered traces: %d" % len(covered_traces))
        
        if len(candidates) <= 0:
            logging.error("Did not find a solution!")
            return None

        # Sort by lower bound on coverage; tie breaker is number of inputs
        candidates = sorted(
            candidates,
            key=objective_fun
            #key=lambda x: objective_fun(x['inputs'], x['lowest_overall'], x['lowest_differing'])
        )

        cand = candidates[-1]
        if cand is None:
            logging.warning("No candidate found!")
            return None

        solution.append(cand)

        for iname in cand['inputs']:
            covered_traces.add(iname)
        
        if len(covered_traces) < nb_traces:
            new_candidates = []
            for x in candidates:
                inputs_left = [iname for iname in x['inputs'] if not iname in covered_traces]
                if not inputs_left:
                    continue

                x['inputs_left'] = inputs_left
                new_candidates.append(x)

            candidates = new_candidates

    def to_basic_block(x):
        gmid = x['bb'][0]
        path = global_id_to_info[gmid]['path']
        offset = x['bb'][1]
        
        return BasicBlock(path, offset, {
            'nb_inputs': len(x['inputs']),
            'size': sizes[x['bb']],
            'save_size': save_sizes[x['bb']],
            'overall_coverages_asc': x['overall_coverages_asc'],
            'differing_coverages_asc': x['differing_coverages_asc'],
            'combined_coverages_asc': x['combined_coverages_asc'],
            'appearances': appearances[x['bb']],
            }
        )

    blocks = frozenset([to_basic_block(x) for x in solution])

    logging.info("For %.1f%% overall and %.1f%% differing bound, the solution is:" % (100*cap_tol_overall, 100*cap_tol_differing))
    for i, x in enumerate(blocks):
        logging.info(
            "  {i}.) {offset:#010x} in module {module_id} ({module_name}) sized {size} bytes with a minimum overall coverage of {ocov:.0f}% and minimum differing coverage of {dcov:.0f}%".format(
                i=i,
                offset=x.offset,
                module_id=global_path_to_info[x.module_path]['id'],
                module_name=os.path.split(x.module_path)[1],
                size=x.info['size'],
                ocov=100*min(x.info['overall_coverages_asc']),
                dcov=100*min(x.info['differing_coverages_asc']),
            )
        )

    name = 'covtrace_overall_%.6f_differing_%.6f_%s' % (cap_tol_overall, cap_tol_differing, objective)
        
    return Solution(name, blocks, {
        'cap_tol_overall': cap_tol_overall,
        'cap_tol_differing': cap_tol_differing,
        'weight_overall': weight_overall,
        'weight_differing': weight_differing,
        'objective': objective,
        'only_from_exe': only_from_exe,
        'min_size': min_size,
        'exe_name': effective_blocks_name(blocks) + '.exe',
        })
