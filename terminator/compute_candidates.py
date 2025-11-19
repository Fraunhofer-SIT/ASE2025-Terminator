
import argparse
from dataclasses import dataclass
import datetime
import os
import hashlib
import itertools
import json
import logging
import math
import numpy as np
import re
import scipy.stats as st
import shutil
import statistics
import subprocess
import tempfile
import time
import tqdm

import binary
import candidates
import drcov
import iopaths
import traces

class TemporaryPatch:
    def __init__(self, solution, patch):
        self.solution = solution
        self.patch = patch

    def __enter__(self):
        for orig, repl in self.patch.items():
            orig_dir, orig_name = os.path.split(orig)
            backup = os.path.join(orig_dir, orig_name + '.backup')

            if os.path.exists(backup):
                raise Exception("Backup already exists in %s" % backup)

            logging.debug("Renaming %s -- %s -- %s" % (orig, backup, repl))
            os.rename(orig, backup)
            shutil.copy(repl, orig)
    
    def __exit__(self, exc_type, exc_value, traceback):
        for orig, repl in self.patch.items():
            orig_dir, orig_name = os.path.split(orig)
            backup = os.path.join(orig_dir, orig_name + '.backup')

            if orig_name.endswith('.exe'):
                subprocess.run(
                      "TASKKILL /F /IM %s" % (orig_name)
                    , stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )

            logging.debug("Renaming %s -- %s" % (orig, backup))
            os.remove(orig)
            os.rename(backup, orig)

def temporary_patch(target_path, candidates_dir, solution):
    binary_dir = os.path.join(candidates_dir, 'binary')
    if not os.path.isdir(binary_dir):
        raise Exception("Binary dir does not exist:\n     %s" % binary_dir)

    if not target_path is None:
        name = candidates.effective_solution_name(solution) + '.exe'
        path = os.path.join(binary_dir, 'updated_' + name)
        if os.path.isfile(path):
            return TemporaryPatch(solution, {target_path: path})

        path = os.path.join(binary_dir, name)
        if os.path.isfile(path):
            return TemporaryPatch(solution, {target_path: path})
    
    name = candidates.effective_solution_name(solution)
    path = os.path.join(binary_dir, name)
    if os.path.isdir(path):
        with open(os.path.join(path, 'patch.json')) as file:
            patch = json.loads(file.read())

        return TemporaryPatch(solution, patch)

    raise Exception("Patch not found for %s with effective name %s in %s" % (solution.name, name, candidates_dir))

def args_to_candidate_list(args_list):
    compute_list = []
    pattern = re.compile('^(o(\d+))?(d(\d+))?(se|es|sl|ls)?(vo(\d+)vd(\d+))?$')
    for x in args_list:
        match = re.match(pattern, x)
        if not match:
            raise Exception("Incorrect argument %s" % x)

        if not match.group(1) and not match.group(3):
            raise Exception("Need a bound on overall or differing or both")

        bounds = []
        if match.group(1):
            # For example: 095 -> 0.095
            value = int(match.group(2)) / (10 ** len(match.group(2)))
            cap_tol_overall = value;
            bounds.append('overall_%f' % value)
        else:
            cap_tol_overall = None

        if match.group(3):
            # For example: 095 -> 0.095
            value = int(match.group(4)) / (10 ** len(match.group(4)))
            cap_tol_differing = value;
            bounds.append('differing_%f' % value)
        else:
            cap_tol_differing = None

        bound = '_'.join(bounds)

        if match.group(5) == 'sl':
            objective = 'smallest_latest'
        elif match.group(5) == 'ls':
            objective = 'latest_smallest'
        elif match.group(5) == 'se':
            objective = 'smallest_earliest'
        elif match.group(5) == 'es':
            objective = 'earliest_smallest'
        else:
            objective = 'smallest_earliest'

        if match.group(6):
            weight_o = int(match.group(7))
            weight_d = int(match.group(8))
        else:
            weight_o = 1 if cap_tol_overall else 0
            weight_d = 1 if cap_tol_differing else 0

        weight = 'weights_o%d_d%d' % (weight_o, weight_d)
        name = bound + '_' + objective + '_' + weight

        compute_list.append((name, cap_tol_overall, weight_o, cap_tol_differing, weight_d, objective))
    
    res = frozenset(compute_list)
    return res

@dataclass(frozen=True)
class AlgorithmConfig:
    name: str
    cap_tol_overall: float
    weight_o: int
    cap_tol_differing: float
    weight_d: int
    objective: str
    short: str

def solution_filename_to_config(filename):
    # This is not 100% accurate, but good enough.
    pattern = re.compile('(overall_([\d\.]+))?_?(differing_([\d\.]+))?_(smallest_latest|latest_smallest|smallest_earliest|earliest_smallest)_weights_o(\d+)_d(\d+)\.json')
    match = re.match(pattern, filename)

    if not match:
        return None

    cap_tol_overall = 0
    cap_tol_differing = 0

    if match.group(1):
        cap_tol_overall = float(match.group(2))
    if match.group(3):
        cap_tol_differing = float(match.group(4))

    objective = match.group(5)

    weight_o = int(match.group(6))
    weight_d = int(match.group(7))

    short = ''
    return AlgorithmConfig(match.group(0)[:-5], cap_tol_overall, weight_o, cap_tol_differing, weight_d, objective, short)

def main(args):
    logging.basicConfig(level=getattr(logging, args.log.upper(), logging.INFO))

    if not args.output_dir is None:
        output_dir = os.path.abspath(args.output_dir)
    else:
        assert(not args.find_output_dir_in is None)
        output_dir = iopaths.find_newest_output_dirname(os.path.abspath(args.find_output_dir_in))
        logging.info("Using the output directiory %s" % output_dir)

    if not args.compute is None:
        compute_list = args_to_candidate_list(args.compute)
    else:
        if args.data_type == 'covtrace':
            # mine = [
            #     # Smallest earliest
            #     'o85sevo1vd0', 'o90sevo1vd0',
            #     'd85sevo0vd1', 'd90sevo0vd1',
            #     'o90d70sevo1vd1', 'o85d85sevo1vd1', 
            #     # Latest smallest
            #     'o0d0lsvo1vd0', 'o0d0lsvo0vd1', 'o0d0lsvo1vd1', 
            #     # Smallest latest
            #     'o0d0slvo1vd0', 'o50slvo1vd0', 'o75slvo1vd0', 'o90slvo1vd0', 
            #     'o0d0slvo0vd1', 'd50slvo0vd1', 'd75slvo0vd1', 'd90slvo0vd1', 
            #     'o0d0slvo1vd1', 'o75d50slvo1vd1', 'o50d50slvo0vd1', 
            # ]

            # mine = [
            #     'o0sevo1vd1',
            #     'o5sevo1vd1',
            #     'o10sevo1vd1',
            #     'o15sevo1vd1',
            #     'o20sevo1vd1',
            #     'o25sevo1vd1',
            #     'o30sevo1vd1',
            #     'o35sevo1vd1',
            #     'o40sevo1vd1',
            #     'o45sevo1vd1',
            #     'o50sevo1vd1',
            #     'o55sevo1vd1',
            #     'o60sevo1vd1',
            #     'o65sevo1vd1',
            #     'o70sevo1vd1',
            #     'o75sevo1vd1',
            #     'o80sevo1vd1',
            #     'o85sevo1vd1',
            #     'o90sevo1vd1',
            #     'o95sevo1vd1',
            #     'o99sevo1vd1',
            #     'd0sevo1vd1',
            #     'd5sevo1vd1',
            #     'd10sevo1vd1',
            #     'd15sevo1vd1',
            #     'd20sevo1vd1',
            #     'd25sevo1vd1',
            #     'd30sevo1vd1',
            #     'd35sevo1vd1',
            #     'd40sevo1vd1',
            #     'd45sevo1vd1',
            #     'd50sevo1vd1',
            #     'd55sevo1vd1',
            #     'd60sevo1vd1',
            #     'd65sevo1vd1',
            #     'd70sevo1vd1',
            #     'd75sevo1vd1',
            #     'd80sevo1vd1',
            #     'd85sevo1vd1',
            #     'd90sevo1vd1',
            #     'd95sevo1vd1',
            #     'd99sevo1vd1',
            # ]

            # mine = [
            #     'o95sevo1vd1',
            #     'o955sevo1vd1',
            #     'o96sevo1vd1',
            #     'o965sevo1vd1',
            #     'o97sevo1vd1',
            #     'o957sevo1vd1',
            #     'o98sevo1vd1',
            #     'o985sevo1vd1',
            #     'o99sevo1vd1',
            #     'd95sevo1vd1',
            #     'd99sevo1vd1',
            # ]

            mine = [
                'o0slvo1vd1',
                'o10esvo1vd1',
                'o20esvo1vd1',
                'o30esvo1vd1',
                'o40esvo1vd1',
                'o50esvo1vd1',
                'o60esvo1vd1',
                'o70esvo1vd1',
                'o80esvo1vd1',
                'o90esvo1vd1',
                'o95esvo1vd1',
                'o10sevo1vd1',
                'o20sevo1vd1',
                'o30sevo1vd1',
                'o40sevo1vd1',
                'o50sevo1vd1',
                'o60sevo1vd1',
                'o70sevo1vd1',
                'o80sevo1vd1',
                'o90sevo1vd1',
                'o95sevo1vd1',
                'o0lsvo1vd1',
                'd10esvo1vd1',
                'd20esvo1vd1',
                'd30esvo1vd1',
                'd40esvo1vd1',
                'd50esvo1vd1',
                'd60esvo1vd1',
                'd70esvo1vd1',
                'd80esvo1vd1',
                'd90esvo1vd1',
                'd95esvo1vd1',
                'd10sevo1vd1',
                'd20sevo1vd1',
                'd30sevo1vd1',
                'd40sevo1vd1',
                'd50sevo1vd1',
                'd60sevo1vd1',
                'd70sevo1vd1',
                'd80sevo1vd1',
                'd90sevo1vd1',
                'd95sevo1vd1',
            ]

            compute_list = args_to_candidate_list(mine)
        else:
            bounds = ['o', 'd']
            objectives = ['se']
            values = [70, 75, 80, 85, 90, 95, 99]

            compute_list = args_to_candidate_list([b + str(v) + o for b in bounds for o in objectives for v in values])
        
    candidates_container_dir = os.path.join(output_dir, 'candidates')
    iopaths.ensure_dir(candidates_container_dir)

    candidates_dir = None
    if args.cont:
        if args.continue_in:
            candidates_dir = os.path.join(candidates_container_dir, args.continue_in)
            if not os.path.exists(candidates_dir) or not os.path.isdir(candidates_dir):
                raise Exception("Directory %s does not exist" % candidates_dir)
        else:
            pattern = re.compile('\d{8}_\d{6}')
            candidates_dir = iopaths.find_maximum_file(candidates_container_dir, lambda x: not re.match(pattern, x) is None)
            if not candidates_dir is None and not os.path.isdir(candidates_dir):
                raise Exception("This is not a directory: %s" % candidates_dir)
    
    if not args.cont or candidates_dir is None:
        now = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        candidates_dir = os.path.join(candidates_container_dir, now)
        iopaths.ensure_dir(candidates_dir)

    rootLogger = logging.getLogger()
    fileHandler = logging.FileHandler(os.path.join(candidates_dir, 'log.txt'))
    #fileHandler.setFormatter(logFormatter)
    rootLogger.addHandler(fileHandler)
    
    #consoleHandler = logging.StreamHandler()
    #consoleHandler.setFormatter(logFormatter)
    #rootLogger.addHandler(consoleHandler)

    postprocess_traces_in_dir(output_dir, candidates_dir, compute_list, args)

def postprocess_traces_in_dir(output_dir, candidates_dir, compute_list, options):
    # This will be a set of frozensets
    solutions = compute_candidates(output_dir, candidates_dir, compute_list, options)
    solutions = merge_solutions(solutions)

    if options.syminfo:
        logging.debug("Determining symbols info…")
        syminfo = {}
        for solution in solutions:
            for x in solution.blocks:
                info = symbols_info(options.syminfo_path, x)
                syminfo[x] = info
                        
    message = "Candidates for auto-exit are:\n"
    for i, solution in enumerate(solutions):
        message += "  Candidate no. %d:\n" % (i + 1)
        message += "    Has blocks:\n"
        for j, x in enumerate(solution.blocks):
            message += '    %2d.) %#010x in %s\n' % (j + 1, x.offset, x.module_path)
            if options.syminfo:
                message += ('         %s\n' % syminfo[x]['summary'])
        message += ("    From solutions:\n")
        for j, x in enumerate(solution.info['parts']):
            message += ('    %2d.) %s\n' % (j + 1, x['name']))
            print(x)
            print("---------------")
            print(x['info'])
            for key, val in x['info'].items():
                if type(val).__module__ == np.__name__:
                    x['info'][key] = val.item()
            info = '\n'.join(['        ' + y for y in (json.dumps(x['info'], indent=2)).splitlines()]) + '\n'
            message += ('        Info:\n')
            message += (info)

    logging.info(message)

    if options.patch:
        logging.debug("Now patching…")
        
        for solution in solutions:
            patched_path = patch_solution(candidates_dir, solution, options)
    else:
        logging.info("You asked me NOT to patch the binaries.")

def compute_candidates(output_dir, candidates_dir, compute_list, options):
    found_candidates = set()

    pred_accept_mod_path = lambda x: accept_mod_path(options, x)

    for name, cap_tol_overall, weight_o, cap_tol_differing, weight_d, objective in compute_list:
        # if options.data_type == 'drcov':
        #     if objective != 'smallest_earliest' or bound == 'combined':
        #         raise Exception("Unsupported")

        #     found_candidates.add(load_or_compute_and_store(
        #         candidates_dir, name, options,
        #         lambda: candidates.coverage_cap_omegafast(
        #             output_dir,
        #             options.min_bb_size,
        #             cap_tol_differing if not cap_tol_differing is None else cap_tol_overall,
        #             options.only_from_exe,
        #             'diff' if not cap_tol_differing is None else None,
        #             pred_accept_mod_path
        #         )
        #     ))
        if options.data_type == 'drcov':
            found_candidates.add(load_or_compute_and_store(
                candidates_dir, name, options,
                lambda: candidates.flexible_coverage_cap_drcov(
                    output_path=output_dir,
                    min_size=options.min_bb_size,
                    cap_tol_overall=cap_tol_overall,
                    weight_overall=weight_o,
                    cap_tol_differing=cap_tol_differing,
                    weight_differing=weight_d,
                    only_from_exe=options.only_from_exe,
                    objective=objective,
                    accept_mod_path=pred_accept_mod_path,
                )
            ))
        elif options.data_type == 'trace':
            if objective != 'smallest_earliest' or bound == 'combined':
                raise Exception("Unsupported")

            found_candidates.add(load_or_compute_and_store(
                candidates_dir, name, options,
                lambda: candidates.coverage_cap(
                    output_dir,
                    options.min_bb_size,
                    cap_tol_differing if not cap_tol_differing is None else cap_tol_overall,
                    options.only_from_exe,
                    'diff' if not cap_tol_differing is None else None,
                )
            ))
        elif options.data_type == 'covtrace':
            found_candidates.add(load_or_compute_and_store(
                candidates_dir, name, options,
                lambda: candidates.flexible_coverage_cap_covtrace(
                    output_path=output_dir,
                    min_size=options.min_bb_size,
                    cap_tol_overall=cap_tol_overall,
                    weight_overall=weight_o,
                    cap_tol_differing=cap_tol_differing,
                    weight_differing=weight_d,
                    only_from_exe=options.only_from_exe,
                    objective=objective,
                    accept_mod_path=pred_accept_mod_path,
                )
            ))
        elif options.data_type == 'dbg-covtrace':
            found_candidates.add(load_or_compute_and_store(
                candidates_dir, name, options,
                lambda: candidates.flexible_coverage_cap_covtrace(
                    output_path=output_dir,
                    min_size=options.min_bb_size,
                    cap_tol_overall=cap_tol_overall,
                    weight_overall=weight_o,
                    cap_tol_differing=cap_tol_differing,
                    weight_differing=weight_d,
                    only_from_exe=options.only_from_exe,
                    objective=objective,
                    accept_mod_path=pred_accept_mod_path,
                    read_trace=lambda x: traces.read_dbgcov_trace_from(x, options.only_main_thread),
                    ub_t=options.ub_time,
                )
            ))

    # Filter out the empty candidates, then freeze the set
    found_candidates = frozenset([x for x in found_candidates if not x is None])

    return found_candidates

def accept_mod_path(options, x):
    restrict = False

    if options.mod_prefixes:
        restrict = True
        for p in options.mod_prefixes:
            if x.lower().startswith(p.lower()):
                return True

    if options.mod_infixes:
        restrict = True
        for p in options.mod_infixes:
            if p.lower() in x.lower():
                return True

    if options.mod_suffixes:
        restrict = True
        for p in options.mod_suffixes:
            if x.lower().endswith(p.lower()):
                return True

    return not restrict

def load_or_compute_and_store_old(candidates_dir, name, options, computer):
    store_path = os.path.join(candidates_dir, name + '.txt')

    # Compute and store
    if not os.path.isfile(store_path):
        logging.info('Did not find %s, will compute now…' % name)

        start = time.time()
        cs = computer()
        elapsed = time.time() - start

        logging.info("Computation of %s took %.2f seconds" % (name, elapsed))
        
        with open(store_path, 'w') as file:
            for x in cs:
                if x is None:
                    continue
                
                file.write('%#018x %s\n' % (x.offset, x.module_path))

        return cs

    # Load
    with open(store_path, 'r') as file:
        content = file.readlines()
    
    cs = set()
    for line in content:
        offset_str = line[0:18]
        offset = int(offset_str, 16)
        module_path = line[19:].strip()

        cs.add(candidates.Candidate(module_path, offset, None, None, None))

    logging.info('Loaded %s from disk' % name)

    return frozenset(cs)

def load_or_compute_and_store(candidates_dir, name, options, computer):
    store_path = os.path.join(candidates_dir, name + '.json')

    # Compute and store
    if not os.path.isfile(store_path):
        logging.info('Did not find %s in %s, will compute now…' % (name, store_path))

        start = time.time()
        solution = computer()
        elapsed = time.time() - start

        logging.info("Computation of %s took %.2f seconds" % (name, elapsed))
        
        candidates.write_solution(store_path, solution)

        return solution

    # Load
    solution = candidates.load_solution(store_path)
    
    logging.info('Loaded %s from disk' % name)

    return solution

def patch_solution(candidates_dir, solution, options):
    name = candidates.effective_solution_name(solution)

    parent_dir = os.path.join(candidates_dir, 'binary')
    solution_dir = os.path.join(parent_dir, name)
    iopaths.ensure_dir(solution_dir)

    sorted_blocks = sorted(solution.blocks, key=lambda x: x.module_path)
    grouped_blocks = itertools.groupby(sorted_blocks, key=lambda x: x.module_path)
    patch = {}

    for module_path, blocks in grouped_blocks:
        module_name = os.path.split(module_path)[1]
        patched_path = os.path.join(solution_dir, module_name)
    
        binary.patch_file(module_path, [x.offset for x in blocks], patched_path, bits=options.bits, fastfail=options.fastfail, bp=options.bp, exit_code=options.exit_code, exit=options.exit)
        patch[module_path] = patched_path
    
    patched_path = os.path.join(solution_dir, 'patch.json')
    with open(patched_path, 'w') as patch_file:
        patch_file.write(json.dumps(patch, indent=2))

    return solution_dir

def symbols_info(syminfo_path, x, delay=50):
    _, modname = os.path.split(x.module_path)

    cmd = subprocess.list2cmdline([syminfo_path, modname, '%x' % x.offset, str(delay), x.module_path])
    logging.debug("Running external tool for symbol info\n    %s" % cmd)

    # Run external command and capture the output to stdout
    process = subprocess.Popen(
          cmd
        , shell=False
        , stdout=subprocess.PIPE
        , text=True
    )

    # Collect the console output of TimedRun.exe
    outs, errs = process.communicate()
    output = str(outs)

    re_1 = re.compile('SymbolAt result:')
    re_2 = re.compile('Module:')
    re_3 = re.compile('  Name: (.+)')
    re_4 = re.compile('  Path: (.+)')
    re_5 = re.compile('Symbol:')
    re_6 = re.compile('  Name: (.+)')
    re_7 = re.compile('  Path: (.+)')
    re_8 = re.compile('  Line: (\d+)')

    info = {}
    state = 1

    for line in output.split('\n'):
        if state == 1:
            if re.match(re_1, line):
                state = 2
        if state == 2:
            if re.match(re_2, line):
                state = 3
        if state == 3:
            match = re.match(re_3, line)
            if match:
                info['mod_name'] = match.group(1)
                state = 4
        if state == 4:
            match = re.match(re_4, line)
            if match:
                info['mod_path'] = match.group(1)
                state = 5
        if state == 5:
            if re.match(re_5, line):
                state = 6
        if state == 6:
            match = re.match(re_6, line)
            if match:
                info['sym_name'] = match.group(1)
                state = 7
        if state == 7:
            match = re.match(re_7, line)
            if match:
                info['sym_path'] = match.group(1)
                state = 8
        if state == 8:
            match = re.match(re_8, line)
            if match:
                info['sym_line'] = match.group(1)
                state = 9

    summary = 'symbol info requested, but not available'
    if state >= 7:
        summary = info['sym_name']
    if state >= 9:
        summary = summary + ' in line ' + info['sym_line']
    if state >= 8:
        summary = summary + ' in source ' + info['sym_path']

    info['summary'] = summary

    return info

def merge_solutions(solutions):
    new_solutions = []
    sorted_solutions = sorted(solutions, key=lambda x: (hash(x.blocks), x.blocks))
    i = 0
    for k, g in itertools.groupby(sorted_solutions, key=lambda x: (hash(x.blocks), x.blocks)):
        sols = list(g)
        name = 'merged_%d' % i
        info = {
            'parts': [{'name': s.name, 'info': s.info} for s in sols]
        }
        s = candidates.Solution(name, sols[0].blocks, info)

        new_solutions.append(s)
        i += 1

    return new_solutions

# Entry point: parse arguments and call main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=(
        "None"
    ))

    parser.add_argument("--output-dir", required=False, default=None, help="Root of the output directory created by compute_traces.py.")
    parser.add_argument("--find-output-dir-in", required=False, default=None)
    parser.add_argument("--log", required=False, default="INFO")
    parser.add_argument("--continue", dest='cont', action='store_true', required=False, default=False
        , help="Whether an unfinished computation should be continued from a subdirectory of the candidates/ folder."
    )
    parser.add_argument("--continue-in", required=False, default=None
        , help="The subdirectory of the candidates/ folder from which the unfinished computation shall be continued."
    )
    parser.add_argument("--compute", required=False, action='append', type=str, default=None)
    parser.add_argument("--min-bb-size", required=False, type=int, default=12)
    #parser.add_argument("--output-symbols", required=False, type=bool, default=True)

    #parser.add_argument("--dynamorio-dir", required=False, default='C:\\Users\\kolvenba\\Projekte\\DynamoRIO-Windows-7.91.18319\\bin64'#default='C:\\Users\\kolvenba\\Projekte\\DynamoRIO-Windows-7.91.18319\\bin64'
    #parser.add_argument("--dynamorio-dir", required=False, default='C:\\Users\\kolvenba\\Projekte\\dynamorio\\DynamoRIO-Windows-7.91.18319\\bin64'#default='C:\\Users\\kolvenba\\Projekte\\DynamoRIO-Windows-7.91.18319\\bin64'
    parser.add_argument("--dynamorio-dir", required=False, default='C:\\Users\\kolvenba\\Projekte\\dynamorio\\DynamoRIO-Windows-7.91.18263-0\\bin64'#default='C:\\Users\\kolvenba\\Projekte\\DynamoRIO-Windows-7.91.18319\\bin64'
        , help=(
            "Path to the binary directory of DynamoRIO, usually ending with "
            "/bin32 or /bin64."
    ))
    parser.add_argument("--no-patch", required=False, action='store_false', dest='patch')
    parser.add_argument("--patch", required=False, action='store_true', dest='patch')
    parser.set_defaults(patch=True)

    parser.add_argument("--bits", required=False, type=int, default=64)

    parser.add_argument("--no-syminfo", required=False, action='store_false', dest='syminfo')
    parser.add_argument("--syminfo", required=False, action='store_true', dest='syminfo')
    parser.add_argument("--syminfo-path", required=False, type=str, default='C:\\Users\\kolvenba\\Projekte\\research\\fuzzing\\CustomFuzzer\\x64\\Release\\SymbolsAt.exe')
    parser.set_defaults(syminfo=True)

    parser.add_argument("--no-only-from-exe", required=False, action='store_false', dest='only_from_exe')
    parser.add_argument("--only-from-exe", required=False, action='store_true', dest='only_from_exe')
    parser.set_defaults(only_from_exe=True)

    parser.add_argument("--mod-prefix", required=False, action='append', type=str, dest='mod_prefixes')
    parser.set_defaults(mod_prefixes=[])
    parser.add_argument("--mod-infix", required=False, action='append', type=str, dest='mod_infixes')
    parser.set_defaults(mod_infixes=[])
    parser.add_argument("--mod-suffix", required=False, action='append', type=str, dest='mod_suffixes')
    parser.set_defaults(mod_suffixes=[])
    
    parser.add_argument("--fastfail", required=False, action='store_true', dest='fastfail')
    parser.add_argument("--no-fastfail", required=False, action='store_false', dest='fastfail')
    parser.set_defaults(fastfail=True)
    
    parser.add_argument("--breakpoint", required=False, action='store_true', dest='bp')
    parser.add_argument("--no-breakpoint", required=False, action='store_false', dest='bp')
    parser.set_defaults(bp=False)
    
    parser.add_argument("--exit", required=False, action='store_true', dest='exit')
    parser.add_argument("--no-exit", required=False, action='store_false', dest='exit')
    parser.set_defaults(exit=False)
    
    parser.add_argument("--exit-code", required=False, type=int, default=0)
    
    parser.add_argument("--ub-time", required=False, default=math.inf, type=int)

    def data_type(x):
        if x in ['covtrace', 'trace', 'drcov', 'dbg-covtrace']:
            return x
        else:
            raise Exception("Bad data type")

    parser.add_argument("--data-type", required=False, type=data_type, default='covtrace')
    
    parser.add_argument("--only-main-thread", required=False, action='store_true', dest='only_main_thread')
    parser.add_argument("--all-threads", required=False, action='store_false', dest='only_main_thread')
    parser.set_defaults(only_main_thread=True)

    args = parser.parse_args()

    if args.output_dir is None and args.find_output_dir_in is None:
        print("[--] Must either specify output-dir or find-output-dir-in")
        exit()

    main(args)
