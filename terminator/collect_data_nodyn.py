
import argparse
import datetime
import json
import logging
import math
import subprocess
import time
import tqdm
import traces
import os
import re
import datetime
import shutil

import iopaths

def main(args):
    logging.basicConfig(level=getattr(logging, args.log.upper(), logging.INFO))

    #if os.path.exists(args.output_dir) and not args.create_subdir and not args.reuse_newest_subdir:
    #    print("[--] Output directory exists")
    #    return

    if args.reuse_newest_subdir:
        _, name = os.path.split(args.target_path)
        output_dir = iopaths.find_newest_output_dirname(args.output_dir)
    elif args.create_subdir:
        _, name = os.path.split(args.target_path)
        output_dir = iopaths.find_unused_output_dirname(args.output_dir, name)
    else:
        output_dir = args.output_dir

    if output_dir is None:
        print("[--] Could not determine output directory")
        return

    working_dir = os.path.join(output_dir, "working")
    log_dir = os.path.join(output_dir, "log")

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print("[+] Created %s" % output_dir)

    if not os.path.exists(working_dir):
        os.makedirs(working_dir)
        print("[+] Created %s" % working_dir)
    
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        print("[+] Created %s" % log_dir)

    ida_cache_dir = os.path.join(output_dir, 'ida_cache')
    if not os.path.exists(ida_cache_dir):
        os.makedirs(ida_cache_dir)
        print("[+] Created %s" % ida_cache_dir)

    #——————————————————————————————————————————————————
    # Dump configuration
    #

    now = datetime.datetime.now()    
    now_str = now.strftime('%Y%m%d_%H%M%S')
    config_path = os.path.join(output_dir, 'config_%s.json' % now_str)
    if os.path.exists(config_path):
        print("[--] Config file already exists")
        exit(1)

    with open(config_path, "w") as config_file:
        config_file.write(json.dumps(vars(args), indent=4))

    analyze_target_on_input_directory(args.input_dir, output_dir, working_dir, log_dir, ida_cache_dir, args.target_path, args)

    return output_dir

def analyze_target_on_input_directory(input_dir, output_dir, working_dir, log_dir, ida_cache_dir, target_path, args):
    """Analyzes the target for all input files located in a directory."""

    all_files = os.listdir(input_dir)
    lower_pc = min(100, max(args.only_from if args.only_from else 0, 0))
    upper_pc = min(100, max(args.only_to if args.only_to else 100, lower_pc))
    lower = math.floor(len(all_files) * lower_pc / 100)
    upper = math.ceil(len(all_files) * upper_pc / 100)

    for filename in tqdm.tqdm(all_files[lower:upper], "Input files"):
        input_path = os.path.realpath(os.path.join(os.getcwd(), input_dir, filename))

        if not os.path.isfile(input_path) and not os.path.islink(input_path):
            continue

        analyze_target_on_input_file(output_dir, working_dir, log_dir, ida_cache_dir, target_path, input_path, filename, args)

def analyze_target_on_input_file(output_dir, working_dir, log_dir, ida_cache_dir, target_path, input_path, input_filename, options):
    """Analyzes the target for a single input file."""

    log_dir_for_input = os.path.join(log_dir, input_filename)

    if not os.path.exists(log_dir_for_input):
        os.makedirs(log_dir_for_input)
        logging.debug("[+] Created %s" % log_dir_for_input)
    elif options.cont:
        logging.debug("[!] Directory %s exists, skipping" % log_dir_for_input)
        return

    input_log_dir_relative_to_working_dir = os.path.relpath(log_dir_for_input, working_dir)

    utility_path = options.path
    script_path = options.script_path
    ida_path = options.ida_path
    target_invokation = replace_placeholders(options.target_invokation, target_path, input_path, input_log_dir_relative_to_working_dir)

    return run_utility(
        output_dir,
        working_dir,
        log_dir,
        ida_cache_dir,
        utility_path,
        ida_path,
        script_path,
        target_path,
        log_dir_for_input,
        target_invokation,
        options.target_timeout,
        options.precomputed_bb_list
        )

def replace_placeholders(haystack, target_path, input_path, input_log_dir_relative_to_working_dir):
    result = haystack

    result = result.replace('@app@', target_path)
    result = result.replace('@log@', '"' + input_log_dir_relative_to_working_dir + '"')
    result = result.replace('@input@', '"' + input_path + '"')

    return result

def run_utility(output_dir, working_dir, log_dir, ida_cache_dir, utility_path, ida_path, script_path, target_path, log_dir_for_input, target_invokation, target_timeout, precomputed_bb_list):
    """Executes the target with DynamoRIO on a specified input file"""

    #
    # Step 1: Run covtrace utility in a new process (this script does not wait 
    # for the process to terminate)
    #

    utility_dir, utility_name = os.path.split(utility_path)

    if precomputed_bb_list:
        _, precomputed_bb_list_name = os.path.split(precomputed_bb_list)

        hex_re = re.compile("^[a-fA-F0-9]+$")
        m = hex_re.match(precomputed_bb_list_name)
        if m:
            precomputed_bb_list_dest_name = precomputed_bb_list_name
        else:
            logging.info("The filename of the precomputed BB list is not a hex hash. I will copy the file and assume it contains basic blocks of the main executable!")

            hash_path = os.path.join(utility_dir, 'Hash.exe')
            process_hash = subprocess.run(
                [hash_path, target_path]
                , shell=False
                , stdout=subprocess.PIPE
                , stderr=subprocess.STDOUT
                , text=True
            )

            if process_hash.returncode != 0:
                logging.warning("Something is wrong with the hash utility. I have to use the path you supplied. The exit code was: %d" % process_hash.returncode)
                precomputed_bb_list_dest_name = precomputed_bb_list_name
            else:
                capture_re = re.compile("BB file name:\s+(.+)\n")
                m = capture_re.search(process_hash.stdout)
                if not m:
                    logging.warning("Something is wrong with the hash utility. I have to use the path you supplied. The output was: %s" % process_hash.stdout)
                    precomputed_bb_list_dest_name = precomputed_bb_list_name
                else:
                    precomputed_bb_list_dest_name = m.group(1)
                    logging.debug("Using basic block file name: %s" % precomputed_bb_list_dest_name)

        precomputed_bb_list_dest_path = os.path.join(ida_cache_dir, precomputed_bb_list_dest_name)
        shutil.copy(precomputed_bb_list, precomputed_bb_list_dest_path)

    target_dir, target_name = os.path.split(target_path)
    utility_invoke_args = [
        utility_path,
        ida_path,
        script_path,
        ida_cache_dir,
        target_path,
        target_invokation,
        str(1000*target_timeout),
        os.path.join(log_dir_for_input, 'covtrace_globalized.bin'),
        os.path.join(log_dir_for_input, 'modules.txt'),
        os.path.join(log_dir_for_input, 'time.txt'),
        str(0)
    ]
    cmd = subprocess.list2cmdline(utility_invoke_args)

    logging.debug("[*] Running covtrace utility with\n    %s" % cmd)
    
    start_time = time.time()

    process_covtrace = subprocess.run(
          cmd
        , cwd=working_dir
        , shell=False
        , stdout=subprocess.PIPE
        , stderr=subprocess.STDOUT
        , text=True
    )

    with open(os.path.join(log_dir_for_input, 'log.txt'), 'w') as log:
        log.write(process_covtrace.stdout)

    if process_covtrace.returncode != 0:
        logging.error("[-] Coverage tool did not terminate successfully.")
    else:
        modules = {}
        with open(os.path.join(log_dir_for_input, 'modules.txt'), 'r') as modules_file:
            for line in modules_file.readlines():
                if not line:
                    continue

                parts = line.strip().split('\t')
                id = int(parts[0])
                start = int(parts[1], base=16)
                tracked = parts[2]
                end = int(parts[3], base=16)
                path = parts[4]

                if not tracked:
                    continue

                modules[path] = {
                    'id': id,
                    'start': start,
                    'end': end,
                }

        with open(os.path.join(log_dir_for_input, 'covtrace_globalized_modtab.json'), 'w') as global_modtab:
            global_modtab.write(json.dumps(modules, indent=2))
    
    #
    # Step 4: Recreate the working directory, deleting all files that have 
    # been created by the target.
    #

    nb_fails = 0

    while True:
        try:
            shutil.rmtree(working_dir)
            break
        except Exception:
            nb_fails += 1

            logging.error(
                ("[-] Could not remove working dir (attempt %d): %s\n"
                 "Maybe the process is still running? I will now attempt to kill the processes and then retry…"
                ) % (nb_fails, working_dir)
                )
            
            subprocess.run(
                "TASKKILL /T /F /IM " + utility_name
                , stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

            if nb_fails >= 2:
                # Don’t kill the target by name straight away, because there 
                # is a chance that there are other processes running by that 
                # name, and it’s really annoying if they get killed like that 
                # (e.g., if you’re debugging).
                subprocess.run(
                    "TASKKILL /T /F /IM " + target_name
                    , stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )

            time.sleep(1)
            continue
        
    os.makedirs(working_dir)

# Entry point: parse arguments and call main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=(
        "None"
    ))

    parser.add_argument("--input-dir", required=True
        , help=(
            "Path to the directory which contains (nothing but) all the input files."
    ))

    parser.add_argument("--output-dir", required=True, help="Root of the output directory. Must not exist.")
    
    parser.add_argument("--create-subdir", required=False, dest='create_subdir', action='store_true')
    parser.add_argument("--no-create-subdir", required=False, dest='create_subdir', action='store_false')
    parser.set_defaults(create_subdir=False)
    
    parser.add_argument("--reuse-newest-subdir", required=False, dest='reuse_newest_subdir', action='store_true')
    parser.add_argument("--no-reuse-newest-subdir", required=False, dest='reuse_newest_subdir', action='store_false')
    parser.set_defaults(reuse_newest_subdir=False)

    parser.add_argument("--path", required=True, help="Path to the CoverageTrace executable file.")
    parser.add_argument("--script-path", required=True, help="Path to the BB extraction IDA python script.")
    parser.add_argument("--ida-path", required=True, help="Path to IDA Pro idat64.exe.")
    parser.add_argument("--precomputed-bb-list", required=False, type=str, default=None)

    parser.add_argument("--target-path", required=True, help="Path to the executable file.")
    parser.add_argument("--target-timeout", required=False, type=int, default=10
        , help="Time in seconds after which target will be terminated."
        )

    parser.add_argument("--target-invokation", required=False, default="@app@ @input@", help=(
        "Command pattern to invoke the target:\n"
        "    /path/to/foo.exe -input /path/to/input\n"
        "In the string, @app@ and @input@ are replaced by the paths to"
        "the target app and the current input file."
        ))

    parser.add_argument("--log", required=False, default="INFO")
    parser.add_argument("--continue", required=False, action='store_true', dest='cont')

    parser.add_argument("--only-from", required=False, type=int, default=None
        , help="Start from this percentage of all input files, ignoring those before."
    )
    parser.add_argument("--only-to", required=False, type=int, default=None
        , help="End at this percentage of all input files, ignoring those after."
    )
    parser.set_defaults(cont=False)

    args = parser.parse_args()

    main(args)
