
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
import numpy as np
import datetime
import psutil
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

    analyze_target_on_input_directory(args.dynamorio_dir, args.input_dir, output_dir, working_dir, log_dir, args.target_path, args)

    return output_dir

def analyze_target_on_input_directory(dynamorio_dir, input_dir, output_dir, working_dir, log_dir, target_path, args):
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

        analyze_target_on_input_file(dynamorio_dir, output_dir, working_dir, log_dir, target_path, input_path, filename, args)

def analyze_target_on_input_file(dynamorio_dir, output_dir, working_dir, log_dir, target_path, input_path, input_filename, options):
    """Analyzes the target for a single input file."""

    log_dir_for_input = os.path.join(log_dir, input_filename)

    if not os.path.exists(log_dir_for_input):
        os.makedirs(log_dir_for_input)
        logging.debug("[+] Created %s" % log_dir_for_input)
    elif options.cont:
        logging.debug("[!] Directory %s exists, skipping" % log_dir_for_input)
        return

    input_log_dir_relative_to_working_dir = os.path.relpath(log_dir_for_input, working_dir)
    input_log_dir_relative_to_working_dir = log_dir_for_input

    target_invokation = replace_placeholders(options.target_invokation, target_path, input_path, input_log_dir_relative_to_working_dir)
    client_invokation = replace_placeholders(options.client_invokation, target_path, input_path, input_log_dir_relative_to_working_dir)

    return run_drrun(
        dynamorio_dir,
        working_dir,
        log_dir,
        target_path,
        log_dir_for_input,
        client_invokation,
        target_invokation,
        options.target_timeout,
        options.nudge_timeout,
        options.max_nb_nudge_attempts,
        options.nudge_grace_timeout
        )

def replace_placeholders(haystack, target_path, input_path, input_log_dir_relative_to_working_dir):
    result = haystack

    result = result.replace('@app@', target_path)
    result = result.replace('@log@', '"' + input_log_dir_relative_to_working_dir + '"')
    result = result.replace('@input@', '"' + input_path + '"')

    return result

def run_drrun(dynamorio_dir, working_dir, log_dir, target_path, log_dir_for_input, client_invokation, target_invokation, target_timeout, nudge_timeout, max_nb_nudge_attempts, nudge_grace_timeout):
    """Executes the target with DynamoRIO on a specified input file"""

    #
    # Step 1: Run drrun in a new process (this script does not wait for the 
    # process to terminate)
    #

    target_dir, target_name = os.path.split(target_path)
    drrun_invoke_args = [
        os.path.join(dynamorio_dir, "drrun.exe"),
        client_invokation, "--", target_invokation
    ]
    cmd = subprocess.list2cmdline(drrun_invoke_args)

    foo = os.path.join(dynamorio_dir, "drrun.exe") + " " + client_invokation + " -- " + target_invokation
    cmd = foo

    #print(drrun_invoke_args)
    #print(cmd)
    #print(foo)
    #exit(0)

    logging.debug("[*] Running drrun with\n    %s" % cmd)
    
    start_time = time.time()

    process_drrun = subprocess.Popen(
          cmd
        , cwd=working_dir
        , shell=False
    )
    
    time_log_path = os.path.join(log_dir_for_input, 'time.txt')
    
    try:
        #
        # Step 2: Wait for a user-specified time before terminating. We assume that 
        # all the interesting parsing work by the target process is completed in the
        # meanwhile.
        #
        process_drrun.wait(target_timeout)
        elapsed_time = time.time() - start_time
        with open(time_log_path, 'w') as f:
            f.write(f'Finished after {elapsed_time}\n')
            
    except subprocess.TimeoutExpired:
        #
        # Step 3: Since the process did not finish in time, terminate it in an 
        # escalating fashion.
        #
        elapsed_time = time.time() - start_time
        with open(time_log_path, 'w') as f:
            f.write(f'Killed after {elapsed_time}\n')
        
        #
        # Step 3a: Try a few nudge signals so that the DynamoRIO client can do 
        # necessary clean up work, like saving its results to the disk.
        #

        nudge_invoke_args = [
              os.path.join(dynamorio_dir, "drconfig.exe")
            , "-nudge", target_name, "0", "1"
            , "-nudge_timeout", str(1000*nudge_timeout)
        ]
        
        nb_attempts = 0
        
        while process_drrun.poll() is None and nb_attempts < max_nb_nudge_attempts:
            logging.debug("[*] Sending a nudge signal to terminate drrun with\n    %s" % subprocess.list2cmdline(nudge_invoke_args))

            process_nudge = subprocess.Popen(
                  nudge_invoke_args
                , cwd=working_dir
                , shell=False
            )
            
            try:
                process_nudge.wait(nudge_grace_timeout)
            except subprocess.TimeoutExpired:
                # If a nudge hangs, just kill everything
                logging.debug("[*] Nudge hangs, now killing everything…")
                try:
                    if process_nudge.poll() is None:
                        logging.debug("[*] Nudge process still running, now killing…")
                        process_nudge.kill()
                except:
                    logging.debug("[*] Killing nudge process failed.")

                break
            
            nb_attempts += 1

        #
        # Step 3b: Forcefully terminate the all processes.
        #

        if process_drrun.poll() is None:
            try:
                logging.debug("[*] Target process still running, now killing…")
                process_drrun.kill()
            except:
                logging.debug("[*] Killing target process failed.")

        subprocess.run(
             "TASKKILL /F /IM " + target_name
            , stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        subprocess.run(
             "TASKKILL /F /IM " + "drrun.exe"
            , stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        subprocess.run(
             "TASKKILL /F /IM " + "drconfig.exe"
            , stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        
    #
    # Step 4: Recreate the working directory, deleting all files that have 
    # been created by the target.
    #

    shutil.rmtree(working_dir)
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

    parser.add_argument("--dynamorio-dir", required=False, default='C:\\Users\\kolvenba\\Projekte\\dynamorio\\DynamoRIO-Windows-7.91.18263-0\\bin64'#default='C:\\Users\\kolvenba\\Projekte\\DynamoRIO-Windows-7.91.18319\\bin64'
        , help=(
            "Path to the binary directory of DynamoRIO, usually ending with "
            "/bin32 or /bin64."
    ))

    parser.add_argument("--client-invokation", required=True, help=(
        "Command pattern to invoke DynamoRIO client:\n"
        "    drrun.exe <client-invokation> -- foo.exe input.txt\n"
        "Any occurrence of @log@ will be replaced by the path to "
        "the log directory for the current input file."
        ))

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

    parser.add_argument("--nudge-timeout", required=False, type=int, default=2
        , help="Timeout in seconds to use for the nudge signal."
        )

    parser.add_argument("--max-nb-nudge-attempts", required=False, type=int, default=2
        , help="Number of nudges to send."
        )

    parser.add_argument("--nudge-grace-timeout", required=False, type=int, default=10
        , help="Timeout in seconds before to forcefully kill nudge process."
        )

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
