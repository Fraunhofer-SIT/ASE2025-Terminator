
import argparse
import os
import re

import iopaths

def main(options):
    output_dir = os.path.realpath(options.output_dir)
    log_dir = os.path.join(output_dir, 'log')

    if not os.path.isdir(output_dir) or not os.path.isdir(log_dir):
        print("[-] Either of %s and %s is not a directory" % (output_dir, log_dir))
        exit(1)

    regex = re.compile(options.correct_regex)
    
    empty_dir = os.path.join(output_dir, 'log-empty')
    
    if options.undo:
        if os.path.isdir(empty_dir):
            for path_dir in iopaths.subdirs(empty_dir):
                _, dir_name = os.path.split(path_dir)
                new_path = os.path.join(log_dir, dir_name)
                print("[*] Moving %s\n"
                      "      from %s\n"
                      "        to %s" % (dir_name, path_dir, new_path)
                if not options.dry:
                    os.rename(path_dir, new_path)
    
    for path_dir in iopaths.subdirs(log_dir):
        not_accept_dir = os.path.join(path_dir, 'drcov_other')
        
        if options.undo:
            for path in iopaths.list_paths(not_accept_dir):
                _, filename = os.path.split(path)
                new_path = os.path.join(path_dir, filename)
                print("[*] Moving %s\n"
                      "      from %s\n"
                      "        to %s" % (filename, path, new_path))
                if not options.dry:
                    os.rename(path, new_path)
                    
            print("[*] Removing %s" % not_accept_dir)
            if not options.dry:
                os.rmdir(not_accept_dir)
                    
        else:
            for path in iopaths.list_paths(path_dir):
                if not os.path.isfile(path):
                    continue

                _, filename = os.path.split(path)
                if not filename.startswith('drcov.'):
                    continue

                m = regex.search(filename)
                if not m:
                    if not os.path.isdir(not_accept_dir):
                        print("[*] Creating %s" % not_accept_dir)
                        if not options.dry:
                            iopaths.ensure_dir(not_accept_dir)

                    new_path = os.path.join(not_accept_dir, filename)
                    print("[*] Moving non-matching %s\n"
                          "      from %s\n"
                          "        to %s" % (filename, path, new_path))
                    
                    if not options.dry:
                        os.rename(path, new_path)
                else:
                    if os.path.getsize(path) < options.min_size:
                        new_path = os.path.join(not_accept_dir, filename)
                        print("[*] Moving too small %s\n"
                              "      from %s\n"
                              "        to %s" % (filename, path, new_path))
                        if not options.dry:
                            os.rename(path, new_path)
                              
            if not iopaths.find_file_by_pattern(path_dir, options.correct_regex):
                _, dirname = os.path.split(path_dir)
                new_path = os.path.join(empty_dir, dirname)
                print("[*] Moving empty directory %s\n"
                      "      from %s\n"
                      "        to %s" % (dirname, path_dir, new_path))
                      
                if not options.dry:
                    iopaths.ensure_dir(empty_dir)
                    os.rename(path_dir, new_path)

# Entry point: parse arguments and call main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("--output-dir", required=False, default=None, help="Root of the output directory created by compute_traces.py.")
    parser.add_argument("--log", required=False, default="INFO")
    parser.add_argument("--correct-regex", required=True, type=str)
    parser.add_argument("--dry", required=False, action="store_true", dest="dry")
    parser.add_argument("--min-size", required=False, default=0, type=int)
    parser.set_defaults(dry=False)
    parser.add_argument("--undo", required=False, action="store_true", dest="undo")
    parser.set_defaults(undo=False)
    args = parser.parse_args()

    main(args)
