
import os
import datetime
import re

def list_paths(path):
    for file in os.listdir(path):
        yield os.path.join(path, file)

def subdirs(path):
    return [x for x in list_paths(path) if os.path.isdir(x)]

def ensure_dir(path):
    if os.path.exists(path):
        if os.path.isdir(path):
            return
        
        raise Exception('Path %s exists but is not a directory' % path)

    os.makedirs(path)

def find_files_by_pattern(dir, pattern):
    result = []
    regex = re.compile(pattern)
    for file in os.listdir(dir):
        if regex.match(file):
            result.append(os.path.join(dir, file))

    return result

def find_file_by_pattern(dir, pattern):
    regex = re.compile(pattern)
    for file in os.listdir(dir):
        if regex.match(file):
            return os.path.join(dir, file)

    return None

def find_file_by_pattern_or_die(dir, pattern):
    file = find_file_by_pattern(dir, pattern)

    if file is None:
        raise Exception("Did not find %s in %s" % (pattern, dir))

    return file

def generate_output_dirname(name, dt, attempt):
    now_str = dt.strftime('%Y-%m-%d_T_%H-%M-%S-%f')
    candidate = now_str + '_' + name

    if attempt > 1:
        candidate = candidate + '_' + str(attempt)

    return candidate

def output_dirname_pattern():
    pattern = re.compile('^\d{4}-\d{2}-\d{2}_T_\d{2}-\d{2}-\d{2}-\d{6}_(.)+\.exe(_\d+)?$')

    return pattern

def find_unused_output_dirname(container_path, name, max_nb_attempts = 100):
    nb_attempts = 1
    output_dir_candidate = None
    is_candidate_good = False

    while not is_candidate_good and nb_attempts <= max_nb_attempts:
        now = datetime.datetime.now()
        candidate_dirname = generate_output_dirname(name, now, nb_attempts)
        output_dir_candidate = os.path.join(container_path, candidate_dirname)
        is_candidate_good = os.path.exists(output_dir_candidate) == False
        nb_attempts = nb_attempts + 1

    if is_candidate_good:
        return output_dir_candidate
    else:
        return None

def find_newest_output_dirname(container_path):
    dirnames = []
    pattern = output_dirname_pattern()

    for dirname in os.listdir(container_path):
        match = pattern.match(dirname)
        if not match:
            continue

        dirnames = dirnames + [dirname]

    dirnames.sort()

    if len(dirnames) == 0:
        return None

    return os.path.join(container_path, dirnames[-1])

def find_maximum_file(container_path, predicate):
    dirnames = []

    for dirname in os.listdir(container_path):
        if not predicate(dirname):
            continue

        dirnames = dirnames + [dirname]

    dirnames.sort()

    if len(dirnames) == 0:
        return None

    return os.path.join(container_path, dirnames[-1])
