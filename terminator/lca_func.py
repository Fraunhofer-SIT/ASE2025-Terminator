# lca_func: Find the lowest common ancestor (LCA) function that calls 
# the exit nodes and the IO functions.

import argparse
import re
import json

def main(args):
    with open(args.func_bounds, 'r') as file:
        func_bounds = file.read()

    with open(args.stack1, 'r') as file:
        stack1_content = file.read()

    with open(args.stack2, 'r') as file:
        stack2_content = file.read()

    with open(args.modules1, 'r') as file:
        modules1_content = file.read()

    with open(args.modules2, 'r') as file:
        modules2_content = file.read()

    modules1, stack1 = stack_windbg(modules1_content, stack1_content)
    modules2, stack2 = stack_windbg(modules2_content, stack2_content)

    table = func_bounds_table(func_bounds)

    funcs = {}

    for s in stack1:
        for f in table:
            if f['start'] <= s['return-offset'] <= f['end']:
                s['func'] = f

                if not f['start'] in funcs:
                    funcs[f['start']] = {
                        'start': f['start'],
                        'occ1': [],
                        'occ1-s': [],
                        'occ2': [],
                        'occ2-s': [],
                    }

                funcs[f['start']]['occ1'].append(s['number'])
                funcs[f['start']]['occ1-s'].append(s)

        if not 'func' in s:
            print('[-] No function for stack frame: %d' % s['number'])

                

    for s in stack2:
        for f in table:
            if f['start'] <= s['return-offset'] <= f['end']:
                s['func'] = f

                if not f['start'] in funcs:
                    funcs[f['start']] = {
                        'start': f['start'],
                        'occ1': [],
                        'occ1-s': [],
                        'occ2': [],
                        'occ2-s': [],
                    }

                funcs[f['start']]['occ2'].append(s['number'])
                funcs[f['start']]['occ2-s'].append(s)

        if not 'func' in s:
            print('[-] No function for stack frame: %d' % s['number'])

    common = [x for x in funcs.values() if x['occ1'] and x['occ2']]
    sfuncs = sorted(common, key=lambda x: max(max(x['occ1']), max(x['occ2'])))


    #print(json.dumps(stack1, indent=2))
    #print(json.dumps(stack2, indent=2))
    #print(json.dumps(sfuncs, indent=2))

    if not sfuncs:
        print('[--] No candidates')
    else:
        print('[+] Best candidate:')
        print(json.dumps(sfuncs[0], indent=2))
        print('[+] Offset is %#x' % sfuncs[0]['start'])

def func_bounds_table(func_bounds):
    table = []
    i = 0

    pattern = re.compile('([^:]+):\s+(0x[0-9a-zA-Z]+)\s+(0x[0-9a-zA-Z]+)\s+(\d+)')
    for line in func_bounds.splitlines():
        m = re.match(pattern, line)
        if not m:
            print('Unexpected line format: %s' % line)
            continue

        func_name = m.group(1)
        func_start = int(m.group(2), 16)
        func_end = int(m.group(3), 16)
        func_size = int(m.group(4))

        table.append({'i': i, 'name': func_name, 'start': func_start, 'end': func_end, 'size': func_size})
        i = i + 1

    table.sort(key=lambda x: x['start'])

    return table

def stack(content):
    stack = []
    modules = {}
    patternStack = re.compile('(\d+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+(.+)')
    patternModule = re.compile('Module: ([0-9a-zA-Z]+)   ([0-9a-zA-Z]+)   ([0-9a-zA-Z]+)   (.+)')
    for line in content.splitlines():
        m = re.match(patternStack, line)
        if m:
            stack.append({
                'number': int(m.group(1)),
                'pc': int(m.group(2), 16),
                'pc-offset': int(m.group(3), 16),
                'return': int(m.group(3), 16),
                'return-offset': int(m.group(3), 16) - modules[m.group(5)]['start'],
                'stack-pointer': int(m.group(4), 16),
                'pc': m.group(5),
            })
        else:
            m = re.match(patternModule, line)
            if not m:
                print('Unexpected line format: %s' % line)
                continue
            
            modules[m.group(4)] = {
                'hmod': int(m.group(1), 16),
                'start': int(m.group(2), 16),
                'end': int(m.group(3), 16),
                'path': m.group(4),
            }

    return modules, stack        

def stack_windbg(smodules, sstack):
    stack = []
    modules = []

    patternModule = re.compile('([0-9a-zA-Z]+)\s+([0-9a-zA-Z]+)\s+(.+)')
    patternStack = re.compile('([0-9a-zA-Z]+)\s+([0-9a-zA-Z]+)\s+([0-9a-zA-Z]+)\s+(.+)')

    number = 0
    for line in smodules.splitlines():
        m = re.match(patternModule, line)
        if not m:
            print('[-] Unexpected line format: %s' % line)
            continue

        modules.append({
            'number': number,
            'start': int(m.group(1), 16),
            'end': int(m.group(2), 16),
            'path': m.group(3),
        })

        number += 1

    for line in sstack.splitlines():
        m = re.match(patternStack, line)
        if not m:
            print('[-] Unexpected line format: %s' % line)
            continue
        
        number = int(m.group(1), 16)
        child_ebp = int(m.group(2), 16)
        retaddr = int(m.group(3), 16)
        mod = None

        for m in modules:
            if m['start'] <= retaddr <= m['end']:
                mod = m
                break

        if not mod:
            print('[-] Could not find module for address %x in line\n%s' % (retaddr, line))
        elif mod['number'] != 0:
            #print('[*] Ignoring stack frame from other module')
            pass
        else:
            stack.append({
                'number': number,
                'child-ebp': child_ebp,
                'return': retaddr,
                'return-offset': retaddr - mod['start'],
            })

    return modules, stack        

# Entry point: parse arguments and call main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=(
        "None"
    ))

    parser.add_argument("--func-bounds", type=str, required=True)
    parser.add_argument("--stack1", type=str, required=True)
    parser.add_argument("--stack2", type=str, required=True)
    parser.add_argument("--modules1", type=str, required=True)
    parser.add_argument("--modules2", type=str, required=True)

    args = parser.parse_args()

    main(args)
