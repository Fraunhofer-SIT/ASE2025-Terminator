
import argparse
import logging

import binary

def main(options):
    if options.method == 'fastfail':
        fastfail = True
        breakpoint = False
        jump = False
    elif options.method == 'breakpoint':
        fastfail = False
        breakpoint = True
        jump = False
    elif options.method == 'terminate':
        fastfail = False
        breakpoint = False
        jump = False
    else:
        raise Exception('unexpected')

    binary.patch_file(options.input_file, options.positions, options.output_file, options.exit_code, jump, options.bits, fastfail, breakpoint)


# Entry point: parse arguments and call main function
if __name__ == "__main__":
    def termination_method(x):
        if x in ['fastfail', 'breakpoint', 'terminate']:
            return x
        else:
            raise Exception("Bad termination method")

    def bits_32_or_64(x):
        x = int(x)
        if x in [32, 64]:
            return x
        else:
            raise Exception("Bad bits")

    parser = argparse.ArgumentParser()
    parser.add_argument('--in', dest='input_file', required=True, type=str)
    parser.add_argument('--out', dest='output_file', required=True, type=str)
    parser.add_argument('--method', required=True, type=termination_method)
    parser.add_argument('--exit-code', required=False, type=int, default=0)
    parser.add_argument('--positions', nargs='+', required=True, type=lambda x: int(x, 16))
    parser.add_argument('--bits', required=True, type=bits_32_or_64)
    parser.add_argument("--log", required=False, default='INFO')
    options = parser.parse_args()

    logging.basicConfig(level=getattr(logging, options.log.upper(), logging.INFO))
    main(options)
