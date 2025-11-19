# TERMINATOR

TERMINATOR is a method to modify a program (referred to as the _target program_) such that it self-terminates when it is presumed to execute few or no new basic blocks.
TERMINATOR consists of two phases:

1.  **Data Collection (Learning Phase):** TERMINATOR executes the target program with a defined set of input files and, using dynamic instrumentation, records for each input file which basic blocks are executed (for the first time) and in what order. This recording is called a _trace_, for example `T = (t_0, t_1, …, t_N)`, where `t_i != t_j` for `i != j`. `t_i` is the block that is executed _for the first time_ as the _i_-th block. This means that `t_N` is not necessarily the last block executed, but it is the block after which only blocks that have already been executed at least once are encountered. If the program flow can be represented as `A B B B A C B C D A B`, then `T = (A, B, C, D)`. The value `i / N` is the _premiere_ of basic block `t_i`.

2.  **Data Evaluation (Solution Phase):** TERMINATOR finds a set (called a _solution_) of basic blocks (called _solution blocks_) with the following properties:

    1.  At least one solution block is contained in every trace.
    2.  For every trace: The set of basic blocks that follow the solution blocks appearing in that trace is relatively small (see below). This means that each solution block appears _relatively late_ in every trace, thus having a relatively late premiere.
    3.  Each basic block is large enough to accommodate the necessary machine code for termination.

    The target program is then patched at all solution blocks so that it self-terminates upon execution of a solution block.

    The first property ensures that the modified target program (presumably!) terminates for at least all files in the input corpus; _presumably_ because the target program might not have deterministic traces.

    The second property ensures that all program code of interest for subsequent fuzzing is executed before the program terminates.

The definition of _relatively small_ and _relatively late_ is somewhat arbitrary. TERMINATOR offers various approaches to define these. For this purpose, one can specify an _objective function_ and a _constraint_. For explanation, a _candidate_ is a set of basic blocks that satisfies properties (1) and (3) above. The following objective functions are available:

1.  **Latest (latest):** TERMINATOR searches for the candidate whose basic blocks have the latest possible premieres across all traces. Since a basic block can have different premieres in different traces, only the earliest premiere is relevant. The earliest premiere of each block should be as late as possible.
2.  **Smallest (smallest):** TERMINATOR searches for the candidate with the smallest number of basic blocks.
3.  **Earliest (earliest):** TERMINATOR searches for the candidate whose basic blocks have the earliest possible premiere.

Another objective function can be used as a tie-breaker. For example, one can search for the smallest possible solution, and among all equally small solutions, choose the latest one.

The following constraints are available:

1.  **Lower bound on premieres:** for example, every premiere must be at least 50% = 0.5.
2.  **Upper bound on premieres.**
3.  **Upper bound on time:** every premiere must occur after at most X seconds.

There is also the so-called _differing coverage_. Instead of being interested in all basic blocks in the trace, only those blocks that do not appear in all traces are considered. There are corresponding counterparts for premiere, as well as for objective functions and constraints.

## Installation of Coverage Tool (for recording traces)

        cd coverage-trace-debugger
        mkdir build\x64-Release
        cmake -A "x64" ..\..
        cmake --build . --config Release
        mkdir ..\x86-Release
        cd ..\x86-Release
        cmake -A "Win32" ..\..
        cmake --build . --config Release

## Data Collection

TERMINATOR requires a table of basic blocks with metadata for the target program. This can be created using IDA Pro. For this, the target program must be opened with IDA Pro, and the initial automatic analysis must be completed. Only then can the script `ida_bb_list_ide.py` be executed. The path to the resulting table of basic blocks corresponds to the `precomputed_bb_list_path` variable below.

Example:

    rem Path to this repository
    set script_dir="..."
    rem Path to the directory containing input files:
    rem For a PDF program, these are the PDF files with which TERMINATOR learns
    rem everything necessary about the PDF program through dynamic program analysis.
    set input_dir="..."
    rem Root directory for the output
    set output_dir="..."
    set coverage_path="%script_dir%\coverage-trace-debugger\x64\Release\CoverageTrace.exe"
    set script_path="%script_dir%\coverage-trace-debugger\ida_bb_list_autonomous.py"
    set ida_path="C:\Program Files\IDA Pro 7.6\idat.exe"
    set precomputed_bb_list_path="...\basicblocks.bin"
    set target_path="...\fuzzee.exe"
    rem Time in seconds before the fuzzed target is terminated.
    set timeout=5

    python.exe %script_dir%\collect_data_nodyn.py --create-subdir --input-dir %input_dir% --output-dir %output_dir% --path %coverage_path% --script-path %script_path% --ida-path %ida_path% --precomputed-bb-list %precomputed_bb_list_path% --target-path %target_path% --log debug --target-timeout %timeout%

### Script Alternative

Adjust the script `collect_data.ps1`/`collect_data_32.ps1` and then execute it.
The variable names are equivalent to those in the example above.

## Data Evaluation: Calculating the Solution

Example:

    rem Path to this repository
    set script_dir="..."
    rem Path to the output directory created with the command above. Example:
    set output_dir="<output_dir from above>\2022-06-01_T_21-14-04-705138_fuzzee.exe"

    python.exe %script_dir%\move_bad_logs.py --output-dir %output_dir%
    python.exe %script_dir%\compute_candidates.py --output-dir %output_dir% --data-type dbg-covtrace --bits 64 --no-syminfo --compute o0sl --compute o80sl --compute o0ls  --log debug --fastfail --patch --min-bb-size 1 --exit-code 1337

The format for defining the objective function and constraints is as follows:

1.  `--compute o0sl`: Lower bound of 0% (no bound), smallest possible solution, and among all equally small solutions, the latest one.
2.  `--compute o80sl`: Lower bound of 80%, smallest possible solution, and among all equally small solutions, the latest one.
3.  `--compute o0ls`: Lower bound of 0% (no bound), latest possible solution, and among all equally late solutions, the smallest one.
4.  `--compute o90ls`: Lower bound of 90% (for normal coverage), latest possible solution, and among all equally late solutions, the smallest one.
5.  `--compute o50d75sl`: Lower bound of 50% for normal coverage and 75% for differing coverage, smallest possible solution, and among all equally small solutions, the latest one.
6.  `--compute o50se --ub-time 5000`: Lower bound of 50% for normal coverage, smallest possible solution, and among all equally small solutions, the earliest one that occurs after at most 5000 milliseconds.

The patched program will be found somewhere in the output directory. To run it, it usually needs to be copied to its original installation directory.

### Script Alternative

Adjust the script `calculate_solution.ps1`/`calculate_solution_32.ps1` and then execute it.
The variable names are equivalent to those in the example above.
Bits

## Further Scripts

The `build_winnie_harness.py` script creates a DLL file that can be used as a harness for WINNIE. To define a harness, one only needs the offset of the address in the target binary where WINNIE should perform the fork. Additionally, the correct architecture (x64 or x86) must be specified.

The `collect_data.py` script is an older variant of `collect_data_nodyn.py` that uses DynamoRIO.

With `ida_func_bounds.py`, one can determine the boundaries of functions in IDA Pro, i.e., the start and end addresses of each function. It should be noted that not every function has only one beginning and one end.

With `lca_func.py`, one can determine the Lowest Common Ancestor of two call stacks. If I recall correctly, for each call stack, one needs both the actual call stack as output of the `k` command in WinDbg and the module boundaries as output of `lm`.

With `manual_patch.py`, one can manually patch a binary so that it self-terminates at a specified location.

The `move_bad_logs.py` script moves subfolders from the output directory where data collection failed.

The `move_wrong_drcov_files.py` script works similarly.

The remaining files are libraries.
