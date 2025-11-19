$script_dir="C:\Users\Fuzzing\Documents\hampel\terminator"
$input_dir="C:\Users\Fuzzing\Documents\hampel\runs\xpdf_example\in"
$output_dir="C:\Users\Fuzzing\Documents\hampel\runs\toy_gui_32\solution"
$coverage_path="$script_dir\coverage-trace-debugger\build\x86-Release\CoverageTrace\Release\CoverageTrace.exe"
$script_path="$script_dir\coverage-trace-debugger\scripts\ida_bb_list_autonomous.py"
$ida_path="C:\Program Files\IDA Pro 8.4\idat.exe"
$precomputed_bb_list_path="C:\Users\Fuzzing\Documents\hampel\runs\toy_gui_32\bb_list.txt"
$target_path="C:\Users\Fuzzing\Documents\hampel\targets\Toy_GUI\x86\Toy_GUI.exe"
$timeout=5
$dynamorio="C:\Users\Fuzzing\Documents\hampel\DynamoRIO-Windows-10.0.0\DynamoRIO-Windows-10.0.0\bin32"
# $client_invokation="-c winafl.dll -debug -target_module Toy_GUI.exe -target_offset 0x1000 -fuzz_iterations 5 -nargs 1 -- Toy_GUI.exe"

python $script_dir\collect_data_nodyn.py --create-subdir --input-dir $input_dir --output-dir $output_dir --path $coverage_path --script-path $script_path --ida-path $ida_path --precomputed-bb-list $precomputed_bb_list_path --target-path $target_path --log debug --target-timeout $timeout


# Just for exeperiments
# python %script_dir%\collect_data.py --create-subdir --input-dir %input_dir% --output-dir %output_dir% --path %coverage_path% --script-path %script_path% --ida-path %ida_path% --precomputed-bb-list %precomputed_bb_list_path% --target-path %target_path% --log debug --target-timeout %timeout% --dynamorio-dir %dynamorio% --client-invokation %client_invokation%
