$script_dir="C:\Users\Fuzzing\Documents\hampel\terminator"
$output_dir="C:\Users\Fuzzing\Documents\hampel\runs\toy_gui_32\solution\32bit_example"
$bits=32

python $script_dir\move_bad_logs.py --output-dir $output_dir
python $script_dir\compute_candidates.py --output-dir $output_dir --data-type dbg-covtrace --bits $bits --no-syminfo --compute o0sl --compute o80sl --comput o0ls --log debug --fastfail --patch --min-bb-size 1 --exit-code 1337
