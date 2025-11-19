$script_dir="C:\Users\Fuzzing\Documents\hampel\terminator"
$output_dir="C:\Users\Fuzzing\Documents\hampel\runs\xpdf_example\out\terminator_example"
$bits=64

python $script_dir\move_bad_logs.py --output-dir $output_dir
python $script_dir\compute_candidates.py --output-dir $output_dir --data-type dbg-covtrace --bits $bits --no-syminfo --compute o0sl --compute o80sl --comput o0ls --log debug --fastfail --patch --min-bb-size 1 --exit-code 1337
