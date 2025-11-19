# TERMINATOR: Coverage-Guided Program Termination for Efficient Fuzzing

This repository contains the implementation and evaluation artifacts for TERMINATOR, a method that modifies programs to self-terminate when they are presumed to execute few or no new basic blocks, thereby improving fuzzing efficiency.

## Repository Structure

### `terminator/`
Contains the core TERMINATOR implementation and toolchain:

- **Core Implementation**: Python scripts for data collection, trace analysis, and solution computation
- **Coverage Tool**: C++ instrumentation tool for recording execution traces (`coverage-trace-debugger/`)
- **IDA Pro Integration**: Scripts for extracting basic block metadata from target binaries
- **Patching Tools**: Utilities for modifying binaries with termination points
- **Configuration Scripts**: PowerShell scripts for automated data collection and solution calculation

**Key Components:**
- `collect_data_nodyn.py`: Collects execution traces from target programs
- `compute_candidates.py`: Calculates optimal termination points using various objective functions
- `manual_patch.py`: Patches binaries with computed termination points
- Coverage instrumentation tools for x64 and x86 architectures

### `evaluation/`
Contains the comprehensive experimental evaluation comparing TERMINATOR against CPU idle monitor baselines:

- **Experimental Data**: Raw fuzzing results from 15 applications across 3 categories (PDF readers, image/document viewers, archive utilities)
- **Statistical Analysis**: Performance comparisons showing 1.56x to 54.27x speed improvements
- **Crash Discovery Analysis**: Vulnerability detection effectiveness comparison
- **Visualization Results**: Charts and graphs showing performance timelines and comparative analysis

**Key Files:**
- `extracted_data_results.csv`: Detailed fuzzing performance metrics
- `analysis_summary.csv`: Statistical comparison results
- Visualization plots showing execution speed, crash discovery, and timeline analysis

## Quick Start

1. **Setup**: Install dependencies and build the coverage tool (see `terminator/README.md`)
2. **Data Collection**: Run TERMINATOR on your target program with a representative input corpus
3. **Solution Computation**: Calculate optimal termination points using the provided objective functions
4. **Binary Patching**: Apply the computed solution to create a TERMINATOR-modified binary

For detailed methodology, results, and technical specifications, refer to the accompanying research paper and the README files in each subdirectory.
