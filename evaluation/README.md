# TERMINATOR vs CPU Idle Monitor: Fuzzing Performance Analysis

This folder contains the analysis results comparing TERMINATOR-modified binaries against CPU idle monitor baseline across multiple applications. The study evaluates the impact of coverage-guided termination on fuzzing effectiveness.

## Experimental Setup

We conducted a comprehensive study comparing TERMINATOR-modified binaries against CPU idle monitor baselines across **15 different applications**. Each configuration was tested with **3 independent 24-hour fuzzing runs** for statistical robustness.
The TERMINATOR binaries were all patched using the o90ls Objective to ensure no early termination (see `../terminator/README.md`).

## Targets Analyzed

The study covers **15 different applications** across three categories:

### PDF Readers
- **Adobe Reader**
- **Foxit PDF Reader** 
- **MuPDF** 
- **SlimPDF Reader**
- **SumatraPDF**
- **Xpdf Reader**

### Image/Document Viewers  
- **BandiView**
- **Birdfont** 
- **FSViewer**
- **IrfanView**
- **STDU Viewer**

### Archive Utilities
- **ALZip** 
- **Kofax PDF**
- **UltraISO**
- **WinRAR**

## Data Files
- **`tasks.csv`**: Task configuration data including target names, architecture (32/64-bit), and termination settings
- **`task_results.csv`**: Detailed fuzzing results including block discoveries, execution counts, crash information, and timing data

## Visualization Results

- **`analysis_crash_analysis.png`**: Detailed crash discovery analysis including:
  - Total unique crashes found
  - Crash discovery rates (crashes per hour)
  - Time to first crash
  - Crash discovery timeline patterns

- **`analysis_execution_speed_analysis.png`**: Execution performance analysis showing:
  - Execution speed over time
  - Speed by time periods
  - Average execution speed by target
  - Speed distribution comparisons

- **`analysis_detailed_timelines.png`**: Individual discovery timelines for each target showing cumulative block discoveries over time

- **`analysis_speed_advantage.png`**: Speed advantage analysis showing TERMINATOR's efficiency gains
  - Speed advantage factors by target with 95% confidence intervals
  - Confidence interval widths indicating measurement uncertainty
  - Number of pairwise comparisons for statistical robustness
  - Distribution histogram of speed advantages across all targets
