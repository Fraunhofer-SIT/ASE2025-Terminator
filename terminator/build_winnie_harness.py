
import argparse
import logging
import os
import shutil
import subprocess
import tempfile

# %comspec% /k "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" && 
# %comspec% /k "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
# %comspec% /k "C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\VC\Auxiliary\Build\vcvars32.bat"

def find_vcvars(bits):
    parts1 = ["Program Files", "Program Files (x86)"]
    parts2 = ["2022", "2019", "2017", "2015", "2013"]
    parts3 = ["BuildTools", "Professional", "Community"]
    p4 = f'vcvars{bits}.bat'

    pathVcvars = None

    for p1 in parts1:
        for p2 in parts2:
            for p3 in parts3:
                pathVcvars = f'C:\\{p1}\Microsoft Visual Studio\\{p2}\\{p3}\\VC\\Auxiliary\\Build\\{p4}'
                if os.path.isfile(pathVcvars):
                    logging.debug(f"Found: {pathVcvars}")
                    return pathVcvars

    if pathVcvars is None:
        logging.error(f"Did not find {p4} – cannot continue!")
        exit(1)

def create_dllmain(pathDllmain, offset):
    source = '''
// Harness API
//
// This file defines an interface fuzzing harnesses must expose for the injected forkserver.

#pragma once

#include <stdio.h>
#include <stdint.h>
#include <Windows.h>

// Unfortunately, no stdatomic without VS 2019.

typedef volatile struct
{
	LPVOID target_method;			   // Required. The function to hook. The injected component of fuzzer will hook this function and enter the fuzzing loop once it is hit.
	void (CALLBACK *fuzz_iter_func)(); // Required. Target function to fuzz. The injected forkserver will call this function repeatedly. The function should follow stdcall convention and return gracefully.
	const WCHAR* input_file;           // Optional. The input filename that the fuzzer will mutate; for example, L"my_input.txt". If NULL, defaults to L".cur_input".
	void (CALLBACK *setup_func)();     // Optional. If not NULL, a function that will be called after the target process initializes, before entering the forkserver loop.
	                                   // You might want to use setup_func for doing things like marking all of the handles as inheritable, killing other threads, closing problematic handles, etc.
	BOOL network;                      // Optional. If true, apply de-socket techniques (redirects Winsock APIs)
	volatile CHAR ready;               // Required. Set this to true only when all the other struct members are populated and ready.
} HARNESS_INFO, *PHARNESS_INFO;

#define HARNESS_INFO_PROC "HarnessInfo"

// Ensure compatibility with C and C++
#ifdef __cplusplus
#define externCbegin extern "C" {
#define externCend };
#else
#define externCbegin
#define externCend
#endif

#define EXPOSE_HARNESS(target_method, fuzz_iter_func, preload, input_file, setup_func, network) \\
		externCbegin __declspec(dllexport) HARNESS_INFO HarnessInfo = { \\
		target_method, \\
		fuzz_iter_func, \\
		input_file, \\
		setup_func, \\
		network, \\
	}; \\
externCend

// This macro exports the HARNESS_INFO struct expected by fuzzer. The injected forkserver (injected-harness) will LoadLibrary the harness, and then use this.
EXPOSE_HARNESS(
  NULL,  // target method, we will fill this in dynamically at DllMain
  NULL,  // fuzz iter func, we will fill this in dynamically at DllMain
  NULL,  // default input file (.cur_input)
  NULL,  // no setup func needed
  FALSE, // don't need desocket
  FALSE  // Not ready yet, we initialize dynamically in DllMain.
);

typedef void (*TargetFun)(void);

HMODULE hMainModule;
TargetFun targetFun;

BOOL APIENTRY DllMain(
    HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hMainModule = GetModuleHandle(NULL); // PTR to base, where target is loaded to

		targetFun = (TargetFun)(##OFFSET## + (uint64_t)hMainModule);
		HarnessInfo.target_method = targetFun;
		HarnessInfo.fuzz_iter_func = (void (CALLBACK *)(void)) targetFun;

		MemoryBarrier(); // Prevent the compiler from messing things up by reordering.
		InterlockedExchange8(&HarnessInfo.ready, TRUE); // Signal to forkserver that we're ready to go.

		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
'''

    formatedSource = source.replace('##OFFSET##', '%#x' % offset)

    with open(pathDllmain, 'w') as file:
        file.write(formatedSource)

def build(options):
    pathVcvars = find_vcvars(options.bits)

    if os.path.isdir(options.output):
        filenameDllDst = 'harness_%d_%#x.dll' % (options.bits, options.offset)
        pathDllDst = os.path.join(options.output, filenameDllDst)
    else:
        pathDllDst = options.output

    with tempfile.TemporaryDirectory() as pathTempDir:
        #pathTempDir = r'C:\Users\kolvenba\Projekte\research\fuzzing\terminator\terminator\test'
        logging.debug(f"Temporary directory is: {pathTempDir}")
        pathDllmain = os.path.join(pathTempDir, 'dllmain.c')
        create_dllmain(pathDllmain, options.offset)

        filenameDllSrc = 'harness.dll'
        pathDllSrc = os.path.join(pathTempDir, filenameDllSrc)

        cmdCd = f'cd /d "{pathTempDir}"'
        cmdMake = f'cl.exe /D_USERDLL /D_WINDLL dllmain.c /MT /link /DLL /OUT:{filenameDllSrc}'

        pathBatch = os.path.join(pathTempDir, 'make.bat')
        with open(pathBatch, 'w') as file:
            file.write(
                f'''
if not defined DevEnvDir (
    call "{pathVcvars}"
)
{cmdCd}
{cmdMake}
'''
            )

        cmdBuild = f'"{pathBatch}"'
        logging.debug("About to exec:\n%s", cmdBuild)
        
        try:
            proc = subprocess.run(cmdBuild, shell=True, timeout=10)
            
            if proc.returncode != 0:
                logging.error("Did not succeed")
                exit(1)
            
            logging.debug("This worked")
        except subprocess.TimeoutError:
            logging.error("Compilation timed out")
            exit(1)

        shutil.copy(src=pathDllSrc, dst=pathDllDst)
        logging.info(f"Copied harness DLL to: {pathDllDst}")

if __name__ == "__main__":
    def hex(x):
        return int(x, base=16)

    parser = argparse.ArgumentParser()
    parser.add_argument('--bits', type=int, required=True)
    parser.add_argument('--output', type=str, required=True)
    parser.add_argument('--offset', type=hex, required=True)
    parser.add_argument('--log', type=str, required=False, default='info')
    options = parser.parse_args()

    logging.basicConfig(level=getattr(logging, options.log.upper(), logging.INFO))

    logging.debug(f"Arguments:\n  bits:   {options.bits}\n  output: {options.output}\n  offset: {options.offset}")

    build(options)
