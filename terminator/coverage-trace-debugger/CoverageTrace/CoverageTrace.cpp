
#include "CoverageTrace.h"

#include <chrono>
#include <iostream>
#include <iomanip>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <set>
#include <memory>
#include <sstream>
#include <optional>
#include <vector>
#include "Ntstatus.h"

#include <Psapi.h>
#include <DbgHelp.h>
#pragma comment( lib, "dbghelp.lib" )

std::pair<STARTUPINFO, PROCESS_INFORMATION>
StartProcess(std::wstring fuzzeeCmdLine);

std::map<std::wstring, Module>
GetCurrentModulesList(HANDLE procHandle);

std::map<std::wstring, Module>::iterator
UpdateCurrentModulesList(HANDLE procHandle, std::map<std::wstring, Module>& modules, const LOAD_DLL_DEBUG_INFO& info);

std::optional<Module>
LookupAddress(const std::map<std::wstring, Module> & modules, address_t absoluteAddress);

void
PatchProcess(HANDLE proc, const std::map<address_t, GlobalBasicBlock> & bps);

void
UnpatchBreakpoint(DWORD procId, address_t absAddr, byte_t originalByte);

/*void
OutputStackTrace(const PROCESS_INFORMATION& pi);*/

void
GoBackBeforeBreakpoint(HANDLE hThread);

std::map<address_t, GlobalBasicBlock>
ObtainBreakpoints(
    std::wstring pathToIdaPro,
    std::wstring pathToIdaScript,
    std::wstring pathToBinary,
    std::wstring pathToIdaOutputDir,
    Module const * mod
);

std::vector<ModuleBasicBlock>
ReadBasicBlockBytes(std::wstring path);

void OutputCoverageTrace(
    std::wstring path,
    std::vector<GlobalBasicBlockVisit> trace
);

void
OutputModuleList(std::wstring path, std::map<std::wstring, Module> modules);

void
OutputThreadsList(std::wstring path, std::map<DWORD, ThreadInfo> threads);

std::size_t
HashModulePath(std::wstring path);

// For logging purposes
static std::wostream& out = std::wcout;

void
DebugLoop(
    STARTUPINFO startupInfo,
    PROCESS_INFORMATION processInfo,
    std::wstring pathToIdaPro,
    std::wstring pathToIdaScript,
    std::wstring pathToIdaOutputDir,
    std::wstring pathToTarget,
    int timeout,
    std::wstring pathToOutput,
    std::wstring pathToModuleOutput,
    std::wstring pathToTimeOutput,
    int verbosity
);

std::pair<STARTUPINFO, PROCESS_INFORMATION>
CreateProcessWithParent(std::wstring fuzzeeCmdLine);

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 10) {
        std::wcout << "Expecting 10 arguments but got " << argc << std::endl;
        std::wcout << "Usage: " << std::endl
            << "CoverageTrace.exe"
            << " path-to-idat64.exe"
            << " path-to-ida_bb_list.py"
            << " path-to-ida-output"
            << " path-to-target.exe"
            << " target-cmd-line"
            << " timeout"
            << " path-to-output.bin"
            << " path-to-modlist.txt"
            << " path-to-time.txt"
            << std::endl;
        return 1;
    }

    /*std::wstring pathToIdaPro = L"C:\\Program Files\\IDA Pro 7.6\\idat64.exe";
    std::wstring pathToIdaScript = L"C:\\Users\\kolvenba\\Projekte\\research\\fuzzing\\CustomFuzzer\\CoverageTrace\\ida_bb_list.py";
    std::wstring pathToTarget = L"C:\\Users\\kolvenba\\Projekte\\research\\fuzzing\\fuzzing-target-apps\\mupdf\\mupdf-1.7-x64\\platform\\win32\\x64\\Release\\mupdf.exe";
    std::wstring pathToOutput = L"C:\\Users\\kolvenba\\Projekte\\research\\fuzzing\\CustomFuzzer\\CoverageTrace\\out.bin";
    std::wstring pathToMuInput = L"C:\\Users\\kolvenba\\Projekte\\research\\fuzzing\\CustomFuzzer\\CoverageTrace\\quarantaneregeln_in_hessen_final_051221.pdf";
    std::wstring pathToMuOutput = L"C:\\Users\\kolvenba\\Projekte\\research\\fuzzing\\CustomFuzzer\\CoverageTrace\\out.png";
    std::wstring cmdLine = pathToTarget + L" " + pathToMuInput;
    pathToTarget = L"C:\\Users\\kolvenba\\Projekte\\research\\fuzzing\\fuzzing-target-apps\\mupdf\\mupdf-1.7-x64\\platform\\win32\\Debug\\mutool.exe";
    cmdLine = pathToTarget + L" info " + pathToMuInput;
    pathToTarget = L"C:\\Users\\kolvenba\\Projekte\\research\\fuzzing\\fuzzing-target-apps\\mupdf\\mupdf-1.7-x64\\platform\\win32\\x64\\Release\\mutool.exe";
    cmdLine = pathToTarget + L" info " + pathToMuInput;
    pathToTarget = L"C:\\Users\\kolvenba\\Projekte\\research\\fuzzing\\fuzzing-target-apps\\mupdf\\mupdf-1.7-x64\\platform\\win32\\x64\\Release\\mutool.exe";
    cmdLine = pathToTarget + L" clean " + pathToMuInput + L" " + pathToMuOutput;
    pathToTarget = L"C:\\Users\\kolvenba\\Projekte\\research\\fuzzing\\fuzzing-target-apps\\mupdf\\mupdf-1.19\\platform\\win32\\x64\\Release\\mutool.exe";
    cmdLine = pathToTarget + L" draw -o " + pathToMuOutput + L" " + pathToMuInput;*/

    int arg = 0;
    std::wstring pathToIdaPro = argv[++arg];
    std::wstring pathToIdaScript = argv[++arg];
    std::wstring pathToIdaOutputDir = argv[++arg];
    std::wstring pathToTarget = argv[++arg];
    std::wstring cmdLine = argv[++arg];
    int timeout = std::stoi(argv[++arg]);
    std::wstring pathToOutput = argv[++arg];
    std::wstring pathToModuleOutput = argv[++arg];
    std::wstring pathToTimeOutput = argv[++arg];
    int verbosity = std::stoi(argv[++arg]);

    out << "The command line to the target is:" << std::endl
        << cmdLine
        << std::endl;

    //auto [si, pi] = CreateProcessWithParent(cmdLine);
    auto [si, pi] = StartProcess(cmdLine);

    DebugLoop(si, pi, 
        pathToIdaPro,
        pathToIdaScript,
        pathToIdaOutputDir,
        pathToTarget,
        timeout,
        pathToOutput,
        pathToModuleOutput,
        pathToTimeOutput,
        verbosity
    );

	return 0;
}

void
DebugLoop(
    STARTUPINFO startupInfo,
    PROCESS_INFORMATION processInfo,
    std::wstring pathToIdaPro,
    std::wstring pathToIdaScript,
    std::wstring pathToIdaOutputDir,
    std::wstring pathToTarget,
    int timeoutMs,
    std::wstring pathToOutput,
    std::wstring pathToModuleOutput,
    std::wstring pathToTimeOutput,
    int verbosity
)
{
    //std::wstring pathToThreadsOutput =
    std::filesystem::path ppathToTimeOutput(pathToTimeOutput);
    std::filesystem::path ppathToThreadsOutput = ppathToTimeOutput.parent_path() / "threads.txt";
    std::wstring pathToThreadsOutput = ppathToThreadsOutput.wstring();

    /* This will be written by the WinAPI function WaitForDebugEvent. */
    DEBUG_EVENT debugEv;

    /* This will be passed to the WinAPI function ContinueDebugEvent at the end 
       of each loop iteration. */
    DWORD dwContinueStatus = DBG_CONTINUE;

    /* This will be written during the debugging event CREATE_PROCESS_DEBUG_EVENT.
       It contains information about the target processto be used by our debugger. */
    CREATE_PROCESS_DEBUG_INFO createProcessInfo;

    /* The thread ID at the initial breakpoint*/
    DWORD threadIdAtStartBp;

    /* We keep track of all threads, because we need to decide which context to 
       use when we want to continue after a breakpoint. */
    static std::map<DWORD, ThreadInfo> threads;

    /* This iterator is used several times in the loop. We put it outside the 
       loop because of restrictions on variable declarations inside switch 
       statements. */
    std::map<DWORD, ThreadInfo>::const_iterator threads_it;

    /* Iterator for finding breakpoints. */
    //std::map<address_t, byte_t>::const_iterator bp_it;

    /* The currently loaded modules, including the executable image.
       Changes when a DLL is loaded or unloaded. */
    std::map<std::wstring, Module> currentModules;

    /* The boolean condition of the debugging loop. */
    bool shouldContinue = true;

    /* The current state of our simple state machine. */
    DebugFsmState state = DebugFsmState::JustStarted;

    /* Process handle used to set and unset breakpoints. */
    HANDLE rewriteProcHandle = nullptr;

    /* Active breakpoints, i.e., those that have not been visited yet. */
    std::map<address_t, GlobalBasicBlock> bpActive;

    /* Visited breakpoints. */
    std::vector<GlobalBasicBlockVisit> bpVisited;

    // At the time the debugger is informed about an upcoming DLL load, the DLL 
    // is not yet loaded. A few convenient WinAPI functions to identify the 
    // base address and so on are not available yet. Until I know how to get 
    // these information up front, I have to analyze the DLL during a future 
    // breakpoint, when the DLL is already loaded.
    std::vector<LOAD_DLL_DEBUG_INFO> deferredDllLoads;

    std::map<long, std::string> exception_codes;
    std::map<long, std::string>::const_iterator code_it;
    exception_codes[EXCEPTION_ACCESS_VIOLATION] = "EXCEPTION_ACCESS_VIOLATION";
    exception_codes[EXCEPTION_ARRAY_BOUNDS_EXCEEDED] = "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
    exception_codes[EXCEPTION_BREAKPOINT] = "EXCEPTION_BREAKPOINT";
    exception_codes[EXCEPTION_DATATYPE_MISALIGNMENT] = "EXCEPTION_DATATYPE_MISALIGNMENT";
    exception_codes[EXCEPTION_FLT_DENORMAL_OPERAND] = "EXCEPTION_FLT_DENORMAL_OPERAND";
    exception_codes[EXCEPTION_FLT_DIVIDE_BY_ZERO] = "EXCEPTION_FLT_DIVIDE_BY_ZERO";
    exception_codes[EXCEPTION_FLT_INEXACT_RESULT] = "EXCEPTION_FLT_INEXACT_RESULT";
    exception_codes[EXCEPTION_FLT_INVALID_OPERATION] = "EXCEPTION_FLT_INVALID_OPERATION";
    exception_codes[EXCEPTION_FLT_OVERFLOW] = "EXCEPTION_FLT_OVERFLOW";
    exception_codes[EXCEPTION_FLT_STACK_CHECK] = "EXCEPTION_FLT_STACK_CHECK";
    exception_codes[EXCEPTION_FLT_UNDERFLOW] = "EXCEPTION_FLT_UNDERFLOW";
    exception_codes[EXCEPTION_ILLEGAL_INSTRUCTION] = "EXCEPTION_ILLEGAL_INSTRUCTION";
    exception_codes[EXCEPTION_IN_PAGE_ERROR] = "EXCEPTION_IN_PAGE_ERROR";
    exception_codes[EXCEPTION_INT_DIVIDE_BY_ZERO] = "EXCEPTION_INT_DIVIDE_BY_ZERO";
    exception_codes[EXCEPTION_INT_OVERFLOW] = "EXCEPTION_INT_OVERFLOW";
    exception_codes[EXCEPTION_INVALID_DISPOSITION] = "EXCEPTION_INVALID_DISPOSITION";
    exception_codes[EXCEPTION_NONCONTINUABLE_EXCEPTION] = "EXCEPTION_NONCONTINUABLE_EXCEPTION";
    exception_codes[EXCEPTION_PRIV_INSTRUCTION] = "EXCEPTION_PRIV_INSTRUCTION";
    exception_codes[EXCEPTION_SINGLE_STEP] = "EXCEPTION_SINGLE_STEP";
    exception_codes[EXCEPTION_STACK_OVERFLOW] = "EXCEPTION_STACK_OVERFLOW";

    std::map<long, int> verbosity_levels;
    std::map<long, int>::const_iterator verb_it;
    verbosity_levels[EXCEPTION_ACCESS_VIOLATION] = 0;
    verbosity_levels[EXCEPTION_ARRAY_BOUNDS_EXCEEDED] = 0;
    verbosity_levels[EXCEPTION_BREAKPOINT] = 1;
    verbosity_levels[EXCEPTION_DATATYPE_MISALIGNMENT] = 0;
    verbosity_levels[EXCEPTION_FLT_DENORMAL_OPERAND] = 0;
    verbosity_levels[EXCEPTION_FLT_DIVIDE_BY_ZERO] = 0;
    verbosity_levels[EXCEPTION_FLT_INEXACT_RESULT] = 0;
    verbosity_levels[EXCEPTION_FLT_INVALID_OPERATION] = 0;
    verbosity_levels[EXCEPTION_FLT_OVERFLOW] = 0;
    verbosity_levels[EXCEPTION_FLT_STACK_CHECK] = 0;
    verbosity_levels[EXCEPTION_FLT_UNDERFLOW] = 0;
    verbosity_levels[EXCEPTION_ILLEGAL_INSTRUCTION] = 0;
    verbosity_levels[EXCEPTION_IN_PAGE_ERROR] = 0;
    verbosity_levels[EXCEPTION_INT_DIVIDE_BY_ZERO] = 0;
    verbosity_levels[EXCEPTION_INT_OVERFLOW] = 0;
    verbosity_levels[EXCEPTION_INVALID_DISPOSITION] = 0;
    verbosity_levels[EXCEPTION_NONCONTINUABLE_EXCEPTION] = 0;
    verbosity_levels[EXCEPTION_PRIV_INSTRUCTION] = 0;
    verbosity_levels[EXCEPTION_SINGLE_STEP] = 0;
    verbosity_levels[EXCEPTION_STACK_OVERFLOW] = 0;

    out << "Hello from EnterDebugLoop()" << std::endl;

    auto timeAtStart = std::chrono::high_resolution_clock::now();
    std::chrono::high_resolution_clock::duration halted = std::chrono::high_resolution_clock::duration::zero();
    std::chrono::high_resolution_clock::duration running = std::chrono::high_resolution_clock::duration::zero();
    std::wofstream timeLog(pathToTimeOutput);
    bool killed = false;

    std::chrono::high_resolution_clock::time_point runningFrom, runningTill;
    std::chrono::high_resolution_clock::time_point haltedFrom, haltedTill;

    ResumeThread(processInfo.hThread);
    runningFrom = std::chrono::high_resolution_clock::now();
	
	unsigned long long sizeAtTermination = 0;

    while (shouldContinue)
    {
        /* Wait for a debugging event to occur. If the timeout is hit, waitSuccess is zero and 
         * GetLastError() returns ERROR_SEM_TIMEOUT = 121 (the code is not documented, though). */
        bool waitSuccess = WaitForDebugEvent(
            &debugEv,
            max(timeoutMs - std::chrono::duration_cast<std::chrono::milliseconds>(running).count(), 0)
        );

        runningTill = std::chrono::high_resolution_clock::now();
        haltedFrom = runningTill;
        running += runningTill - runningFrom;

        auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(runningTill - timeAtStart).count();
        auto elapsedRunningMs = std::chrono::duration_cast<std::chrono::milliseconds>(running).count();
        auto haltedMs = std::chrono::duration_cast<std::chrono::milliseconds>(halted).count();

        if (elapsedRunningMs >= timeoutMs || !waitSuccess) {
            out << "Terminating, because" << std::endl
                << "    elapsed (running) " << std::dec << elapsedRunningMs << std::endl
                << "    elapsed (total)   " << std::dec << elapsedMs << std::endl
                << "    halted            " << std::dec << haltedMs << std::endl
                << "is greater than" << std::endl
                << "    timeout           " << std::dec << timeoutMs << std::endl
                << "WaitForDebugEv success:" << std::endl
                << "    " << waitSuccess << std::endl;

            timeLog << "Terminating, because" << std::endl
                << "    elapsed (running) " << std::dec << elapsedRunningMs << std::endl
                << "    elapsed (total)   " << std::dec << elapsedMs << std::endl
                << "    halted            " << std::dec << haltedMs << std::endl
                << "is greater than" << std::endl
                << "    timeout           " << std::dec << timeoutMs << std::endl
                << "WaitForDebugEv success:" << std::endl
                << "    " << waitSuccess << std::endl;
				
			out << "Trace length at time of termination: " << std::dec << bpVisited.size() << std::endl;
			timeLog << "Trace length at time of termination: " << std::dec << bpVisited.size() << std::endl;
			sizeAtTermination = bpVisited.size();

            /*out << "Adding marker basic block" << std::endl;
            timeLog << "Adding marker basic block" << std::endl;
			
			currentModules[L"DUMMY"] = Module{0, 0, 0, L"", false};
			
            bpVisited.push_back(GlobalBasicBlockVisit{
                GlobalBasicBlock{
					&currentModules[L"DUMMY"],
					ModuleBasicBlock{0, 0, 0, 0, 0, 0, 0, 0}
				},
				std::chrono::high_resolution_clock::now(),
				0
			});*/
			
		    TerminateProcess(processInfo.hProcess, 1);
            killed = true;

            break;
        }

        /* By default, continue without special treatment of the breakpoint. 
           This value might be overwritten before the end of the current 
           iteration. At the end of the iteration, it is passed to the function 
           ContinueDebugEvent. */
        dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;

        switch (debugEv.dwDebugEventCode)
        {
        case EXCEPTION_DEBUG_EVENT:
            // Check whether the current verbosity level fits to the verbosity 
            // level of the current exception. If so, or if the exception code 
            // is unknown, output some information about the event.
            verb_it = verbosity_levels.find(debugEv.u.Exception.ExceptionRecord.ExceptionCode);
            if (verb_it == verbosity_levels.end() || verbosity >= verb_it->second) {
                out << "Exception at "
                    << std::hex << debugEv.u.Exception.ExceptionRecord.ExceptionAddress
                    << ": 0x" << std::hex << debugEv.u.Exception.ExceptionRecord.ExceptionCode;

                code_it = exception_codes.find(debugEv.u.Exception.ExceptionRecord.ExceptionCode);
                if (code_it != exception_codes.end()) {
                    out << "(" << code_it->second.c_str() << ")";
                }

                out << std::endl;
            }
            
            switch (debugEv.u.Exception.ExceptionRecord.ExceptionCode)
            {
            case STATUS_WX86_BREAKPOINT:
                // This is something like 0x4000001f
                dwContinueStatus = DBG_CONTINUE;
                break;
            case EXCEPTION_BREAKPOINT:
                if (state == DebugFsmState::WaitingForInitialBreakpoint)
                {
                    /* I think, the initial breakpoint is the first breakpoint that 
                       is triggered in WinDbg after loading a process. Here, we can 
                       initialize the symbolics. */
                    if (!SymInitialize(processInfo.hProcess, nullptr, true)) {
                        out << "SymInitialize() fails: " << std::dec << GetLastError() << std::endl;
                        std::exit(1);
                    }

                    currentModules = GetCurrentModulesList(processInfo.hProcess);

                    out << "Removing "
                        << std::dec << deferredDllLoads.size()
                        << " deferred DLL loads"
                        << std::endl;
                    for (auto i : deferredDllLoads) {
                        CloseHandle(i.hFile);
                    }
                    deferredDllLoads.clear();

                    auto targetModule = currentModules.find(pathToTarget);
                    if (targetModule == currentModules.cend()) {
                        out << "Cannot find module of target executable with path:" << std::endl
                            << "    " << pathToTarget << std::endl;
                        std::exit(1);
                    }
                    targetModule->second.tracked = true;
                    
                    auto beforeObtain = std::chrono::high_resolution_clock::now();
                    bpActive = ObtainBreakpoints(pathToIdaPro, pathToIdaScript, pathToTarget, pathToIdaOutputDir, &targetModule->second);
                    auto afterObtain = std::chrono::high_resolution_clock::now();
                    out << "Obtaining breakpoints took "
                        << std::chrono::duration_cast<std::chrono::milliseconds>(afterObtain - beforeObtain).count()
                        << "ms" << std::endl;
                    out << "Active breakpoints: " << std::dec << bpActive.size() << std::endl;
                    PatchProcess(rewriteProcHandle, bpActive);

                    dwContinueStatus = DBG_CONTINUE;
                    state = DebugFsmState::WaitingForNextBreakpoint;
                    out << L"State -> WaitingForNextBreakpoint" << std::endl;
                    break;
                }
                else if (state == DebugFsmState::WaitingForNextBreakpoint)
                {
                    if (!deferredDllLoads.empty()) {
                        for (auto i : deferredDllLoads) {
                            UpdateCurrentModulesList(processInfo.hProcess, currentModules, i);
                            CloseHandle(i.hFile);
                        }
                        deferredDllLoads.clear();
                    }

                    uintptr_t absAddr = reinterpret_cast<uintptr_t>(debugEv.u.Exception.ExceptionRecord.ExceptionAddress);
                    auto maybeModule = LookupAddress(currentModules, absAddr);
                    if (!maybeModule.has_value()) {
                        out << "Unknown address!" << std::endl;

                        GetCurrentModulesList(processInfo.hProcess);
                        std::exit(1);
                    }

                    auto bp_it = bpActive.find(absAddr);
                    if (bp_it == bpActive.cend()) {
                        out << "Unknown breakpoint!" << std::endl;
                        break;
                        // std::exit(1);
                    }

                    threads_it = threads.find(debugEv.dwThreadId);
                    if (threads_it == threads.cend()) {
                        out << "Unknown thread " << std::dec << debugEv.dwThreadId << std::endl;
                        std::exit(1);
                    }

                    bpVisited.push_back(GlobalBasicBlockVisit{
                        bp_it->second,
                        std::chrono::high_resolution_clock::now(),
                        threads_it->first
                    });
                    //out << "Hit breakpoint " << std::hex << bp_it->first << std::endl;

                    UnpatchBreakpoint(debugEv.dwProcessId, bp_it->first, bp_it->second.module_block.firstByte);
                    bpActive.erase(bp_it);
                    //OutputStackTrace(processInfo);
                    GoBackBeforeBreakpoint(threads_it->second.handle);

                    if (bpActive.size() <= 0) {
                        state = DebugFsmState::NoMoreBreakpoints;
                        out << L"State -> NoMoreBreakpoints" << std::endl;
                    }
                    else {
                        state = DebugFsmState::WaitingForNextBreakpoint;
                        //out << L"State -> WaitingForNextBreakpoint" << std::endl;
                    }

                    dwContinueStatus = DBG_CONTINUE;
                }
                else if (state == DebugFsmState::NoMoreBreakpoints)
                {
                    out << "Unexpected: no more breakpoints " << std::endl;
                    std::exit(1);
                }
                else if (state == DebugFsmState::JustStarted)
                {
                    out << "Hm." << std::endl;
                }
                else
                {
                    out << "Unexpected state: " << (int)state << std::endl;
                    std::exit(1);
                }

                break;
            }
            break;

        case CREATE_THREAD_DEBUG_EVENT:
            if (state == DebugFsmState::JustStarted) {
                /* When we’ve just started, patch the process and set the 
                   breakpoints. */

                /*rewriteProcHandle = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_QUERY_INFORMATION, false, debugEv.dwProcessId);
                if (rewriteProcHandle == NULL) {
                    out << "OpenProcess error: "
                        << std::dec << GetLastError()
                        << std::endl;
                    std::exit(1);
                }

                state = DebugFsmState::WaitingForInitialBreakpoint;*/
            }
            else {
                /* Nothing; a thread may start at any time. */
            }

            threads[debugEv.dwThreadId] = ThreadInfo { debugEv.dwThreadId, debugEv.u.CreateThread.hThread, threads.size() };

            out << "New thread " << std::dec << debugEv.dwThreadId << std::endl;

            //CloseHandle(debugEv.u.CreateThread.hThread);

            break;

        case CREATE_PROCESS_DEBUG_EVENT:
            // As needed, examine or change the registers of the
            // process's initial thread with the GetThreadContext and
            // SetThreadContext functions; read from and write to the
            // process's virtual memory with the ReadProcessMemory and
            // WriteProcessMemory functions; and suspend and resume
            // thread execution with the SuspendThread and ResumeThread
            // functions. Be sure to close the handle to the process image
            // file with CloseHandle.

            if (state != DebugFsmState::JustStarted) {
                /* We are expecting the process to start only at the 
                   beginning of our state machine. */
                out << "Error!" << std::endl;
                std::exit(1);
            }

            rewriteProcHandle = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_QUERY_INFORMATION, false, debugEv.dwProcessId);
            if (rewriteProcHandle == NULL) {
                out << "OpenProcess error: "
                    << std::dec << GetLastError()
                    << std::endl;
                std::exit(1);
            }

            state = DebugFsmState::WaitingForInitialBreakpoint;

            createProcessInfo = debugEv.u.CreateProcessInfo;
            threads[debugEv.dwThreadId] = ThreadInfo { debugEv.dwThreadId, createProcessInfo.hThread, threads.size() };

            out << "Process created with ID " << std::dec << debugEv.dwProcessId
                << std::endl
                << "          and thread ID " << std::dec << debugEv.dwThreadId
                << std::endl;

            /*CloseHandle(debugEv.u.CreateProcessInfo.hFile);
            CloseHandle(debugEv.u.CreateProcessInfo.hProcess);
            CloseHandle(debugEv.u.CreateProcessInfo.hThread);*/

            break;

        case EXIT_THREAD_DEBUG_EVENT:
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            shouldContinue = false;
            break;

        case LOAD_DLL_DEBUG_EVENT:
            deferredDllLoads.push_back(debugEv.u.LoadDll);
            //if (state != DebugFsmState::WaitingForInitialBreakpoint) {
                /* From MSDN:
                 *     https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-load_dll_debug_info
                 * There they say about debugEv.u.LoadDll.lpImageName:
                 *
                 *     This member is strictly optional. Debuggers must be prepared to handle the case where
                 *     lpImageName is NULL or *lpImageName (in the address space of the process being debugged)
                 *     is NULL. Specifically, the system will never provide an image name for a create process
                 *     event, and it will not likely pass an image name for the first DLL event. The system
                 *     will also never provide this information in the case of debugging events that originate
                 *     from a call to the DebugActiveProcess function.
                 */

                //UpdateCurrentModulesList(processInfo.hProcess, currentModules, debugEv.u.LoadDll);
            //}
            //CloseHandle(debugEv.u.LoadDll.hFile);
            break;

        case UNLOAD_DLL_DEBUG_EVENT:
            break;

        case OUTPUT_DEBUG_STRING_EVENT:
            break;

        case RIP_EVENT:
            shouldContinue = true;
            out << "RIP_EVENT" << std::endl;
            break;
        default:
            break;
        }

        ContinueDebugEvent(debugEv.dwProcessId, debugEv.dwThreadId, dwContinueStatus);
        runningFrom = std::chrono::high_resolution_clock::now();
        haltedTill = runningFrom;
        halted += haltedTill - haltedFrom;
    }

    out << "Trace is that long: " << std::dec << bpVisited.size() << std::endl;
	
	if (sizeAtTermination > 0 && bpVisited.size() != sizeAtTermination) {
		out << "WARNING: unexpected new trace entries after termination!" << std::endl;
	}

    OutputCoverageTrace(pathToOutput, bpVisited);
    OutputModuleList(pathToModuleOutput, currentModules);
    OutputThreadsList(pathToThreadsOutput, threads);

    if (!killed) {

        auto timeNow = std::chrono::high_resolution_clock::now();
        auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(timeNow - timeAtStart).count();
        auto elapsedRunningMs = std::chrono::duration_cast<std::chrono::milliseconds>((timeNow - timeAtStart) - halted).count();

        timeLog << "Finished after" << std::endl
            << "    elapsed (running) " << std::dec << elapsedRunningMs << std::endl
            << "    elapsed (total)   " << std::dec << elapsedMs << std::endl
            << "    halted            " << std::dec << std::chrono::duration_cast<std::chrono::milliseconds>(halted).count() << std::endl;
    }

    out << "Bye bye from EnterDebugLoop()" << std::endl;
}

/**
 * Starts the target process suspended and attaches the current process as a debugger.
 */
std::pair<STARTUPINFO, PROCESS_INFORMATION>
StartProcess(std::wstring fuzzeeCmdLine)
{
    // These will be filled by CreateProcess and later returned.
    STARTUPINFO startupInfo;
    PROCESS_INFORMATION processInfo;

    ZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);
    ZeroMemory(&processInfo, sizeof(processInfo));

    /* CreateProcess requires a non-const argument, for whatever reason. Hence, we have to
       copy the const c_str() to a new non-const char field. */
    std::size_t size = fuzzeeCmdLine.size() * sizeof(wchar_t);
    std::unique_ptr<wchar_t[]> cmdLinePtr(new wchar_t[fuzzeeCmdLine.size() + 1]);
    wchar_t* cmdLine = cmdLinePtr.get();
    memcpy_s(cmdLine, size, fuzzeeCmdLine.c_str(), size);
    cmdLine[fuzzeeCmdLine.size()] = '\0';

    /* Create suspended so that we can set breakpoints. */
    DWORD creationFlags = CREATE_SUSPENDED | DEBUG_ONLY_THIS_PROCESS;

    /*
     * DEBUG_ONLY_THIS_PROCESS means that only the process is debugged, but not its child processes.
     *
     * C6335: The handles are closed in EnterInMemoryFuzzingLoop().
     */

    if (!CreateProcess(
        nullptr,       /* LPCWSTR               lpApplicationName */
        cmdLine,       /* LPWSTR                lpCommandLine */
        nullptr,       /* LPSECURITY_ATTRIBUTES lpProcessAttributes */
        nullptr,       /* LPSECURITY_ATTRIBUTES lpThreadAttributes */
        false,         /* BOOL                  bInheritHandles */
        creationFlags, /* DWORD                 dwCreationFlags */
        nullptr,       /* LPVOID                lpEnvironment */
        nullptr,       /* LPCWSTR               lpCurrentDirectory */
        &startupInfo,  /* LPSTARTUPINFOW        lpStartupInfo */
        &processInfo   /* LPPROCESS_INFORMATION lpProcessInformation */
    ))
    {
        out << "CreateProcess error: "
            << std::dec << GetLastError()
            << std::endl;
        std::exit(1);
    }

    out << "CreateProcess() successful" << std::endl;

    return std::make_pair(startupInfo, processInfo);
}

std::map<std::wstring, Module>
GetCurrentModulesList(HANDLE procHandle)
{
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(procHandle, hMods, sizeof(hMods), &cbNeeded))
    {
        out << "EnumProcessModules error in GetCurrentModulesList: "
            << std::dec << GetLastError()
            << std::endl;
        std::exit(1);
    }

    TCHAR szModName[MAX_PATH];
    std::wstring path;
    
    std::map<std::wstring, Module> modules;

    for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
    {
        // Get the full path to the module's file.

        if (!GetModuleFileNameEx(procHandle, hMods[i], szModName,
            sizeof(szModName) / sizeof(TCHAR)))
        {
            out << "GetModuleFileNameEx error: "
                << GetLastError()
                << std::endl;
            std::exit(1);
        }

        path = szModName;

        MODULEINFO minfo;
        if (!GetModuleInformation(
            procHandle,   /* HANDLE       hProcess*/
            hMods[i],     /* HMODULE      hModule */
            &minfo,       /* LPMODULEINFO lpmodinfo */
            sizeof(minfo) /* DWORD        cb */
        )) {
            out << "GetModuleInformation error: "
                << GetLastError()
                << std::endl;
            std::exit(1);
        }

        Module mod;
        mod.id = HashModulePath(path);
        mod.start = (address_t)minfo.lpBaseOfDll;
        mod.end = (address_t)minfo.lpBaseOfDll + (address_t)minfo.SizeOfImage;
        mod.path = path;
        modules[path] = mod;

        out << "Module: " << mod.path
            << "   " << hMods[i]
            << "   0x" << std::hex << mod.start
            << "   0x" << std::hex << mod.end
            << std::endl;
    }

    return modules;
}

std::wstring
GetFileNameFromHandle(HANDLE hFile)
{
    std::wstring result;

    const DWORD sizeBuffer = MAX_PATH;
    TCHAR buffer[sizeBuffer];
    DWORD length;
    
    length = GetFinalPathNameByHandleW(hFile, buffer, sizeBuffer, FILE_NAME_NORMALIZED);

    if (length == 0) {
        out << "GetFinalPathNameByHandleW error: " << std::dec << GetLastError() << std::endl;
        std::exit(1);
    }

    if (length >= sizeBuffer) {
        DWORD sizeDynBuffer = length;
        TCHAR* dynBuffer = new TCHAR[sizeDynBuffer];

        length = GetFinalPathNameByHandleW(hFile, dynBuffer, sizeDynBuffer, FILE_NAME_NORMALIZED);
        if (length + 1 != sizeDynBuffer) {
            out << "Unexpected GetFinalPathNameByHandleW behavior" << std::endl;
            std::exit(1);
        }

        result = dynBuffer;
        delete[] dynBuffer;

        return result;
    }

    result = buffer;
    return result;
}

std::map<std::wstring, Module>::iterator
UpdateCurrentModulesList(HANDLE procHandle, std::map<std::wstring, Module>& modules, const LOAD_DLL_DEBUG_INFO & info)
{
    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(procHandle, hMods, sizeof(hMods), &cbNeeded))
    {
        out << "EnumProcessModules error in UpdateCurrentModulesList: "
            << std::dec << GetLastError()
            << std::endl;
        std::exit(1);
    }

    TCHAR szModName[MAX_PATH];
    std::wstring path;

    for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
    {
        MODULEINFO minfo;
        if (!GetModuleInformation(
            procHandle,   /* HANDLE       hProcess*/
            hMods[i],     /* HMODULE      hModule */
            &minfo,       /* LPMODULEINFO lpmodinfo */
            sizeof(minfo) /* DWORD        cb */
        )) {
            out << "GetModuleInformation error: "
                << GetLastError()
                << std::endl;
            std::exit(1);
        }

        if (minfo.lpBaseOfDll != info.lpBaseOfDll)
        {
            //out << std::hex << minfo.lpBaseOfDll << " != " << info.lpBaseOfDll << std::endl;
            continue;
        }

        // Get the full path to the module's file.
        if (!GetModuleFileNameEx(procHandle, hMods[i], szModName,
            sizeof(szModName) / sizeof(TCHAR)))
        {
            out << "GetModuleFileNameEx error: "
                << GetLastError()
                << std::endl;
            std::exit(1);
        }

        path = szModName;

        Module mod;
        mod.id = HashModulePath(path);
        mod.start = (address_t)minfo.lpBaseOfDll;
        mod.end = (address_t)minfo.lpBaseOfDll + (address_t)minfo.SizeOfImage;
        mod.path = path;

        out << "Module update: " << mod.path
            << "   " << hMods[i]
            << "   0x" << std::hex << mod.start
            << "   0x" << std::hex << mod.end
            << std::endl;

        return modules.insert(std::make_pair(path, mod)).first;
    }

    out << "Failed updating modules: " << std::endl
        << "    " << std::hex << info.lpBaseOfDll << std::endl
        << "    " << GetFileNameFromHandle(info.hFile) << std::endl
        << "    not found"
        << std::endl;

    return modules.end();
    //std::exit(1);
}

std::optional<Module>
LookupAddress(const std::map<std::wstring, Module> & modules, address_t absoluteAddress)
{
    for (auto i : modules) {
        if (i.second.start <= absoluteAddress && absoluteAddress <= i.second.end) {
            return i.second;
        }
    }

    return {};
}

void
UnpatchBreakpoint(DWORD processId, address_t absAddr, byte_t originalByte)
{
    SIZE_T nbWritten, nbRead;
    unsigned char patchedByte;

    HANDLE procHandle = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_QUERY_INFORMATION, false, processId);
    if (procHandle == NULL) {
        out << "OpenProcess() error: "
            << std::dec << GetLastError()
            << std::endl;
        std::exit(1);
    }

    if (!ReadProcessMemory(
        procHandle,          // HANDLE  hProcess
        (void*)absAddr,      // LPCVOID lpBaseAddress
        &patchedByte,        // LPVOID  lpBuffer
        sizeof(patchedByte), // SIZE_T  nSize
        &nbRead              // SIZE_T *lpNumberOfBytesRead
    ))
    {
        out << "Could not read patched byte from address: "
            << std::dec << GetLastError()
            << std::endl;
        std::exit(1);
    }

    if (patchedByte != 0xcc) {
        out << "I was expecting to unpatch a breakpoint, but I got byte " << std::hex << patchedByte << std::endl;
        std::exit(1);
    }

    if (!WriteProcessMemory(
        procHandle,           // HANDLE  hProcess
        (void*)absAddr,       // LPVOID  lpBaseAddress
        &originalByte,        // LPCVOID lpBuffer
        sizeof(originalByte), // SIZE_T  nSize
        &nbWritten            // SIZE_T *lpNumberOfBytesWritten
    ))
    {
        out << "Could not unpatch breakpoint: "
            << std::dec << GetLastError()
            << std::endl;
        std::exit(1);
    }

    if (!FlushInstructionCache(procHandle, nullptr, 0))
    {
        out << "Could not flush cache after unpatching breakpoint: "
            << std::dec << GetLastError()
            << std::endl;
        std::exit(1);
    }

    CloseHandle(procHandle);
}
/*
void
OutputStackTrace(const PROCESS_INFORMATION& pi)
{
    CONTEXT Context;
    ZeroMemory(&Context, sizeof(CONTEXT));
    Context.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(pi.hThread, &Context)) {
        out << "GetThreadContext() fails: " << std::dec << GetLastError() << std::endl;
        std::exit(1);
    }

    STACKFRAME64 StackFrame;
    StackFrame.AddrPC.Offset = Context.Rip;
    StackFrame.AddrPC.Mode = AddrModeFlat;
    StackFrame.AddrFrame.Offset = Context.Rbp; //Context.Rsp;
    StackFrame.AddrFrame.Mode = AddrModeFlat;
    StackFrame.AddrStack.Offset = Context.Rsp;
    StackFrame.AddrStack.Mode = AddrModeFlat;

    // Data for StackWalk64
    DWORD MachineType = IMAGE_FILE_MACHINE_AMD64;
    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;
    LPSTACKFRAME64 pStackFrame = &StackFrame;
    PVOID ContextRecord = &Context;
    PREAD_PROCESS_MEMORY_ROUTINE64   ReadMemoryRoutine = NULL;
    PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine = SymFunctionTableAccess64;
    PGET_MODULE_BASE_ROUTINE64       GetModuleBaseRoutine = SymGetModuleBase64;
    PTRANSLATE_ADDRESS_ROUTINE64     TranslateAddress = NULL;

    auto modules = GetCurrentModulesList(pi.hProcess);

    long long depth = 0;

    out << "####"
        << "   "
        << std::setfill(L' ')
        << std::setw(16) << "PC"
        << "   "
        << std::setw(10) << "PC Offset"
        << "   "
        << std::setw(16) << "Return"
        << "   "
        << std::setw(16) << "Stack"
        << "   "
        << "Path"
        << std::endl;

    while (depth < 1024)
    {
        if (!StackWalk64(
            MachineType,
            hProcess,
            hThread,
            &StackFrame,
            ContextRecord,
            ReadMemoryRoutine,
            FunctionTableAccessRoutine,
            GetModuleBaseRoutine,
            TranslateAddress))
        {
            break;
        }

        auto mod_it = std::find_if(modules.cbegin(), modules.cend(), [StackFrame](auto it) {
            return it.second.start <= StackFrame.AddrPC.Offset
                && StackFrame.AddrPC.Offset <= it.second.end;
        });

        out
            << std::dec << std::setfill(L'0')
            << std::setw(4) << depth
            << "   0x"
            << std::hex << std::setfill(L'0')
            << std::setw(14) << StackFrame.AddrPC.Offset
            << "   0x"
            << std::setw(8) << ((mod_it != modules.cend()) ? StackFrame.AddrPC.Offset - mod_it->second.start : StackFrame.AddrPC.Offset)
            << "   0x"
            << std::setw(14) << StackFrame.AddrReturn.Offset
            << "   0x"
            << std::setw(14) << StackFrame.AddrStack.Offset
            << "   "
            << ((mod_it != modules.cend()) ? mod_it->second.path : L"")
            << std::endl;

        ++depth;
    }

    out << std::endl;
}*/

void
GoBackBeforeBreakpoint(HANDLE hThread)
{
    CONTEXT context;
    ZeroMemory(&context, sizeof(context));
    context.ContextFlags = CONTEXT_ALL;

    if (!GetThreadContext(hThread, &context)) {
        out << "GetThreadContext() fails: " << std::dec << GetLastError() << std::endl;
        std::exit(1);
    }

#ifdef _WIN64
    context.Rip--;
#else
    context.Eip--;
#endif

    if (!SetThreadContext(hThread, &context)) {
        out << "SetThreadContext() fails: " << std::dec << GetLastError() << std::endl;
        std::exit(1);
    }
}

void
PatchProcess(HANDLE procHandle, const std::map<address_t, GlobalBasicBlock> & bps)
{
    /* Breakpoint machine code */
    unsigned char cc = 0xcc;

    SIZE_T nbWritten, nbRead;
    byte_t original;

    for (auto bp : bps)
    {
        if (!ReadProcessMemory(
            procHandle,       /* HANDLE  hProcess */
            (void*)bp.first,  /* LPCVOID lpBaseAddress */
            &original,        /* LPVOID  lpBuffer */
            sizeof(original), /* SIZE_T  nSize */
            &nbRead           /* SIZE_T  *lpNumberOfBytesRead */
        ))
        {
            out << "Could not read original byte from address "
                << "0x" << std::hex << bp.first
                << ": "
                << std::dec << GetLastError()
                << std::endl;
            continue;
            // std::exit(1);
        }

        if (original != bp.second.module_block.firstByte) {
            out << "Original byte at address "
                << "0x" << std::hex << bp.first
                << " is "
                << "0x" << (unsigned char)original
                << " but I expected "
                << "0x" << std::hex << bp.second.module_block.firstByte
                << std::endl;
            continue;
            // std::exit(1);
        }

        if (!WriteProcessMemory(
            procHandle,               /* HANDLE  hProcess */
            (void*)bp.first, /* LPVOID  lpBaseAddress */
            &cc,                      /* LPCVOID lpBuffer */
            sizeof(cc),               /* SIZE_T  nSize */
            &nbWritten                /* SIZE_T * lpNumberOfBytesWritten */
        ))
        {
            out << "Could not patch breakpoint at: "
                << std::dec << GetLastError()
                << std::endl;
            std::exit(1);
        }
    }

    if (!FlushInstructionCache(procHandle, nullptr, 0))
    {
        out << "Could not flush cache after patching breakpoint: "
            << std::dec << GetLastError()
            << std::endl;
        std::exit(1);
    }

    //out << "Successfully set breakpoints!" << std::endl;
}

DWORD
RunProgram(std::wstring cmd)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    /* CreateProcess requires a non-const argument, for whatever reason. Hence, we have to
       copy the const c_str() to a new non-const char field. */
    std::size_t size = cmd.size() * sizeof(wchar_t);
    std::unique_ptr<wchar_t[]> cmdLinePtr(new wchar_t[cmd.size() + 1]);
    wchar_t* cmdLine = cmdLinePtr.get();
    memcpy_s(cmdLine, size, cmd.c_str(), size);
    cmdLine[cmd.size()] = '\0';

    out << "About to call:" << std::endl
        << "    " << cmdLine << std::endl;

    /* Create suspended so that we can set breakpoints. */
    DWORD creationFlags = 0;

    /*
     * DEBUG_ONLY_THIS_PROCESS means that only the process is debugged, but not its child processes.
     *
     * C6335: The handles are closed in EnterInMemoryFuzzingLoop().
     */

    if (!CreateProcess(
        nullptr,       /* LPCWSTR               lpApplicationName */
        cmdLine,       /* LPWSTR                lpCommandLine */
        nullptr,       /* LPSECURITY_ATTRIBUTES lpProcessAttributes */
        nullptr,       /* LPSECURITY_ATTRIBUTES lpThreadAttributes */
        false,         /* BOOL                  bInheritHandles */
        creationFlags, /* DWORD                 dwCreationFlags */
        nullptr,       /* LPVOID                lpEnvironment */
        nullptr,       /* LPCWSTR               lpCurrentDirectory */
        &si,           /* LPSTARTUPINFOW        lpStartupInfo */
        &pi            /* LPPROCESS_INFORMATION lpProcessInformation */
    ))
    {
        out << "CreateProcess error: "
            << std::dec << GetLastError()
            << std::endl;
        std::exit(1);
    }

    if (WAIT_FAILED == WaitForSingleObject(pi.hProcess, INFINITE)) {
        out << "WaitForSingleObject error: "
            << std::dec << GetLastError()
            << std::endl;
        std::exit(1);
    }

    DWORD dwExitCode;
    if (STILL_ACTIVE == GetExitCodeProcess(pi.hProcess, &dwExitCode)) {
        out << "GetExitCodeProcess error: "
            << std::dec << GetLastError()
            << std::endl;
        std::exit(1);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return dwExitCode;
}

std::map<address_t, GlobalBasicBlock>
ObtainBreakpoints(std::wstring pathToIdaPro, std::wstring pathToIdaScript, std::wstring pathToBinary, std::wstring pathToIdaOutputDir, Module const * mod)
{
    std::size_t hash = std::hash<std::wstring>{}(pathToBinary);
    std::wostringstream filenameStream;
    filenameStream << std::hex << hash;
    std::wstring filename = filenameStream.str() + L"_bb.bin";
    std::filesystem::path outputDir(pathToIdaOutputDir);
    std::filesystem::path outputPath = outputDir / filename;
    std::filesystem::path outputDatabasePath = outputDir / (filenameStream.str() + L"_database");
    std::wstring outputPathStr = outputPath.native();

    if (!std::filesystem::exists(outputPath) || std::filesystem::file_size(outputPath) <= 0) {
        std::wstring cmd = L"\""
            + pathToIdaPro + L"\""
            + L" -o\""
            + outputDatabasePath.native()
            + L"\""
            + L" -A -S\""
            + pathToIdaScript
            + L" --out \"\""
            + outputPathStr
            + L"\"\""
            + L"\"" // close -S"
            + L" "
            + L"\""
            + pathToBinary
            + L"\"";

        DWORD exitCode;
        exitCode = RunProgram(cmd);

        if (0 != exitCode) {
            out << "Unexpected exit code "
                << std::dec << exitCode << " (" << std::hex << exitCode << "):" << std::endl
                << cmd << std::endl
                << "Are you connected to VPN?" << std::endl;
            std::exit(1);
        }
    }

    std::map<address_t, GlobalBasicBlock> result;

    auto list = ReadBasicBlockBytes(outputPath);
    for (auto i = list.cbegin(); i != list.cend(); i++) {
        ModuleBasicBlock mbb = *i;
        GlobalBasicBlock gbb{ mod, mbb };
        result[mod->start + mbb.base_offset] = gbb;
    }

    return result;
}

std::vector<ModuleBasicBlock>
ReadBasicBlockBytes(std::wstring path)
{
    std::uint64_t curStartEa;
    std::uint64_t curBase = 0;
    std::uint64_t curBaseOffset;
    std::uint64_t curFileOffset;
    std::vector<ModuleBasicBlock> result;
    std::uint64_t curSegStart = 0;
    std::uint64_t curSegOffset = 0;
    std::uint64_t curSize;
    std::uint8_t curByte;

    std::ifstream file(path, std::ios::binary);

    if (!file.good()) {
        out << "Something is wrong with file:" << std::endl
            << "    " << path << std::endl;
        std::exit(1);
    }

    while (file.good()) {
        file.read(reinterpret_cast<char*>(&curStartEa), 8);
        //file.read(reinterpret_cast<char*>(&curBase), 8);
        file.read(reinterpret_cast<char*>(&curBaseOffset), 8);
        file.read(reinterpret_cast<char*>(&curFileOffset), 8);
        //file.read(reinterpret_cast<char*>(&curSegStart), 8);
        //file.read(reinterpret_cast<char*>(&curSegOffset), 8);
        file.read(reinterpret_cast<char*>(&curSize), 8);
        file.read(reinterpret_cast<char*>(&curByte), 1);
        result.push_back(ModuleBasicBlock{ curStartEa, curBase, curBaseOffset, curFileOffset, curSegStart, curSegOffset, curSize, curByte });
    }

    return result;
}

std::size_t HashModulePath(std::wstring path)
{
    return std::hash<std::wstring>{}(path);
}

void OutputCoverageTrace(
    std::wstring path,
    std::vector<GlobalBasicBlockVisit> trace
)
{
    std::ofstream file(path, std::ios::binary);

    std::filesystem::path ppath(path);
    ppath.replace_extension(".txt");
    std::ofstream file2(ppath.wstring());

    for (auto i : trace) {
        std::uint32_t module_id = i.global_block.module->id;
        std::uint32_t offset = i.global_block.module_block.base_offset;
        std::uint32_t file_offset = i.global_block.module_block.file_offset;
        std::uint32_t bb_size = i.global_block.module_block.size;
        std::uint64_t time = std::chrono::duration_cast<std::chrono::nanoseconds>(i.time.time_since_epoch()).count();
        std::uint32_t thread_id = i.thread_id;

        file.write(reinterpret_cast<const char*>(&module_id), sizeof(std::uint32_t));
        file.write(reinterpret_cast<const char*>(&offset), sizeof(std::uint32_t));
        file.write(reinterpret_cast<const char*>(&file_offset), sizeof(std::uint32_t));
        file.write(reinterpret_cast<const char*>(&bb_size), sizeof(std::uint32_t));
        file.write(reinterpret_cast<const char*>(&time), sizeof(std::uint64_t));
        file.write(reinterpret_cast<const char*>(&thread_id), sizeof(std::uint32_t));

        file2 << std::dec << module_id
              << '\t'
              << std::hex << offset
              << '\t'
              << std::hex << file_offset
              << '\t'
              << std::dec << bb_size
              << '\t'
              << std::dec << time
              << '\t'
              << std::dec << thread_id
              << std::endl;
    }
}

void
OutputModuleList(std::wstring path, std::map<std::wstring, Module> modules)
{
    std::wofstream file(path);

    for (auto i : modules) {
        file << std::dec << i.second.id
            << '\t' << std::hex << i.second.start
            << '\t' << (i.second.tracked ? "true" : "false")
            << '\t' << std::hex << i.second.end
            << '\t' << i.second.path
            << std::endl;
    }
}

void
OutputThreadsList(std::wstring path, std::map<DWORD, ThreadInfo> threads)
{
    std::wofstream file(path);
    std::vector<ThreadInfo> thread_list;

    for (auto i : threads) {
        thread_list.push_back(i.second);
    }

    std::sort(thread_list.begin(), thread_list.end(), [](const ThreadInfo& a, const ThreadInfo& b) {
        return a.number < b.number;
    });

    for (auto i : thread_list) {
        file << std::dec << i.number
             << '\t' << std::dec << i.id
             << '\t' << std::hex << i.handle
            << std::endl;
    }
}

std::pair<STARTUPINFO, PROCESS_INFORMATION>
CreateProcessWithParent(std::wstring fuzzeeCmdLine) {
    // These will be filled by CreateProcess and later returned.
    STARTUPINFO startupInfo;
    PROCESS_INFORMATION processInfo;

    ZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);
    ZeroMemory(&processInfo, sizeof(processInfo));

    wchar_t parentCmdLine[256];
    wcscpy_s(parentCmdLine, L"cmd.exe");

    DWORD creationFlags = 0;

    if (!CreateProcess(
        nullptr,       /* LPCWSTR               lpApplicationName */
        parentCmdLine, /* LPWSTR                lpCommandLine */
        nullptr,       /* LPSECURITY_ATTRIBUTES lpProcessAttributes */
        nullptr,       /* LPSECURITY_ATTRIBUTES lpThreadAttributes */
        false,         /* BOOL                  bInheritHandles */
        creationFlags, /* DWORD                 dwCreationFlags */
        nullptr,       /* LPVOID                lpEnvironment */
        nullptr,       /* LPCWSTR               lpCurrentDirectory */
        &startupInfo,  /* LPSTARTUPINFOW        lpStartupInfo */
        &processInfo   /* LPPROCESS_INFORMATION lpProcessInformation */
    ))
    {
        out << "CreateProcess 1 error: "
            << std::dec << GetLastError()
            << std::endl;
        std::exit(1);
    }

    auto hProcess = processInfo.hProcess;

    //
    //
    //
    //
    //

    /* CreateProcess requires a non-const argument, for whatever reason. Hence, we have to
       copy the const c_str() to a new non-const char field. */
    std::size_t size = fuzzeeCmdLine.size() * sizeof(wchar_t);
    std::unique_ptr<wchar_t[]> cmdLinePtr(new wchar_t[fuzzeeCmdLine.size() + 1]);
    wchar_t* cmdLine = cmdLinePtr.get();
    memcpy_s(cmdLine, size, fuzzeeCmdLine.c_str(), size);
    cmdLine[fuzzeeCmdLine.size()] = '\0';

    SIZE_T size2;
    //
    // call InitializeProcThreadAttributeList twice
    // first, get required size
    //
    ::InitializeProcThreadAttributeList(nullptr, 1, 0, (PSIZE_T)&size2);

    //
    // now allocate a buffer with the required size and call again
    //
    auto buffer = std::make_unique<BYTE[]>(size2);
    auto attributes = reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(buffer.get());
    ::InitializeProcThreadAttributeList(attributes, 1, 0, (PSIZE_T)&size2);

    //
    // add the parent attribute
    //
    ::UpdateProcThreadAttribute(attributes, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hProcess, sizeof(hProcess), nullptr, nullptr);

    STARTUPINFOEX si = { sizeof(si) };
    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFO);
    //
    // set the attribute list
    //
    si.lpAttributeList = attributes;
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    /* Create suspended so that we can set breakpoints. */
    creationFlags = EXTENDED_STARTUPINFO_PRESENT;

    /*
     * DEBUG_ONLY_THIS_PROCESS means that only the process is debugged, but not its child processes.
     *
     * C6335: The handles are closed in EnterInMemoryFuzzingLoop().
     */

    if (!CreateProcess(
        nullptr,       /* LPCWSTR               lpApplicationName */
        cmdLine,       /* LPWSTR                lpCommandLine */
        nullptr,       /* LPSECURITY_ATTRIBUTES lpProcessAttributes */
        nullptr,       /* LPSECURITY_ATTRIBUTES lpThreadAttributes */
        false,         /* BOOL                  bInheritHandles */
        creationFlags, /* DWORD                 dwCreationFlags */
        nullptr,       /* LPVOID                lpEnvironment */
        nullptr,       /* LPCWSTR               lpCurrentDirectory */
        &startupInfo,  /* LPSTARTUPINFOW        lpStartupInfo */
        &processInfo   /* LPPROCESS_INFORMATION lpProcessInformation */
    ))
    {
        out << "CreateProcess 2 error: "
            << std::dec << GetLastError()
            << std::endl;
        std::exit(1);
    }

    out << "CreateProcess() successful" << std::endl;


    //
    // cleanup
    //
    ::DeleteProcThreadAttributeList(attributes);

    TerminateProcess(hProcess, 0);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(hProcess);

    return std::make_pair(startupInfo, processInfo);
}
