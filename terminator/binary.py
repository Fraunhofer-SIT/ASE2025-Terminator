
import lief
import logging
import keystone
import os
import shutil
import struct
import sys

import ctypes
import ctypes.wintypes

ADDED_SECTION_NAME = ".new_exe"

def resolve_function_address(dll_name, function_name):
    kernel32 = ctypes.windll.kernel32
    
    # PK: The code below hasn’t worked for me. Specifically, either the handle 
    # to the kernel DLL wasn’t found or the address of ExitProcess with an error 
    # code of 126. See also:
    #     https://stackoverflow.com/a/33780664
    #     https://stackoverflow.com/a/17524073
    #     https://stackoverflow.com/q/35849546
    #

    # PK: Originally, the variant GetModuleHandleA was called here, which uses 
    # a different encoding of its parameters. The input encoding of this file 
    # (Patch_Section) might be relevant. Alternatively, call this method with 
    # resolve_function(b'KERNEL32.dll', b'ExitProcess')?
    # 
    # handle = kernel32.GetModuleHandleW(dll)
    # print("    [*] Found handle " + str(handle))
    # error = kernel32.GetLastError()
    # print("        %d: %s" % (error, FormatError(error)))
    # 
    # address = kernel32.GetProcAddress(handle, func)
    # print("    [*] Found address " + str(address))
    # error = kernel32.GetLastError()
    # print("        %d: %s" % (error, FormatError(error)))
    # 
    # address = kernel32.GetProcAddress(handle, b"ExitProcess")
    # print("    [*] Found address " + str(address))
    # error = kernel32.GetLastError()
    # print("        %d: %s" % (error, FormatError(error)))
    # 
    # kernel32.CloseHandle(handle)

    # PK: This is adapted from https://stackoverflow.com/a/33780664.
    kernel32_2 = ctypes.WinDLL(dll_name, use_last_error=True)   
    kernel32_2.GetProcAddress.restype = ctypes.c_void_p
    kernel32_2.GetProcAddress.argtypes = (ctypes.wintypes.HMODULE, ctypes.wintypes.LPCSTR)
    address = kernel32_2.GetProcAddress(kernel32_2._handle, function_name)
    error = ctypes.get_last_error()

    if error != 0:
        print("[-] Error %d: %s" % (error, ctypes.FormatError(error)))
        return None

    return address

def asm_call_to_exitprocess():
    # PK: Here it is necessary to pass 'ExitProcess' as bytes, not as a unicode 
    # string. Otherwise, a type error is thrown by ctypes.
    #address = resolve_function_address('KERNEL32.dll', b'ExitProcess')
    address = resolve_function_address('KERNEL32.dll', b'TerminateProcess')

    if not address:
        raise Exception("ExitProcess has not been found")
    
    code = []

    # PK: Original 32 bit code. 
    # code += [0x31, 0xc0] # xor eax, eax
    # code += [0x50] # push eax
    # code += [0xb8] # mov eax…
    
    # PK: The calling convention for 64-bit Windows is different. The first (and
    # only argument) to ExitProcess(0), i.e., that 0, has to be placed in RCX.
    # The address of ExitProcess is 64 bits long and, hence, has to be put into 
    # RAX instead of EAX.
    code += [0x48, 0x31, 0xc9] # xor rcx, rcx  a.k.a  load 0 into rcx
    code += [0x48, 0xb8] # mov rax… (rest follows)

    # PK: The original line is:
    #     code += list(map(ord, struct.pack("<I", address)))
    # Two things no longer work with that line. First, struct.pack nowadays (?) 
    # already returns a string and needs not be converted with list(map(ord, …)). 
    # Second, the address is a long long on my system, not an int. Therefore, 
    # "<Q" instead of "<I" needs to be used, see 
    #     https://docs.python.org/3/library/struct.html#format-characters

    try:
        code += struct.pack("<I", address)
    except struct.error:
        code += struct.pack("<Q", address)

    # This is indentical for call eax
    code += [0xff, 0xd0] # call rax

    return code

def asm_terminate_process(exit_code=0):
    # PK: Here it is necessary to pass 'TerminateProcess' as bytes, not as a 
    # unicode string. Otherwise, a type error is thrown by ctypes.
    #address = resolve_function_address('KERNEL32.dll', b'ExitProcess')
    address = resolve_function_address('KERNEL32.dll', b'TerminateProcess')

    if not address:
        raise Exception("ExitProcess has not been found")
    
    code = []

    # PK: Original 32 bit code. 
    # code += [0x31, 0xc0] # xor eax, eax
    # code += [0x50] # push eax
    # code += [0xb8] # mov eax…
    
    # PK: The calling convention for 64-bit Windows is different. The first (and
    # only argument) to TerminateProcess(handle, code), i.e., that handle, has 
    # to be placed in RCX. The exit code goes into RDX. See
    #     https://docs.microsoft.com/de-de/cpp/build/x64-calling-convention?view=vs-2019
    # The address of TerminateProcess is 64 bits long and, hence, has to be put 
    # into RAX instead of EAX.
    # The -1 in RCX terminates the calling process.
    code += [0x48, 0x31, 0xc9] # xor rcx, rcx  a.k.a  load 0 into rcx
    code += [0x48, 0xff, 0xc9] # dec rcx
    
    if exit_code == 0:
        code += [0x48, 0x31, 0xd2] # xor rdx, rdx
    else:
        code += [0x48, 0xba] # mov rdx… (rest follows)    
        code += struct.pack("<Q", exit_code)

    code += [0x48, 0xb8] # mov rax… (rest follows)

    # PK: The original line is:
    #     code += list(map(ord, struct.pack("<I", address)))
    # Two things no longer work with that line. First, struct.pack nowadays (?) 
    # already returns a string and needs not be converted with list(map(ord, …)). 
    # Second, the address is a long long on my system, not an int. Therefore, 
    # "<Q" instead of "<I" needs to be used, see 
    #     https://docs.python.org/3/library/struct.html#format-characters

    try:
        code += struct.pack("<I", address)
    except struct.error:
        code += struct.pack("<Q", address)

    # This is indentical for call eax
    code += [0xff, 0xd0] # call rax

    logging.debug("  TerminateProcess at %#018x" % address)
    logging.debug("  Exit code is: %s\n" % (" ".join([format(x, '02x') for x in code])))

    return code

def asm_terminate_process_dynamic(exit_code=0):
    absolute_address = resolve_function_address('kernel32.dll', b'TerminateProcess')
    offset = absolute_address - ctypes.windll.kernel32._handle

    asm = ""

    # Related reads:
    #   https://www.felixcloutier.com/x86/rdfsbase:rdgsbase
    #   https://stackoverflow.com/questions/61217462/getting-the-actual-value-of-segment-register-in-masm
    #   https://nytrosecurity.com/2019/06/30/writing-shellcodes-for-windows-x64/
    #   https://www.tophertimzen.com/blog/windowsx64Shellcode/
    # Note: Above references mostly assume that register GS points to TEB; the stackoverflow 
    # reference is the only to mention (in the comments!) that RDGSBASE is required to obtain 
    # the base that GS refers to.
    # 
    # I tested the following successfully with mupdf. The result of RDGSBASE points 
    # directly to the TEB. The register GS had an offset 0x2b, which was irrelevant. 
    # That means RDGSBASE points to TEB, and RDGSBASE + GS points to a random (?) 
    # position inside TEB.
    #
    # To terminate the current process, the HANDLE value needs to be set accordingly.
    # This can be achieved best by calling GetCurrentProcess(), but I’m too lazy. According 
    # to the Microsoft docs, the value -1 should work:
    #   https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
    # 
    asm += 'rdgsbase rbx\n'          # RBX points to TEB
    asm += 'mov rbx, [rbx + 0x60]\n' # RBX points to PEB
    asm += 'mov rbx, [rbx + 0x18]\n' # RBX points to PEB_LDR_DATA
    asm += 'mov rbx, [rbx + 0x20]\n' # Get pointer to first entry in InMemoryOrderModuleList
    asm += 'mov rbx, [rbx]\n'        # Get pointer to second (ntdll.dll) entry in InMemoryOrderModuleList
    asm += 'mov rbx, [rbx]\n'        # Get pointer to third (kernel32.dll) entry in InMemoryOrderModuleList
    asm += 'mov rbx, [rbx + 0x20]\n' # Get kernel32.dll base address
    asm += 'add rbx, %#x\n' % offset # Add offset of TerminateProcess
    asm += 'xor rcx, rcx\n'          # Load -1 into rcx as first parameter to TerminateProcess
    asm += 'dec rcx\n'
    asm += 'mov rdx, %#0x\n' % exit_code # Load exit_code into rdx as second parameter to TerminateProcess
    asm += 'call rbx\n'

    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    encoding, count = ks.asm(asm)

    logging.debug("  TerminateProcess offset is: %#x" % offset)
    logging.debug("  Exit code is: %s\n" % (" ".join([format(x, '02x') for x in encoding])))

    return encoding

def asm_exit_process_dynamic(exit_code=0):
    absolute_address = resolve_function_address('kernel32.dll', b'ExitProcess')
    offset = absolute_address - ctypes.windll.kernel32._handle

    asm = ""

    # Related reads:
    #   https://www.felixcloutier.com/x86/rdfsbase:rdgsbase
    #   https://stackoverflow.com/questions/61217462/getting-the-actual-value-of-segment-register-in-masm
    #   https://nytrosecurity.com/2019/06/30/writing-shellcodes-for-windows-x64/
    #   https://www.tophertimzen.com/blog/windowsx64Shellcode/
    # Note: Above references mostly assume that register GS points to TEB; the stackoverflow 
    # reference is the only to mention (in the comments!) that RDGSBASE is required to obtain 
    # the base that GS refers to.
    # 
    # I tested the following successfully with mupdf. The result of RDGSBASE points 
    # directly to the TEB. The register GS had an offset 0x2b, which was irrelevant. 
    # That means RDGSBASE points to TEB, and RDGSBASE + GS points to a random (?) 
    # position inside TEB.
    #
    # To terminate the current process, the HANDLE value needs to be set accordingly.
    # This can be achieved best by calling GetCurrentProcess(), but I’m too lazy. According 
    # to the Microsoft docs, the value -1 should work:
    #   https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
    # 
    asm += 'rdgsbase rbx\n'          # RBX points to TEB
    asm += 'mov rbx, [rbx + 0x60]\n' # RBX points to PEB
    asm += 'mov rbx, [rbx + 0x18]\n' # RBX points to PEB_LDR_DATA
    asm += 'mov rbx, [rbx + 0x20]\n' # Get pointer to first entry in InMemoryOrderModuleList
    asm += 'mov rbx, [rbx]\n'        # Get pointer to second (ntdll.dll) entry in InMemoryOrderModuleList
    asm += 'mov rbx, [rbx]\n'        # Get pointer to third (kernel32.dll) entry in InMemoryOrderModuleList
    asm += 'mov rbx, [rbx + 0x20]\n' # Get kernel32.dll base address
    asm += 'add rbx, %#x\n' % offset # Add offset of ExitProcess
    asm += 'mov rcx, %#0x\n' % exit_code # Load exit_code into rdx as second parameter to ExitProcess
    asm += 'call rbx\n'

    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    encoding, count = ks.asm(asm)

    logging.debug("  ExitProcess offset is: %#x" % offset)
    logging.debug("  Exit code is: %s\n" % (" ".join([format(x, '02x') for x in encoding])))

    return encoding

def asm_terminate_process32(exit_code=0):
    # PK: Here it is necessary to pass 'TerminateProcess' as bytes, not as a 
    # unicode string. Otherwise, a type error is thrown by ctypes.
    #address = resolve_function_address('KERNEL32.dll', b'ExitProcess')
    address = resolve_function_address('KERNEL32.dll', b'ExitProcess')

    if not address:
        raise Exception("ExitProcess has not been found")
    
    code = []

    # PK: Original 32 bit code. 
    code += [0x31, 0xc0] # xor eax, eax
    code += [0x50] # push eax
    code += [0xb8] # mov eax…
    
    # PK: The calling convention for 64-bit Windows is different. The first (and
    # only argument) to TerminateProcess(handle, code), i.e., that handle, has 
    # to be placed in RCX. The exit code goes into RDX. See
    #     https://docs.microsoft.com/de-de/cpp/build/x64-calling-convention?view=vs-2019
    # The address of TerminateProcess is 64 bits long and, hence, has to be put 
    # into RAX instead of EAX.
    # The -1 in RCX terminates the calling process.
    # code += [0x48, 0x31, 0xc9] # xor rcx, rcx  a.k.a  load 0 into rcx
    # code += [0x48, 0xff, 0xc9] # dec rcx
    
    # if exit_code == 0:
    #     code += [0x48, 0x31, 0xd2] # xor rdx, rdx
    # else:
    #     code += [0x48, 0xba] # mov rdx… (rest follows)    
    #     code += struct.pack("<Q", exit_code)

    # code += [0x48, 0xb8] # mov rax… (rest follows)

    # PK: The original line is:
    #     code += list(map(ord, struct.pack("<I", address)))
    # Two things no longer work with that line. First, struct.pack nowadays (?) 
    # already returns a string and needs not be converted with list(map(ord, …)). 
    # Second, the address is a long long on my system, not an int. Therefore, 
    # "<Q" instead of "<I" needs to be used, see 
    #     https://docs.python.org/3/library/struct.html#format-characters

    try:
        code += struct.pack("<I", address)
    except struct.error:
        code += struct.pack("<Q", address)

    # This is indentical for call eax
    code += [0xff, 0xd0] # call rax

    logging.debug("  ExitProcess at %#018x" % address)
    logging.debug("  Exit code is: %s\n" % (" ".join([format(x, '02x') for x in code])))

    return code

def asm_terminate_process32_dynamic(exit_code=0):
    address = resolve_function_address('KERNEL32.dll', b'TerminateProcess')
    offset = 0x0001f4d0
    offset = address - ctypes.windll.kernel32._handle

    asm = ""

    #asm += 'xor ecx, ecx\n'
    #asm += 'dec ecx\n'
    #asm += 'xor edx, edx\n'
    asm += 'push %d\n' % exit_code
    asm += 'push -1\n'
    # From https://idafchev.github.io/exploit/2017/09/26/writing_windows_shellcode.html
    # I verified the code on Acrobat Reader in WinDbg
    asm += 'mov ebx, fs:0x30\n'      # Get pointer to PEB
    asm += 'mov ebx, [ebx + 0x0C]\n' # Get pointer to PEB_LDR_DATA
    asm += 'mov ebx, [ebx + 0x14]\n' # Get pointer to first entry in InMemoryOrderModuleList
    asm += 'mov ebx, [ebx]\n'        # Get pointer to second (ntdll.dll) entry in InMemoryOrderModuleList
    asm += 'mov ebx, [ebx]\n'        # Get pointer to third (kernel32.dll) entry in InMemoryOrderModuleList
    asm += 'mov ebx, [ebx + 0x10]\n' # Get kernel32.dll base address
    asm += 'add ebx, %#x\n' % offset   # Add offset of TerminateProcess

    asm += 'call ebx'

    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    encoding, count = ks.asm(asm)

    logging.debug("  Exit code is: %s\n" % (" ".join([format(x, '02x') for x in encoding])))

    return encoding

def asm_exit_process32_dynamic(exit_code=0):
    address = resolve_function_address('KERNEL32.dll', b'ExitProcess')
    offset = 0x0001f4d0
    offset = address - ctypes.windll.kernel32._handle

    asm = ""

    #asm += 'xor ecx, ecx\n'
    #asm += 'dec ecx\n'
    #asm += 'xor edx, edx\n'
    asm += 'push %d\n' % exit_code
    # From https://idafchev.github.io/exploit/2017/09/26/writing_windows_shellcode.html
    # I verified the code on Acrobat Reader in WinDbg
    asm += 'mov ebx, fs:0x30\n'      # Get pointer to PEB
    asm += 'mov ebx, [ebx + 0x0C]\n' # Get pointer to PEB_LDR_DATA
    asm += 'mov ebx, [ebx + 0x14]\n' # Get pointer to first entry in InMemoryOrderModuleList
    asm += 'mov ebx, [ebx]\n'        # Get pointer to second (ntdll.dll) entry in InMemoryOrderModuleList
    asm += 'mov ebx, [ebx]\n'        # Get pointer to third (kernel32.dll) entry in InMemoryOrderModuleList
    asm += 'mov ebx, [ebx + 0x10]\n' # Get kernel32.dll base address
    asm += 'add ebx, %#x\n' % offset   # Add offset of ExitProcess

    asm += 'call ebx'

    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    encoding, count = ks.asm(asm)

    logging.debug("  Exit code is: %s\n" % (" ".join([format(x, '02x') for x in encoding])))

    return encoding

def add_exitprocess_section(binary_path, new_binary_path, exit_code=0, bits=64, exit=exit):
    #code = asm_call_to_exitprocess()
    if bits == 64:
        if exit:
            code = asm_exit_process_dynamic(exit_code)
        else:
            code = asm_terminate_process_dynamic(exit_code) #asm_terminate_process(exit_code)
    elif bits == 32:
        if exit:
            code = asm_exit_process32_dynamic(exit_code)
        else:
            code = asm_terminate_process32_dynamic(exit_code)
    else:
        raise Exception('Bad bits: %s' % str(bits))

    binary = lief.parse(binary_path)
    binary.optional_header.dll_characteristics &= ~lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE

    added_section = lief.PE.Section(ADDED_SECTION_NAME)
    added_section.characteristics = lief.PE.SECTION_CHARACTERISTICS.CNT_CODE | lief.PE.SECTION_CHARACTERISTICS.MEM_READ | lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
    added_section.content = code
    binary.add_section(added_section)

    builder = lief.PE.Builder(binary)
    builder.build()
    builder.write(new_binary_path)

def edit_exitprocess_section(binary_path, new_binary_path):
    #code = asm_call_to_exitprocess()
    code = asm_terminate_process_dynamic()

    binary = lief.parse(binary_path)
    #binary.optional_header.dll_characteristics &= ~lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE

    added_section = binary.get_section(ADDED_SECTION_NAME)
    added_section.characteristics = lief.PE.SECTION_CHARACTERISTICS.CNT_CODE | lief.PE.SECTION_CHARACTERISTICS.MEM_READ | lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
    added_section.content = code
    #binary.add_section(added_section)

    builder = lief.PE.Builder(binary)
    builder.build()
    builder.write(new_binary_path)

def place_jump_to_exitprocess_section(binary_path, basic_block_address, new_binary_path):
    binary = lief.PE.parse(binary_path)
    
    added_section = binary.get_section(ADDED_SECTION_NAME)
    section_absolute_address = binary.optional_header.imagebase + added_section.virtual_address
    
    # Patch bb with jmp to exit shellcode
    # ks = Ks(KS_ARCH_X86, KS_MODE_32)
    # asm = ""
    # asm += "push " + hex(section_absolute_address)[:-1] + "\n"
    # asm += "ret\n"
    # encoding, count = ks.asm(asm)

    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    asm = ""
    asm += "mov rax, " + format(section_absolute_address, '#018x') + "\n"
    asm += "push rax\n"
    asm += "ret\n"

    encoding, count = ks.asm(asm)

    logging.info("Patching the last BB with a return to the new section (%d instructions, %d bytes)…\n%s" %
        (count, len(encoding), " ".join([format(x, '#04x') for x in encoding]))
    )

    binary.patch_address(basic_block_address, encoding)

    builder = lief.PE.Builder(binary)
    builder.build()
    builder.write(new_binary_path)

def patch_file(binary_path, basic_block_addresses, new_binary_path, exit_code=0, jump=None, bits=64, fastfail=True, bp=False, exit=False, address_type=lief.Binary.VA_TYPES.AUTO):

    if bits == 64:
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
    elif bits == 32:
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    else:
        raise Exception('Bad bits: %s' % str(bits))

    log = ""

    if fastfail:
        log += "[!] Using __fastfail! See https://docs.microsoft.com/en-us/cpp/intrinsics/fastfail?view=msvc-160\n"
        #shutil.copy(binary_path, new_binary_path)
        binary = lief.PE.parse(binary_path)
        for i, x in enumerate(basic_block_addresses):
            fastfail_asm = "int 0x29"
            fastfail_encoding, fastfail_count = ks.asm(fastfail_asm)
            log += "  Patched offset %#010x (RVA) in %s:\n" % (x, os.path.split(binary_path)[1])
            log += "    __fastfail asm: %s\n" % fastfail_asm
            log += "    __fastfail x64: %s\n" % (" ".join([format(x, '02x') for x in fastfail_encoding]))
            binary.patch_address(x, fastfail_encoding, lief.Binary.VA_TYPES.RVA)

    elif bp:
        log += "[!] Using breakpoint!\n"
        binary = lief.PE.parse(binary_path)
        for i, x in enumerate(basic_block_addresses):
            breakpoint_asm = "int3"
            breakpoint_encoding, breakpoint_count = ks.asm(breakpoint_asm)
            log += "  Patched offset %#010x (RVA) in %s:\n" % (x, os.path.split(binary_path)[1])
            log += "    breakpoint asm: %s\n" % breakpoint_asm
            log += "    breakpoint x64: %s\n" % (" ".join([format(x, '02x') for x in breakpoint_encoding]))
            binary.patch_address(x, breakpoint_encoding, lief.Binary.VA_TYPES.RVA)

    else:
        add_exitprocess_section(binary_path, new_binary_path, exit_code, bits=bits, exit=exit)
        binary = lief.PE.parse(new_binary_path)
        added_section = binary.get_section(ADDED_SECTION_NAME)
        section_absolute_address = binary.optional_header.imagebase + added_section.virtual_address
        
        if (jump == None and binary_path.endswith('.exe')) or jump == False:
            use_ret = True
            use_jmp = False
        else:
            use_ret = False
            use_jmp = True

        if not use_ret and not bits == 64:
            #raise Exception('Bad bits without ret: %s' % str(bits))
            pass

        assert(use_ret ^ use_jmp == True)

        log += ("Patching %d basic blocks with a " + ("return" if use_ret else "jump") + " to the new section\n") % (len(basic_block_addresses))
        log += "  New section absolute: %#018x\n" % section_absolute_address
        log += "  New section relative: %#018x\n" % added_section.virtual_address

        if use_ret:
            asm = ""

            if bits == 64:
                asm += "mov rax, " + format(section_absolute_address, '#018x') + "\n"
                asm += "push rax\n"
                asm += "ret\n"
            elif bits == 32:
                asm += "push " + hex(section_absolute_address) + "\n"
                asm += "ret\n"
            else:
                raise Exception('Bad bits: %s' % str(bits))

            ret_encoding, ret_count = ks.asm(asm)

            log += "  Encoded patch is:\n%s" % asm
            log += "  Encoded patch is: %s\n" % (" ".join([format(x, '02x') for x in ret_encoding]))

        log += "  Now patching blocks…\n"

        for i, x in enumerate(basic_block_addresses):
            if use_jmp:
                sec_of_x = binary.section_from_offset(x)
                sec_offset_of_x = x - sec_of_x.offset
                x_rva = sec_of_x.virtual_address + sec_offset_of_x
                asm_jmp = "jmp " + format(added_section.virtual_address - x, '#010x')
                jmp_encoding, jmp_count = ks.asm(asm_jmp)

                log += "  Patched offset %#010x in %s:\n" % (x, os.path.split(binary_path)[1])
                log += "    Jump: %s\n" % asm_jmp
                log += "    Jump encoding: %s\n" % (" ".join([format(x, '02x') for x in jmp_encoding]))

                encoding = jmp_encoding
            elif use_ret:
                log += "  Patched offset %#010x in %s:\n" % (x, os.path.split(binary_path)[1])

                encoding = ret_encoding

            binary.patch_address(x, encoding, lief.Binary.VA_TYPES.RVA)

    logging.debug(log)

    builder = lief.PE.Builder(binary)
    builder.build()
    builder.write(new_binary_path)
#data = binary.read(r'C:\fuzzing\data\terminator-foxit\2022-05-02_T_14-48-00-000000_FoxitReader.exe\candidates\20220502_144915\binary\1_5738aef02fb138ab\FoxitReader.exe', 0x018f4a5b)
def read(path, offset, size, vat=0):
    binary = lief.PE.parse(path)
    for i in range(0, size):
        d = binary.get_content_from_virtual_address(offset + i, 1, vat)
        print('%#x: %2x' % (offset + i, d[0]))
