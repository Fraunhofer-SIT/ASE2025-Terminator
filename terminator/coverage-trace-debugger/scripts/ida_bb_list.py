from idautils import Segments, Functions
import idaapi
import idc
import ida_kernwin
import ida_pro
import sys

def obtain_bb_list(output_file_path, log = print):
    output_file2_path = output_file_path + '.txt'

    log("[*] Output to %s\n" % output_file_path)
    nb_blocks = 0

    base = idaapi.get_imagebase()
    log("[*] Image base is at %#010x\n" % base)

    # Wait for the automatic analysis. This is necessary, because it produces the 
    # flow chart, from which we derive the list of basic blocks.
    #idc.auto_wait()

    with open(output_file_path, 'wb') as f, \
        open(output_file2_path, 'w') as f2:
        # The outermost loop can probably be removed
        for seg_ea in Segments():
            seg_end_ea = idc.get_segm_end(seg_ea)
            for func_ea in Functions(seg_ea, seg_end_ea):
                func = idaapi.get_func(func_ea)
                funcName = idaapi.get_func_name(func_ea)

                # This was somewhat difficult to search for. The documentation is at 
                #     https://hex-rays.com/products/ida/support/idapython_docs/ida_gdl.html#ida_gdl.FlowChart
                flowchart = idaapi.FlowChart(func)

                for bb in flowchart:
                    nb_blocks += 1

                    # Each basic block bb is a BasicBlock instance, see
                    #     https://hex-rays.com/products/ida/support/idapython_docs/ida_gdl.html#ida_gdl.BasicBlock
                    # Properties:
                    #   end_ea, id, start_ea, type
                    # The type property is documented at 
                    #     https://hex-rays.com/products/ida/support/sdkdoc/gdl_8hpp.html#afa6fb2b53981d849d63273abbb1624bd
                    # The possible values are:
                    #     0 fcb_normal  normal block
                    #     1 fcb_indjump block ends with indirect jump
                    #     2 fcb_ret     return block
                    #     3 fcb_cndret  conditional return block
                    #     4 fcb_noret   noreturn block
                    #     5 fcb_enoret  external noreturn block (does not belong to the function)
                    #     6 fcb_extern  external normal block
                    #     7 fcb_error   block passes execution past the function end

                    first_byte = idaapi.get_byte(bb.start_ea)
                    if not first_byte:
                        log("[-] Failure to receive byte at basic block %#010x in function %s" % (bb.start_ea, funcName))
                        continue

                    offset = bb.start_ea - base
                    file_offset = idaapi.get_fileregion_offset(bb.start_ea)
                    seg_offset = bb.start_ea - seg_ea
                    size = bb.end_ea - bb.start_ea

                    f.write(bb.start_ea.to_bytes(8, byteorder=sys.byteorder, signed=False))
                    f.write(offset.to_bytes(8, byteorder=sys.byteorder, signed=False))
                    f.write(file_offset.to_bytes(8, byteorder=sys.byteorder, signed=False))
                    f.write(size.to_bytes(8, byteorder=sys.byteorder, signed=False))
                    f.write(bytes([first_byte]))
                    
                    f2.write('%d %010x %010x %010x %d %02x\n' % (nb_blocks, bb.start_ea, offset, file_offset, size, first_byte))

    log("[*] Found %d basic blocks." % nb_blocks)

