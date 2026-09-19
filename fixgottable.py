from ida_segment import get_segm_by_name,getseg
from idautils import XrefsTo,XrefsFrom
from ida_name import get_name,set_name,SN_FORCE

def extern_find():
    extern_seg = get_segm_by_name("extern")
    extern_start = extern_seg.start_ea
    extern_end = extern_seg.end_ea
    extern_addr = (extern_start,extern_end)
    return extern_addr

def traverse(start,end):
    total = (end - start) / 8 + 1
    total = int(total)
    for i in range(0,total):
        ea = start + i * 8
        name = get_name(ea)
        if name is not None:
            text_member = XrefsTo(ea,0)
            for txref in text_member:
                found = False
                got_member = XrefsFrom(txref.frm,0)
                for dxref in got_member:
                    seg = getseg(dxref.to)
                    if dxref.to < start and seg.perm == 6:
                        res = set_name(dxref.to,"_" + name,SN_FORCE)
                        print(f"rename {name} success.")
                        found = True
                        break   
                if found:
                    break
def main():
    extern_start,extern_end = extern_find()
    traverse(extern_start,extern_end)

if __name__=="__main__":
    main()
