from idautils import Functions,FuncItems,CodeRefsTo
from ida_funcs import get_func_name,get_func
from datetime import datetime
from ida_segment import getseg,get_segm_name

class unsafe_api:
    def __init__(self,func_start):
        self.func_start = func_start
    def find_use_unsafe_api(self):
        self.used_by = CodeRefsTo(self.func_start,0)
        self.names_of_used_by = []
        for self.used_by_ea in self.used_by:
            self.names_of_used_by.append(get_func_name(self.used_by_ea))
        return self.names_of_used_by

class unsafe_func:
    def __init__(self,name):
        self.all_unsafe_api = []
        self.name = name
    def register_api(self,unsafe_api):
        if unsafe_api not in self.all_unsafe_api:
            self.all_unsafe_api.append(unsafe_api)
def main():
    time_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"~/Desktop/IDA_funcs_scan-{time_str}.md"

    text_count = 0
    plt_count = 0
    other_count = 0
    func_count = 0
    item_count = 0;
    plt_func_box = []
    text_func_box = []
    other_func_box = []
    unsafe_api_sample_box = ["strcpy","system","exec","printf","gets","strcat","scanf","memcpy"]
    unsafe_api_box = []
    unsafe_func_map = {}

    for func_start in Functions():
        func_name = get_func_name(func_start)
        segment = getseg(func_start)
        seg_name = get_segm_name(segment)
        func_count = func_count + 1
        func = get_func(func_start)
        func_size = func.end_ea - func.start_ea

        if seg_name == ".text":
            text_count = text_count + 1
            text_func_box.append((func_name,func_start,func_size))
        elif seg_name == ".plt" or seg_name == ".plt.sec":
            plt_count = plt_count + 1
            plt_func_box.append((func_name,func_start,func_size))
            if func_name in unsafe_api_sample_box:
                unsafe_api_box.append(unsafe_api(func_start))
        else:
            other_count = other_count + 1
            other_func_box.append((func_name,func_start,func_size,seg_name))

        for i in FuncItems(func_start):
            item_count = item_count + 1

    for api in unsafe_api_box:
        for caller_name in api.find_use_unsafe_api():
            if caller_name is None:
                continue
            if caller_name not in unsafe_func_map:
                unsafe_func_map[caller_name] = unsafe_func(caller_name)
            unsafe_func_map[caller_name].register_api(api)
            
    f = open(filename,"w")
    f.write("#PLT/PLT.SEC\n")
    f.write("| name | VA | size |\n")
    f.write("| --- | --- | --- |\n")
    for plt_func,plt_VA,size in plt_func_box:
        f.write("| " + plt_func +" | "+ str(hex(plt_VA)) + " | " + str(hex(size)) + " |\n")
    f.write("\n")
    f.write("#TEXT\n")
    f.write("| name | VA | size |\n")
    f.write("| --- | --- | --- |\n")
    for text_func,text_VA,size in text_func_box:
        f.write("| " + text_func + " | " + str(hex(text_VA)) + " | " + str(hex(size)) + " |\n")
    f.write("\n")
    f.write("#OTHER\n")
    f.write("| name | VA | size | segment\n") 
    f.write("| --- | --- | --- | --- |\n")
    for other_func,other_VA,size,other_seg_name in other_func_box:
        f.write("| " + other_func + " | " + str(hex(other_VA)) + " | " + str(hex(size)) + " | " + other_seg_name + " |\n")
    f.write("\n")
    f.write("#UNSAFE API USAGE\n")
    f.write("| caller | unsafe apis |\n")
    f.write("| --- | --- |\n")
    for uf in unsafe_func_map.values():
        apis = []
        for a in uf.all_unsafe_api:
            apis.append(hex(a.func_start))
        apis_str = ", ".join(apis)
        f.write("| " + uf.name + " | " + apis_str + " |\n") 
    f.close()
    print(f"The count of the functions:                              {func_count}")
    print(f"The count of the items:                                  {item_count}")
    print(f"The count of the functions from segment .text:           {text_count}")
    print(f"The count of the functions from segment .plt:            {plt_count}")
    print(f"The count of the functions from other segment:           {other_count}")

if __name__ == "__main__":
    main()
