from idautils import Functions,FuncItems
from ida_funcs import get_func_name
from datetime import datetime
from ida_segment import getseg,get_segm_name

def main():
    time_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"/tmp/IDA_funcs_scan-{time_str}.txt"

    f = open(filename,"w")
    text_count = 0
    plt_count = 0
    other_count = 0
    func_count = 0
    item_count = 0;

    for func_start in Functions():
        func_name = get_func_name(func_start)
        segment = getseg(func_start)
        seg_name = get_segm_name(segment)
        func_count = func_count + 1
        if seg_name == ".text":
            text_count = text_count + 1
        elif seg_name == ".plt" or seg_name == ".plt.sec":
            plt_count = plt_count + 1
        else:
            other_count = other_count + 1
        func_name = func_name + "\n"
        f.write(func_name)
        for i in FuncItems(func_start):
            item_count = item_count + 1
    f.close()
    print(f"The count of the functions:                              {func_count}")
    print(f"The count of the items:                                  {item_count}")
    print(f"The count of the functions from segment .text:           {text_count}")
    print(f"The count of the functions from segment .plt:            {plt_count}")
    print(f"The count of the functions from other segment:           {other_count}")

if __name__ == "__main__":
    main()
