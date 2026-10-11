一些自写自用的常用的脚本或工具

gdbserver:
    aarch64-gdbserver-12.1 ---aarch64架构下静态编译的gdbserver,服务于qemu虚拟机与远程调试
    mips64el-gdbserver-12.1 ---mips架构下静态编译的gdbserver,同上
    x86_64-gdbserver-12.1 ---x86_64架构下静态编译的gdbserver,同上

libseekstr:
    字符串查找工具，给定一个ELF文件的依赖库目录，可以交互式查询该目录下使用的字符串，可用于匹配函数名/敏感字符，确定符号由哪个字符导出

ext4fstran:
    传输工具，可以在宿主机和根目录ext4文件之间传输文件

fixgottable.py:
    IDA脚本，用于aarch64架构下plt桩被直接嵌入text时的函数名快速复原

func_item_stat.py:
    IDA脚本，快速审计程序信息并输出md文本，同时可以手动修改脚本查询危险API的交叉引用
