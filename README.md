# 常见报错和解决

1. 编译时，cmake/ninja（都是构建工具）如果输出中文可能会乱码。

   是因为gbk/gb2312和utf8的转换导致的，程序输出一个编码，终端(shell)展示又是一个编码。

   一般乱码都是错误时才出现。能忽略就忽略（直接复制不乱码的地方贴百度，不爽就找IDE哪里能改终端(terminal)编码。

2. 系统PATH环境变量里要有个qt的目录不然编译成功而跑不起来：...\Qt\version\toolchain\bin

   比如：D:\Qt\6.4.0\msvc2019_64\bin

   里面的版本和工具链无所谓，先写着先，跑不起来再统一。

   如果升级了Qt，比如从6.2.3->6.4.0，记得在以前的系统PATH里也更新那个目录，

   不然以前设的目录没用了，跑的时候找不到dll文件（IDE里一般是一串光秃秃的错误码

3. 如果找不到qt包就把

   set(CMAKE_PREFIX_PATH D:\Qt\6.4.0\msvc2019_64)

   添加到cmakelists.txt的find_package前

   或者找IDE里的cmake选项（意思是调cmake时用的命令行参数）加入

   -DCMAKE_PREFIX_PATH=D:\Qt\6.4.0\msvc2019_64

   注意用自己的qt路径（

4. qt界面程序和命令行不兼容，只有在qtcreator里可以命令行输出，所有ide都不能命令行输入。

   如果想用命令行先把cmakelists里有关qt的都注释了先。见cmakelists-cmd.txt。

5. qt mingw报错：unrecognized command line option '-Zc:__cplusplus' and unrecognized command line option '-permissive-'
   最容易解决的方式：qtcreator里创建一个项目，测试能不能跑起来，然后再用vscode试试能不能跑起来，如果都可以就把CMakeLists.txt.user复制过来（这是qtcreator里创建工程时创建来的）。这是重要信息。

6. 编译成功但是无法启动/运行就从windows的文件管理器打开，看看有没有报错（启动问题
   如果没有，则启动没问题，是运行时问题，开始debug

## 代码相关

如果觉得uint32_t/unsigned太丑了可以用qt的uint

头文件和cpp文件分不分离我认为无所谓
但是如果在头文件定义的话要加个inline：
inline void f() {}
不然会报错

函数先搜搜c++里有没有再自己实现（严格来说是标准库里有没有

有个注意事项：
用无符号整数是因为负数在这些情况下是没意义的。
不过循环递减时要注意一下坑：
for(uint_t i = 10; i >= 0; i--) / uint i = 10; while(i >= 0) {...; i--;}
是错误的写法，因为无符号不会出现i < 0的情况。0 - 1会循环到2^32 - 1。
正确的写法：
for(uint_t i = 11; i > 0; --i) / uint i = 11; while(i-- > 0) {...;}
这时候后置--的作用就体现出来了
坚持区间左闭右开一百年不动摇（

