**常见报错和解决**

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

