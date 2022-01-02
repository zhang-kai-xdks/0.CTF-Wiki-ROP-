# 0.CTF-Wiki-ROP-
鸣谢Vancir,CTF Wiki.

01. Stack
 栈，FIFO，地址空间由高到低。  
 寄存器：ESP栈顶指针；EBP栈基指针。 
 ![image](https://user-images.githubusercontent.com/96966904/147868209-111ed65e-04a2-41fa-8af4-f2372b9e4cfe.png)  
 上图的EBP是caller，用于保存不需调用的临时数据；下面的EBP是callee，用于保存在调用中保留的值。  

02. Stack overflow(X86)  
 栈溢出，即向栈中变量写入的字，其字节数超出了该变量申请的字节数（例如：该变量总共申请2字节空间，非要往里面存32位int型数据）。  
 gets()函数不检查输入字符串的长度，而是以回车来判断输入是否结束，所以很容易导致栈溢出（例如：莫里斯蠕虫）  
 //PIE和ASLR机制留待学习补充，本页不考虑其存在。   
 代码段：  
   #include <stdio.h>  
   #include <string.h>  
   void success() { puts("You Hava already controlled it."); }  
   void vulnerable() {  
     char s[12];  
     gets(s);  
     puts(s);  
     return;  
   }  
   int main(int argc, char **argv) {  
     vulnerable();  
     return 0;  
   }  
     
 编译：
   ➜  stack-example gcc -m32 -fno-stack-protector stack_example.c -o stack_example   
  stack_example.c: In function ‘vulnerable’:  
  stack_example.c:6:3: warning: implicit declaration of function ‘gets’ [-Wimplicit-function-declaration]  
     gets(s);  
     ^  
  /tmp/ccPU8rRA.o：在函数‘vulnerable’中：  
  stack_example.c:(.text+0x27): 警告： the `gets' function is dangerous and should not be used.  
  注意警告！  
    
  常见的危险函数：  
  输入：gets(),scanf(),vscanf,  
  输出：sprintf()  
  字符串：strcpy(),strcat(),bcopy  
    
  确定填充长度：目的计算我们要操作的地址与我们要覆盖的地址的距离，通过覆盖地址实现对程序的直接或间接控制。
