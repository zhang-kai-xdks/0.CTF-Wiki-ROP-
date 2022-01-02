# 0.CTF-Wiki-ROP-
鸣谢Vancir,CTF Wiki.
 Stack overflow(X86)
 栈，FIFO，地址空间由高到低。
 寄存器：ESP栈顶指针；EBP栈基指针。
 
 ![image](https://user-images.githubusercontent.com/96966904/147868209-111ed65e-04a2-41fa-8af4-f2372b9e4cfe.png)
上图的EBP是caller，用于保存不需调用的临时数据；下面的EBP是callee，用于保存在调用中保留的值。
