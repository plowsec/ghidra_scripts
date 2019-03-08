# ghidra_scripts
On-going work to enhance Ghidra

# SynthetizeFnParams.java

Yet another constant propagation attempt :-)

Basically, the goal is to handle such code obfuscation:
```
local_a0 = local_d8;
local_d8[0] = 0x39f376e1;
local_7c = 0x39f376e1;
uVar3 = (ulong)(0xffffffff - (local_7c ^ 0xc60c891f)) + 0xf & 0xfffffffffffffff0;
local_98 = -uVar3;
lVar2 = -uVar3;
cVar1 = *(char *)((long)local_a0 + local_98);
```

Using the "Highlight Backward Slice Inst" from GHIDRA, we get the following:
```
0x101219, 1393, 4)(register, 0x30, 8) PTRSUB (register, 0x20, 8) , (const, 0xffffffffffffff28, 8)
0x101234, 83, 7)(unique, 0x1f50, 4) COPY (const, 0x39f376e1, 4)
0x10123d, 1222, 11)(stack, 0xffffffffffffff84, 4) INDIRECT (unique, 0x1f50, 4) , (const, 0x5e, 4)
0x101253, 114, 20)(register, 0x38, 4) INT_XOR (stack, 0xffffffffffffff84, 4) , (const, 0xc60c891f, 4)
0x101280, 152, 23)(register, 0x88, 4) INT_SUB (const, 0xffffffff, 4) , (register, 0x38, 4)
0x101283, 661, 24)(register, 0x8, 8) INT_ZEXT (register, 0x88, 4)
0x101286, 160, 25)(register, 0x8, 8) INT_ADD (register, 0x8, 8) , (const, 0xf, 8)
0x10128a, 165, 26)(register, 0x8, 8) INT_AND (register, 0x8, 8) , (const, 0xfffffffffffffff0, 8)
0x101291, 171, 27)(register, 0x10, 8) INT_2COMP (register, 0x8, 8)
0x101421, 1199, 95)(stack, 0xffffffffffffff60, 8) INDIRECT (register, 0x30, 8) , (const, 0x1dc, 4)
0x101421, 1205, 96)(stack, 0xffffffffffffff68, 8) INDIRECT (register, 0x10, 8) , (const, 0x1dc, 4)
0x101458, 1200, 139)(stack, 0xffffffffffffff60, 8) INDIRECT (stack, 0xffffffffffffff60, 8) , (const, 0x1f6, 4)
0x101458, 1206, 140)(stack, 0xffffffffffffff68, 8) INDIRECT (stack, 0xffffffffffffff68, 8) , (const, 0x1f6, 4)
0x101492, 1201, 183)(stack, 0xffffffffffffff60, 8) INDIRECT (stack, 0xffffffffffffff60, 8) , (const, 0x20e, 4)
0x101492, 1207, 184)(stack, 0xffffffffffffff68, 8) INDIRECT (stack, 0xffffffffffffff68, 8) , (const, 0x20e, 4)
0x1014c4, 1435, 214)(unique, 0x1000025a, 8) CAST (stack, 0xffffffffffffff60, 8)
0x1014c4, 546, 215)(unique, 0x10000262, 8) INT_ADD (unique, 0x1000025a, 8) , (stack, 0xffffffffffffff68, 8)
0x1014c4, 1436, 216)(unique, 0x680, 8) CAST (unique, 0x10000262, 8)
0x1014c4, 547, 217)(unique, 0x1f20, 1) LOAD (const, 0x131, 4) , (unique, 0x680, 8)
```

Running the script's current version allows to deobfuscate a little those computations:
```
SynthetizeFnParams.java> (stack, 0xffffffffffffff84, 4) has computed value 972256993
SynthetizeFnParams.java> (unique, 0x680, 8) has computed value 268436066
SynthetizeFnParams.java> (unique, 0x1f20, 1) has computed value 305
SynthetizeFnParams.java> (register, 0x38, 4) has computed value 4294967294
SynthetizeFnParams.java> (register, 0x88, 4) has computed value 1
SynthetizeFnParams.java> (stack, 0xffffffffffffff68, 8) has computed value -10
SynthetizeFnParams.java> Could not concretize value of storage location (register, 0x30, 8)
SynthetizeFnParams.java> (unique, 0x1000025a, 8) has computed value -160
SynthetizeFnParams.java> (register, 0x8, 8) has computed value 0
SynthetizeFnParams.java> (unique, 0x10000262, 8) has computed value -312
SynthetizeFnParams.java> (unique, 0x1f50, 4) has computed value 972256993
SynthetizeFnParams.java> Could not concretize value of storage location (stack, 0xffffffffffffff60, 8)
SynthetizeFnParams.java> (register, 0x10, 8) has computed value -10
SynthetizeFnParams.java> Finished!
```
