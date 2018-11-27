**Scoreboard第40题，Reverse第三题**
>附件下载地址：https://hackme.inndy.tw/static/passthis

Step1:  
file命令查看：passthis.exe: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows

Step2:
32位IDA查看main函数：
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // eax
  int v4; // edx
  signed int v5; // ecx
  unsigned int v6; // eax
  signed int v8; // edx
  BOOL v9; // [esp-1Ch] [ebp-424h]
  char v10[1024]; // [esp+0h] [ebp-408h]
  int *v11; // [esp+400h] [ebp-8h]

  v11 = &argc;
  sub_4016D0();
  v3 = fopen((const char *)lpFileName, "rb");
  if ( v3 )
  {
    fclose(v3);
    dword_40501C = 1;
  }
  else if ( URLDownloadToFileA(0, off_403008, (LPCSTR)lpFileName, 0, 0) )
  {
    dword_40501C = 0;
  }
  else
  {
    dword_40501C = 1;
    v9 = SetFileAttributesA((LPCSTR)lpFileName, 6u);
  }
  printf("Let me check your flag: ", v9);
  fgets(v10, 1023, (FILE *)iob[0]._ptr);
  if ( v10[0] > 0xDu )
  {
    if ( v10[0] == 70 )
    {
      v4 = 0;
      v5 = 9217;
      do
      {
        v6 = (unsigned __int8)v10[++v4];
        if ( (unsigned __int8)v6 <= 0xDu )
        {
          if ( _bittest(&v5, v6) )
            goto LABEL_9;
        }
      }
      while ( ((unsigned __int8)byte_404040[v4] ^ (unsigned __int8)v6) == -121 );
    }
LABEL_12:
    puts("Not the flag!");
    SystemParametersInfoA(0x14u, 0, lpFileName, 1u);
    return 0;
  }
  v8 = 9217;
  if ( !_bittest(&v8, (unsigned __int8)v10[0]) )
    goto LABEL_12;
LABEL_9:
  puts("Good flag ;)");
  return 0;
}
```

关键函数在第40行到第55行，byte_404040开始的0xD个字符为：  
['0xc1', '0xcb', '0xc6', '0xc0', '0xfc', '0xc9', '0xe8', '0xab', '0xa7', '0xde', '0xe8', '0xf2', '0xa7']  
使等式`((unsigned __int8)byte_404040[v4] ^ (unsigned __int8)v6) == -121`一直成立（-121即是135）
等到v6小于0xd时结束，v4是+1增长，可
