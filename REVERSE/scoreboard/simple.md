**Scoreboard第39题，Reverse第二题**
>附件下载地址：https://hackme.inndy.tw/static/simple-rev

Step1:  
`file命令查看simple-rev，simple-rev: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=923390ca9bbe2a4ff25b70b07516e357cd6e013a, with debug_info, not stripped`

Step2:  
32位IDA查看main函数：
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char checking[64]; // [esp+Ch] [ebp-8Ch]
  char buffer[64]; // [esp+4Ch] [ebp-4Ch]
  int i; // [esp+8Ch] [ebp-Ch]

  printf("What is flag? ");
  fgets(buffer, 63, stdin);
  for ( i = 0; buffer[i]; ++i )
  {
    if ( buffer[i] == 10 )
    {
      buffer[i] = 0;
      checking[i] = 0;
    }
    else
    {
      checking[i] = buffer[i] + 1;
    }
  }
  if ( !strcmp(checking, "UIJT.JT.ZPVS.GMBH") )
    printf("FLAG{%s}\n", buffer);
  else
    puts("Try hard.");
  return 0;
}
```

Step3:
很明显flag是字符串`UIJT.JT.ZPVS.GMBH`每个字符的ASCII减1，python运算：
```
str1 = 'UIJT.JT.ZPVS.GMBH'
''.join(map(lambda x:chr(ord(x)-1),str1))
```
得到flag：THIS-IS-YOUR-FLAG
