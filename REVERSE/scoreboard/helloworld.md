Scoreboard第38题，Reverse大类第一题
附件下载地址：https://hackme.inndy.tw/static/helloworld

Step1:
`file命令查看，helloworld: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=7060d74084170ea3740c4ac90ae27516b426da73, with debug_info, not stripped
`

Step2:
```
32位IDA查看main函数代码：
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char flag[29]; // [esp+Bh] [ebp-2Dh]
  int n; // [esp+28h] [ebp-10h]
  int i; // [esp+2Ch] [ebp-Ch]

  *(_DWORD *)flag = -931010319;
  *(_DWORD *)&flag[4] = -825261614;
  *(_DWORD *)&flag[8] = -2118090283;
  *(_DWORD *)&flag[12] = -925515565;
  *(_DWORD *)&flag[16] = -843001906;
  *(_DWORD *)&flag[20] = -858468479;
  *(_DWORD *)&flag[24] = -1881946941;
  flag[28] = 0;
  printf("What is magic number? ");
  __isoc99_scanf("%d", &n);
  if ( n == 314159265 )
  {
    for ( i = 0; flag[i]; ++i )
      flag[i] ^= n;
    printf("Flag is FLAG{%s}\n", flag);
  }
  else
  {
    puts("Try Hard.");
  }
  return 0;
}
```

Step3:
很明显输入314159265即可得到flag: FLAG{PI is not a rational number.}
