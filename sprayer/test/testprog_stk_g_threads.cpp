//@@@headers
#include <cstdio>
#include <windows.h>
//@@@endheaders
#include "spraygen.h"

//@@@privdefs
#define MAINPROC_DECL() int main()
#define MAINPROC_PRE() flag1 = 1; XARGSETUP()
#define MAINPROC_POST() ASSERT(flag1 == 1); XARGCLEANUP(); return 770
#define ThreadProc_DECL() DWORD WINAPI ThreadProc(LPVOID lpParam)
#define ThreadProc_PRE() XARGSETUP(); CUR_A1 = lpParam
#define ThreadProc_POST() XARGCLEANUP(); return 101990
#define ASSERT(e) { if (!(e)) { printf("--------- Check failed - %s\n", #e);  *(int*)0 = 1; } }
//@@@endprivdefs

//@@@staticvars
int flag1 = 0;
int flag2 = 0;
int g_tmp = 0;

//@@@endstaticvars


//@@@zvars
unsigned my_cur_sum;
DWORD tid;
HANDLE hThread;
DWORD dwWait;
//@@@endzvars


SPRAYABLE_PROC(sum2) {
  //@@@proc /name sum2
  CUR_RETD = CUR_A1D + CUR_A2D;
  //@@@endproc
}

SPRAYABLE_PROC(sum3) {
  //@@@proc /name sum3
  CHILD_A1D = CUR_A2D;
  CHILD_A2D = CUR_A3D;
  _CALL(sum2);
  CUR_RETD = CHILD_RETD + CUR_A1D;
  //@@@endproc
}

ThreadProc_DECL() {
  ThreadProc_PRE();
  //@@@proc /decl ThreadProc
  printf("[ Hi from ThreadProc ]\n");
  for (int i=0; i<10; i++) { Sleep(10); }
  //@@@endproc
  ThreadProc_POST();
}


MAINPROC_DECL() {
  MAINPROC_PRE();
  //@@@proc /decl MAINPROC /root yes
  printf("hi2\n");
  flag2 = 1;

  Z(my_cur_sum) = 123456789;
  g_tmp = Z(my_cur_sum);
  Z(my_cur_sum) = g_tmp;
  ASSERT(Z(my_cur_sum) == 123456789);


  CHILD_A1D = 7;
  CHILD_A2D = 3;
  CHILD_A3D = 5;
  _CALL(sum3);
  ASSERT(CHILD_RETD == 15);
  
  
  printf("Creating thread...\n");
  Z(hThread) = CreateThread(0, 0, ThreadProc, 0, 0, &Z(tid));
  
  printf("Thread created, waiting...\n");

  Z(dwWait) = WaitForSingleObject(Z(hThread), INFINITE);
  ASSERT(Z(dwWait) == WAIT_OBJECT_0);

  printf("Wait done.\n");

  //@@@endproc
  MAINPROC_POST();
}

