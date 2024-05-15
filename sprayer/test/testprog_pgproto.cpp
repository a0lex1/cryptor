// only proto; real pg stuff is in pg/
//testprog_pgproto.cpp
//@@@headers
#include <cstdio>
#include <windows.h>
//@@@endheaders
#include "spraygen.h"

//@@@privdefs
#define MAINPROC_DECL() int main()
#define MAINPROC_PRE() XARGSETUP()
#define MAINPROC_POST()XARGCLEANUP(); return 770
#define g1_DECL() DWORD WINAPI g1(LPVOID lpParam)
#define g1_PRE() XARGSETUP(); CUR_A1 = lpParam
#define g1_POST() XARGCLEANUP(); return 101990
#define ASSERT(e) { if (!(e)) { printf("--------- Check failed - %s\n", #e);  *(int*)0 = 1; } }
#define t1data() ((T1_DATA*)CUR_A1)
#define t2data() ((T2_DATA*)CUR_A1)

//@@@endprivdefs

_STRUCT(T1_DATA) {
//@@@structfields /name T1_DATA
  int thread_index;
  int apple;
  int banana;
//@@@endstructfields
};

_STRUCT(T2_DATA) {
  //@@@structfields /name T2_DATA
  int thread_index;
  const char* some_string;
  float some_float;
  //@@@endstructfields
};

//@@@zvars
T1_DATA t1data;
T2_DATA t2data;
DWORD tid1, tid2;
HANDLE hThread1, hThread2;
BOOL exit_loop;
//@@@endzvars


// ------------ T1 ---------------------------------------

SPRAYABLE_PROC(g1_t1_iter_act1) {
  //@@@proc /name g1_t1_iter_act1
  t1data()->apple = 3;
  t1data()->banana = 4;
  printf("g1_t1_iter_act1: apple:%d,banana:%d\n", t1data()->apple, t1data()->banana);
  //@@@endproc
}

SPRAYABLE_PROC(g1_t1_iter_act2) {
  //@@@proc /name g1_t1_iter_act2
  SleepEx(100, FALSE);
  //@@@endproc
}

SPRAYABLE_PROC(g1_t1_iter) {
  //@@@proc /name g1_t1_iter
  CHILD_A1 = CUR_A1; // for all following calls
  _CALL(g1_t1_iter_act1);
  _CALL(g1_t1_iter_act2);
  //@@@endproc
}

SPRAYABLE_PROC(g1_t1_init_act1) {
  //@@@proc /name g1_t1_init_act1
  t1data()->apple = 13;
  //@@@endproc
}

SPRAYABLE_PROC(g1_t1_init_act2) {
  //@@@proc /name g1_t1_init_act2
  t1data()->banana = 270;
  //@@@endproc
}

SPRAYABLE_PROC(g1_t1) {
  //@@@proc /name g1_t1

  CHILD_A1 = CUR_A1;
  _CALL(g1_t1_init_act1);
  _CALL(g1_t1_init_act2);
  
  CHILD_A1 = CUR_A1;
  while (!Z(exit_loop)) { _CALL(g1_t1_iter); }

  for (int i=0; i<10; i++) { Sleep(30); }
  
  //@@@endproc
}

// ------------ T2 ---------------------------------------

SPRAYABLE_PROC(g1_t2) {
  //@@@proc /name g1_t2
  printf("g1_t2: sleeplooping\n");
  for (int i=0; i<10; i++) { Sleep(50); }
  printf("g1_t2: done sleeplooping\n");
  //@@@endproc
}

// ---------------------------------------------------

g1_DECL() {
  g1_PRE();
  //@@@proc /decl g1
  CHILD_A1 = CUR_A1;
  if (*((int*)CUR_A1) == 1) { _CALL(g1_t1); }
  if (*((int*)CUR_A1) == 2) { _CALL(g1_t2); }
  //@@@endproc
  g1_POST();
}


MAINPROC_DECL() {
  MAINPROC_PRE();
  //@@@proc /decl MAINPROC /root yes

  Z(t1data.thread_index) = 1;
  Z(t2data.thread_index) = 2;
  
  Z(hThread1) = CreateThread(0, 0, g1, &Z(t1data), 0, &Z(tid1));
  Z(hThread2) = CreateThread(0, 0, g1, &Z(t2data), 0, &Z(tid2));
  WaitForSingleObject(Z(hThread1), INFINITE);
  WaitForSingleObject(Z(hThread2), INFINITE);

  //@@@endproc
  MAINPROC_POST();
}




