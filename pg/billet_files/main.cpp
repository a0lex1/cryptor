/*
testprog_pgproto.cpp: only proto; real pg stuff is in pg

         (  )
         t 

  (g1)   (g2)  (  )
  t1     t4     t5

(  )(  )     (g1) (g2)
t2   t3       t6   t7

*/
//@@@headers
#include "pg/act_cocrel.h"
#include "pg/act_loadlib.h"
#include "run_all_acts.h"
#include <cstdio>
#include <windows.h>
//@@@endheaders

//@@@privdefs
#define DEF_THRET 101990
#define ProgramEntry_DECL() int main() // g0 t0
#define ProgramEntry_PRE() XARGSETUP()
#define ProgramEntry_POST() XARGCLEANUP(); return 770
#define DEF_THREAD_PRE() XARGSETUP(); CUR_A1 = lpParam; printf(__FUNCTION__": enter\n")
#define DEF_THREAD_POST(retcode) printf(__FUNCTION__": leave\n"); XARGCLEANUP(); return retcode
#define g1_DECL() DWORD WINAPI g1(LPVOID lpParam)
#define g1_PRE() DEF_THREAD_PRE()
#define g1_POST() DEF_THREAD_POST(DEF_THRET)
#define g2_DECL() DWORD WINAPI g2(LPVOID lpParam)
#define g2_PRE() DEF_THREAD_PRE()
#define g2_POST() DEF_THREAD_POST(DEF_THRET)
#define t3_DECL() DWORD WINAPI t3(LPVOID lpParam)
#define t3_PRE() DEF_THREAD_PRE()
#define t3_POST() DEF_THREAD_POST(DEF_THRET)
#define t4_DECL() DWORD WINAPI t4(LPVOID lpParam)
#define t4_PRE() DEF_THREAD_PRE()
#define t4_POST() DEF_THREAD_POST(DEF_THRET)
#define t5_DECL() DWORD WINAPI t5(LPVOID lpParam)
#define t5_PRE() DEF_THREAD_PRE()
#define t5_POST() DEF_THREAD_POST(DEF_THRET)

#define TIMEFIX(T) T//(T/3)
#define USERCODE_COUNT 3
#define T0_NUM_ACTS 3 // ProgramEntry's acts
#define T1_NUM_ACTS 3
#define T2_NUM_ACTS 3
#define T3_NUM_ACTS 3
#define T4_NUM_ACTS 3
#define T5_NUM_ACTS 3
#define T6_NUM_ACTS 3
#define T7_NUM_ACTS 3
#define T0_ACT0_TOFS TIMEFIX(100) // t0 creates t1
#define T0_ACT1_TOFS TIMEFIX(200) // t0 creates t2
#define T0_ACT2_TOFS TIMEFIX(300) // t0 creates t3
#define T2_ACT0_TOFS TIMEFIX(653) 
#define T2_ACT1_TOFS TIMEFIX(844)
#define T1_ACT0_TOFS TIMEFIX(400) // t1 creates t4
#define T1_ACT1_TOFS TIMEFIX(500) // t1 creates t5
#define T1_ACT2_TOFS TIMEFIX(500)
#define T3_ACT0_TOFS TIMEFIX(600) // t3 creates t6
#define T3_ACT1_TOFS TIMEFIX(700) // t3 creates t7
#define T4_ACT0_TOFS TIMEFIX(700)
#define T4_ACT1_TOFS TIMEFIX(753)
#define T5_ACT0_TOFS TIMEFIX(800) // need_exit = TRUE
#define T5_ACT1_TOFS TIMEFIX(600)
#define T7_ACT0_TOFS TIMEFIX(900)

#define __TICK (((DWORD*)0x7ffe0000)[2])
#define ELAPSED(ms) (TICKMS - Z(tick_start) >= ms)
#define THREAD_INDEX(P) (*((int*)P))
#define TICKMS (__TICK/10000)
#define t1data() ((T1_DATA*)CUR_A1)
#define t2data() ((T2_DATA*)CUR_A1)



#define USERCODE1() {_CALL(userproc1); CHILD_RETD = 1;}
#define USERCODE2() {_CALL(userproc2); CHILD_RETD = 1;}
#define USERCODE3() {_CALL(userproc3); CHILD_RETD = 1;}

#define ASSERT(e) { if (!(e)) { printf("--------- Check failed - %s\n", #e);  *(int*)0 = 1; } }
//@@@endprivdefs

// forwards
g1_DECL();
g2_DECL();

_STRUCT(T0_DATA) {
  //@@@structfields /name T0_DATA
  int thread_index;
  BYTE act_called_flags[T0_NUM_ACTS];
  //@@@endstructfields
};
_STRUCT(T1_DATA) {
  //@@@structfields /name T1_DATA
  int thread_index;
  BYTE act_called_flags[T1_NUM_ACTS];
  //@@@endstructfields
};
_STRUCT(T2_DATA) {
  //@@@structfields /name T2_DATA
  int thread_index;
  BYTE act_called_flags[T2_NUM_ACTS];
  ACTVARS_cocrel a1_cocrel_vars; // `a{actnum}_{actname}_vars`
  //@@@endstructfields
};
_STRUCT(T3_DATA) {
  //@@@structfields /name T3_DATA
  int thread_index;
  BYTE act_called_flags[T3_NUM_ACTS];
  //@@@endstructfields
};
_STRUCT(T4_DATA) {
  //@@@structfields /name T4_DATA
  int thread_index;
  BYTE act_called_flags[T4_NUM_ACTS];
  //@@@endstructfields
};
_STRUCT(T5_DATA) {
  //@@@structfields /name T5_DATA
  int thread_index;
  BYTE act_called_flags[T5_NUM_ACTS];
  //@@@endstructfields
};
_STRUCT(T6_DATA) {
  //@@@structfields /name T6_DATA
  int thread_index;
  BYTE act_called_flags[T6_NUM_ACTS];
  //@@@endstructfields
};
_STRUCT(T7_DATA) {
  //@@@structfields /name T7_DATA
  int thread_index;
  BYTE act_called_flags[T7_NUM_ACTS];
  //@@@endstructfields
};
//@@@zvars
DWORD tick_start;
BOOL need_exit;
T0_DATA t0data;
T1_DATA t1data;
T2_DATA t2data;
T3_DATA t3data;
T4_DATA t4data;
T5_DATA t5data;
T6_DATA t6data;
T7_DATA t7data;
DWORD tid;
HANDLE hThread1, hThread2, hThread3, hThread4, hThread5, hThread6, hThread7;

DWORD cur_usercode_idx;

HANDLE t1_hWakerEvents[10];
//@@@endzvars


static SPRAYABLE_PROC(userproc1) {
  //@@@proc /name userproc1
  printf("########## userproc1 called!\n"); Beep(300, 300);
  //@@@endproc
}
static SPRAYABLE_PROC(userproc2) {
  //@@@proc /name userproc2
  printf("!!!!!!!!!! userproc2 called!\n"); Beep(600, 300);
  //@@@endproc
}
static SPRAYABLE_PROC(userproc3) {
  //@@@proc /name userproc3
  printf("@@@@@@@@@@ userproc3 called! OK, ALL USERPROCS CALLED!\n"); Beep(800, 300);
  //@@@endproc
}

// t6 -------------------------------------------------------
static SPRAYABLE_PROC(t6_iter) {
  //@@@proc /name t6_iter
  Sleep(61);
  //@@@endproc
}
static SPRAYABLE_PROC(t6) {
  //@@@proc /name t6
  CHILD_A1 = CUR_A1;
  while (!Z(need_exit)) { _CALL(t6_iter); }
  //@@@endproc
}

// t7 -------------------------------------------------------
static SPRAYABLE_PROC(t7_iter) {
  //@@@proc /name t7_iter
  Sleep(61);
  if (ELAPSED(T7_ACT0_TOFS) && Z(cur_usercode_idx) == 3) { USERCODE3(); Z(need_exit) = TRUE; }

  //@@@endproc
}
static SPRAYABLE_PROC(t7) {
  //@@@proc /name t7
  CHILD_A1 = CUR_A1;
  while (!Z(need_exit)) { _CALL(t7_iter); }
  //@@@endproc
}


// t5 -------------------------------------------------------

static SPRAYABLE_PROC(t5_act0) {
  //@@@proc /name t5_act0
  //printf(__FUNCTION__"(): Yeah, setting need_exit!\n"); // now after userproc(s)
  //Z(need_exit) = TRUE;
  printf("lol, I am once executed action t5_act0\n");
  //@@@endproc
}

static SPRAYABLE_PROC(t5_iter) {
  //@@@proc /name t5_iter
  Sleep(61);
  if (ELAPSED(T5_ACT0_TOFS) && !Z(t5data).act_called_flags[0]) { _CALL(t5_act0); }
  if (ELAPSED(T5_ACT1_TOFS)) { SetEvent(Z(t1_hWakerEvents[0])); }
  //@@@endproc
}
static t5_DECL() {
  t5_PRE();
  //@@@proc /decl t5
  CHILD_A1 = CUR_A1;
  while (!Z(need_exit)) { _CALL(t5_iter); }
  //@@@endproc
  t5_POST();
}

// t4 -------------------------------------------------------

static SPRAYABLE_PROC(t4_iter) {
  //@@@proc /name t4_iter
  Sleep(50);
  if (ELAPSED(T4_ACT0_TOFS)) { SetEvent(Z(t1_hWakerEvents[0])); }
  if (ELAPSED(T4_ACT1_TOFS) && Z(cur_usercode_idx) == 1) { USERCODE1(); Z(cur_usercode_idx)++; }
  //@@@endproc
}

static t4_DECL() {
  t4_PRE();
  //@@@proc /decl t4
  CHILD_A1 = CUR_A1;
  while (!Z(need_exit)) { _CALL(t4_iter); }
  //@@@endproc
  t4_POST();
}


// t3 ------------------------------------------------------- creates t6, t7 (they reuse g1, g2)

static SPRAYABLE_PROC(t3_iter) {
  //@@@proc /name t3_iter
  Sleep(50);
  // init - thread indices
  Z(t6data).thread_index = 6;
  Z(t7data).thread_index = 7;
  if (ELAPSED(T3_ACT0_TOFS) && !Z(t3data).act_called_flags[0]) { Z(hThread6) = CreateThread(0, 0, g1, &Z(t6data), 0, &Z(tid)); Z(t3data).act_called_flags[0] = TRUE; }
  if (ELAPSED(T3_ACT1_TOFS) && !Z(t3data).act_called_flags[1]) { Z(hThread7) = CreateThread(0, 0, g2, &Z(t7data), 0, &Z(tid)); Z(t3data).act_called_flags[1] = TRUE; }
  //@@@endproc
}

static t3_DECL() {
  t3_PRE();
  //@@@proc /decl t3
  CHILD_A1 = CUR_A1;
  while (!Z(need_exit)) { _CALL(t3_iter); }
  //@@@endproc
  t3_POST();
}


// t2 ------------------------------------------------------- no children

static SPRAYABLE_PROC(t2_iter) {
  //@@@proc /name t2_iter
  Sleep(50);
  if (ELAPSED(T2_ACT0_TOFS) && Z(cur_usercode_idx) == 2) { USERCODE2(); Z(cur_usercode_idx)++; }
  if (ELAPSED(T2_ACT1_TOFS)) { CHILD_A1 = &Z(t2data.a1_cocrel_vars);  _CALL(A_runonce_cocrel); }
  //@@@endproc
}

static SPRAYABLE_PROC(t2) {
  //@@@proc /name t2
  // init - acts
  CHILD_A1 = &Z(t2data.a1_cocrel_vars);
  _CALL(A_init_cocrel);
  // run - loop
  CHILD_A1 = CUR_A1;
  while (!Z(need_exit)) { _CALL(t2_iter); }
  // uninit - acts
  CHILD_A1 = &Z(t2data.a1_cocrel_vars);
  _CALL(A_uninit_cocrel);
  //@@@endproc
}

static g2_DECL() {
  g2_PRE();
  //@@@proc /decl g2
  // work - thread creation
  CHILD_A1 = CUR_A1;
  if (THREAD_INDEX(CUR_A1) == 2) { _CALL(t2); }
  if (THREAD_INDEX(CUR_A1) == 7) { _CALL(t7); }
  //@@@endproc
  g2_POST();
}

// t1 ------------------------------------------------------- creates t4, t5

static SPRAYABLE_PROC(t1_iter) {
  //@@@proc /name t1_iter
  Sleep(50);
  if (ELAPSED(T1_ACT0_TOFS) && !Z(t1data).act_called_flags[0]) { Z(hThread4) = CreateThread(0, 0, t4, &Z(t4data), 0, &Z(tid)); Z(t1data).act_called_flags[0] = TRUE; }
  if (ELAPSED(T1_ACT1_TOFS) && !Z(t1data).act_called_flags[1]) { Z(hThread5) = CreateThread(0, 0, t5, &Z(t5data), 0, &Z(tid)); Z(t1data).act_called_flags[1] = TRUE; }
  if (ELAPSED(T1_ACT2_TOFS)) { DWORD dwWait = WaitForMultipleObjects(1, Z(t1_hWakerEvents), FALSE, 1000); printf("waited: %d\n", dwWait); }
  //@@@endproc
}

static SPRAYABLE_PROC(t1) {
  //@@@proc /name t1

  // init - thread indices
  Z(t4data).thread_index = 4;
  Z(t5data).thread_index = 5;
  // init - init wakers
  Z(t1_hWakerEvents[0]) = CreateEventA(0, FALSE, 0, 0);

  // run - loop
  CHILD_A1 = CUR_A1;
  while (!Z(need_exit)) { _CALL(t1_iter); }
  // uninit - uninit wakers
  CloseHandle(Z(t1_hWakerEvents[0]));
  //@@@endproc
}

static g1_DECL() {
  g1_PRE();
  //@@@proc /decl g1
  // work - thread creation
  CHILD_A1 = CUR_A1;
  if (THREAD_INDEX(CUR_A1) == 1) { _CALL(t1); }
  if (THREAD_INDEX(CUR_A1) == 6) { _CALL(t6); }
  //@@@endproc
  g1_POST();
}

// t0 ------------------------------------------------------- creates t1, t2, t3

static SPRAYABLE_PROC(t0_iter) {
  //@@@proc /name t0_iter
  Sleep(30);
  if (ELAPSED(T0_ACT0_TOFS) && !Z(t0data).act_called_flags[0]) { Z(hThread1) = CreateThread(0, 0, g1, &Z(t1data), 0, &Z(tid)); Z(t0data).act_called_flags[0] = TRUE; }
  if (ELAPSED(T0_ACT1_TOFS) && !Z(t0data).act_called_flags[1]) { Z(hThread2) = CreateThread(0, 0, g2, &Z(t2data), 0, &Z(tid)); Z(t0data).act_called_flags[1] = TRUE; }
  if (ELAPSED(T0_ACT2_TOFS) && !Z(t0data).act_called_flags[2]) { Z(hThread3) = CreateThread(0, 0, t3, &Z(t3data), 0, &Z(tid)); Z(t0data).act_called_flags[2] = TRUE; }
  //@@@endproc
}


ProgramEntry_DECL() { // g0 t0
  ProgramEntry_PRE();
  //@@@proc /decl ProgramEntry /root yes

  printf("1. RUNNING TESTS\n");

  printf("test running ALL acts...\n");
  _CALL(run_all_acts);

  printf("2. RUNNING PROGRAM\n");



  // init - globals
  Z(cur_usercode_idx) = 1;
  Z(tick_start) = TICKMS;
  // init - thread indices
  Z(t1data).thread_index = 1;
  Z(t2data).thread_index = 2;
  Z(t3data).thread_index = 3;

  // run - loop
  while (!Z(need_exit)) { _CALL(t0_iter); }

  // uninit - wait for threads
  Sleep(100); //#PgWaitForThreadsWorkaround

  //@@@endproc
  ProgramEntry_POST();
}



