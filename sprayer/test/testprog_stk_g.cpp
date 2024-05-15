//@@@headers
#include <cstdio>
//@@@endheaders
#include "spraygen.h"

//@@@privdefs
#define MAINPROC_DECL() int main()
#define MAINPROC_PRE() flag1 = 1; XARGSETUP()
#define MAINPROC_POST() ASSERT(flag1 == 1); XARGCLEANUP(); return 770
#define ASSERT(e) { if (!(e)) { printf("--------- Check failed - %s\n", #e);  *(int*)0 = 1; } }
//@@@endprivdefs

//@@@staticvars
int flag1 = 0;
int flag2 = 0;
int g_tmp = 0;

//@@@endstaticvars


//@@@zvars
unsigned my_cur_sum;
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
  //@@@endproc
  MAINPROC_POST();
}

