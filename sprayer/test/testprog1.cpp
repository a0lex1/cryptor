//@@@headers
#include <cstdio>
//@@@endheaders
#include "spraygen.h"

//@@@privdefs
#define MAINPROC_DECL()  int main()
#define MAINPROC_PRE()   flag1 = 1; XARGSETUP()
#define MAINPROC_POST()  ASSERT(flag1 == 1); XARGCLEANUP(); return 770
#define ASSERT(e) { if (!(e)) { printf("--------- Check failed - %s\n", #e);  *(int*)0 = 1; } }
//@@@endprivdefs

//@@@staticvars
static int flag1 = 0;
static int flag2 = 0;
//@@@endstaticvars

MAINPROC_DECL() {
  MAINPROC_PRE();
  //@@@proc /decl MAINPROC /root yes
  printf("hi\n");
  flag2 = 1;
  //@@@endproc
  MAINPROC_POST();
}

