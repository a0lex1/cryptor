#pragma once

//
#define MAX_CALL_DEPTH 10
#define PATH_SIZE      512/*???*/
#define STACK_SIZE     512/*???*/
#define XARG_SIZE      10/*???*/
#define XARG_IDX_VARS     0
#define XARG_IDX_STACK      1
#define XARG_IDX_PATH         2
#define XARG_IDX_SELFSTACKPTR 3
#define XARG_IDX_TMPVAR1     4
#define XARG_IDX_TMPVAR2   5
#define XARG_IDX_TMPVAR3  6
#define XARG_IDX_TMPVAR4 7

#define SPRAYABLE_PROC(F) void F(void* _xarg[XARG_SIZE])

// _xarg must be void** (or void*[])
#define STK_CUR       (*(void***)(&_xarg[XARG_IDX_STACK]))
#define STK_CHILD     (&STK_CUR[4+1])
#define STK_TMPVAR1   (*(&_xarg[XARG_IDX_TMPVAR1]))
#define STK_TMPVAR2   (*(&_xarg[XARG_IDX_TMPVAR2]))
#define STK_TMPVAR3   (*(&_xarg[XARG_IDX_TMPVAR3]))

#define PSELF()  (*(void***)(&_xarg[XARG_IDX_SELFSTACKPTR]))
#define SELF()   (*(PSELF()))
#define PUSH_SELF(NEWSELF) { PSELF() += 1; *PSELF() = NEWSELF; }
#define POP_SELF() { PSELF() -= 1; }

#ifdef SPRAYED_BUILD
  // Sprayed builds

  #define XARGSETUP() \
    void* _xarg[XARG_SIZE]; \
    _xarg[XARG_IDX_VARS] = g_pzvars; \
    _xarg[XARG_IDX_STACK] = malloc(STACK_SIZE*4); /*#Weakness: need different variants*/ \
    _xarg[XARG_IDX_PATH] = 0; \
    _xarg[XARG_IDX_SELFSTACKPTR] = malloc(MAX_CALL_DEPTH * sizeof(void*));

  #define XARGCLEANUP() \
    free(_xarg[1]);

#else
  // Non-sprayed builds
  #define _CALL(F)   {STK_CUR += 5; F(_xarg); STK_CUR -= 5;} // will be renamed to _CALL?

  #define XARGSETUP() \
    void* _xarg[XARG_SIZE]; \
    _xarg[XARG_IDX_VARS] = 0; \
    _xarg[XARG_IDX_STACK] = malloc(STACK_SIZE*4); \
    _xarg[XARG_IDX_PATH] = 0; \
    _xarg[XARG_IDX_SELFSTACKPTR] = malloc(MAX_CALL_DEPTH * sizeof(void*));

  #define XARGCLEANUP() \
    free(_xarg[1]);

#endif


//
#define CUR_RET   (STK_CUR[0])
#define CUR_A1    (STK_CUR[1])
#define CUR_A2    (STK_CUR[2])
#define CUR_A3    (STK_CUR[3])
#define CUR_A4    (STK_CUR[4])
#define CHILD_RET (STK_CHILD[0])
#define CHILD_A1  (STK_CHILD[1])
#define CHILD_A2  (STK_CHILD[2])
#define CHILD_A3  (STK_CHILD[3])
#define CHILD_A4  (STK_CHILD[4])

// DWORD helpers
#define CUR_RETD   (*(unsigned*)&CUR_RET)
#define CUR_A1D    (*(unsigned*)&CUR_A1)
#define CUR_A2D    (*(unsigned*)&CUR_A2)
#define CUR_A3D    (*(unsigned*)&CUR_A3)
#define CUR_A4D    (*(unsigned*)&CUR_A4)
#define CHILD_RETD  (*(unsigned*)&CHILD_RET)
#define CHILD_A1D   (*(unsigned*)&CHILD_A1)
#define CHILD_A2D   (*(unsigned*)&CHILD_A2)
#define CHILD_A3D   (*(unsigned*)&CHILD_A3)
#define CHILD_A4D   (*(unsigned*)&CHILD_A4)

#define STK_TMPVAR1D (*(unsigned*)&STK_TMPVAR1)
#define STK_TMPVAR2D (*(unsigned*)&STK_TMPVAR2)
#define STK_TMPVAR3D (*(unsigned*)&STK_TMPVAR3)


//
#define RandDW_1 0xceadbead // for nonsprayed
