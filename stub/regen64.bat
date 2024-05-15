set BDIR=build64

cmake %~dp0^
  -B%~dp0\%BDIR% -Ax64^
  -DCMAKE_CONFIGURATION_TYPES=Debug;Release;DebugSprayed;ReleaseSprayed  && (echo Success) || (echo ***Error*** && goto exit)


:exit

