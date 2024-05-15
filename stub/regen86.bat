set BDIR=build86

cmake %~dp0^
  -B%~dp0\%BDIR% -AWin32^
  -DCMAKE_CONFIGURATION_TYPES=Debug;Release;DebugSprayed;ReleaseSprayed  && (echo Success) || (echo ***Error*** && goto exit)


:exit

