set BDIR=build86vs14

cmake %~dp0^
  -B%~dp0\%BDIR% -AWin32^
  -G "Visual Studio 14 2015"^
  -DCMAKE_CONFIGURATION_TYPES=Debug;Release;DebugSprayed;ReleaseSprayed  && (echo Success) || (echo ***Error*** && goto exit)


:exit

