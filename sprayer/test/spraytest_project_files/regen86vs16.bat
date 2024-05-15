set BDIR=build86vs16

cmake %~dp0^
  -B%~dp0\%BDIR% -AWin32^
  -G "Visual Studio 16 2019"^
  -DCMAKE_CONFIGURATION_TYPES=Debug;Release;DebugSprayed;ReleaseSprayed  && (echo Success) || (echo ***Error*** && goto exit)


:exit

