del /f %~dp0\gened_code.exe
del /f %~dp0\gened_code.obj
del /f %~dp0\gened_graph*
del /f %~dp0\CMakeSettings.json
del /f %~dp0\spraytab.json
del /f %~dp0\spraytab.h
del /f %~dp0\gened_substitutions.h
del /f %~dp0\gened_vars.h
del /f %~dp0\gened_headers.h
@REM deprecated:
rmdir /s /q %~dp0\build86
rmdir /s /q %~dp0\build86vs14
rmdir /s /q %~dp0\build64

