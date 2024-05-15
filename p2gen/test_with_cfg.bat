@echo ***
@echo This test is now obsolete because testbin is requires the presence of BeaconServer, otherwise, it crashes
@echo ***
goto exit

%~dp0\p2gen64\Debug\x64\p2gen64.exe fork-mz %~dp0\..\test\testbin\bin\testbin\Release\x64\testbin.exe
IF %ERRORLEVEL% neq 123400 GOTO UNEXPECTED_RET
@echo PASSED[1]

%~dp0\p2gen64\Release\x64\p2gen64.exe fork-mz %~dp0\..\test\testbin\bin\testbin\Release\x64\testbin.exe
IF %ERRORLEVEL% neq 123400 GOTO UNEXPECTED_RET
@echo PASSED[2]

%~dp0\p2gen86\Debug\Win32\p2gen86.exe fork-mz %~dp0\..\test\testbin\bin\testbin\Release\Win32\testbin.exe
IF %ERRORLEVEL% neq 123400 GOTO UNEXPECTED_RET
@echo PASSED[3]

%~dp0\p2gen86\Release\Win32\p2gen86.exe fork-mz %~dp0\..\test\testbin\bin\testbin\Release\Win32\testbin.exe
IF %ERRORLEVEL% neq 123400 GOTO UNEXPECTED_RET
@echo PASSED[4]

@rem `cd .` drop errorlevel to zero
cd .
goto exit

:UNEXPECTED_RET
@echo ERRORLEVEL UNEXPECTED - %ERRORLEVEL%

:exit

