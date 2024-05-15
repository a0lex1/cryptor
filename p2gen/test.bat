echo TESTING DEBUG
%~dp0\test.deb.bat && (echo Alright) || (echo Problem && goto exit)

echo TESTING RELEASE
%~dp0\test.rel.bat && (echo Alright) || (echo Problem && goto exit)

:exit
