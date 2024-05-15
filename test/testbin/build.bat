@REM I'm trying to keep this file up-to-date with /build.py

devenv %~dp0\testbin.sln /build "DebugDll|x64" /project testbin
devenv %~dp0\testbin.sln /build "ReleaseDll|x64" /project testbin
devenv %~dp0\testbin.sln /build "DebugDll|x86" /project testbin
devenv %~dp0\testbin.sln /build "ReleaseDll|x86" /project testbin

devenv %~dp0\testbin.sln /build "Debug|x64"
devenv %~dp0\testbin.sln /build "Release|x64"
devenv %~dp0\testbin.sln /build "Debug|x86"
devenv %~dp0\testbin.sln /build "Release|x86"
