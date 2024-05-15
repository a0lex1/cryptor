@rem echo Will be generated > %~dp0\NEW_LINK_ORDER.map

echo // we need this file to make cmake add it to project > %~dp0\gened_code.cpp
type nul > %~dp0\emptyfile.bin
type nul > %~dp0\NEW_LINK_ORDER.TXT
del /f %~dp0\*.BMP
del /f %~dp0\cg.dot
del /f %~dp0\$*.bat
del /f %~dp0\string_hashes.h
del /f %~dp0\gened_graph*
del /f %~dp0\CMakeSettings.json
del /f %~dp0\spraytab.json
del /f %~dp0\spraytab.h
del /f %~dp0\gened_substitutions.h
del /f %~dp0\gened_vars.h
del /f %~dp0\gened_headers.h
del /f %~dp0\payload.info.h
del /f %~dp0\exports.h
del /f %~dp0\module.def
del /f %~dp0\p2code*bin
del /f %~dp0\democode.bin
del /f %~dp0\payload.bin
del /f %~dp0\res.info.h
del /f %~dp0\payload.cryptbin.h
del /f %~dp0\payload.cryptbin.bin
del /f %~dp0\payload.binhex.h
del /f %~dp0\cryptbin.keys.h
rmdir /s /q %~dp0\src
rmdir /s /q %~dp0\src_decay
rmdir /s /q %~dp0\rsrc
rmdir /s /q %~dp0\build86
rmdir /s /q %~dp0\build86vs14
rmdir /s /q %~dp0\build64

