call %~dp0\$initial.bat && (echo Success) || (echo ***Error in $initial.bat*** && goto exit)
call %~dp0\$create_payload.bat && (echo Success) || (echo ***Error in $create_payload.bat*** && goto exit)
call %~dp0\$encrypt_payload.bat && (echo Success) || (echo ***Error in $encrypt_payload.bat*** && goto exit)
call %~dp0\$construct_parts.bat && (echo Success) || (echo ***Error in $construct_parts.bat*** && goto exit)
call %~dp0\$construct_extra.bat && (echo Success) || (echo ***Error in $construct_extra.bat*** && goto exit)
call %~dp0\$postprocess_payload.bat && (echo Success) || (echo ***Error in $postprocess_payload.bat*** && goto exit)
call %~dp0\$exports.bat && (echo Success) || (echo ***Error in $exports.bat*** && goto exit)
call %~dp0\$finalize.bat && (echo Success) || (echo ***Error in $finalize.bat*** && goto exit)
call %~dp0\$spray_prepare.bat && (echo Success) || (echo ***Error in $spray_prepare.bat*** && goto exit)
call %~dp0\$done.bat && (echo Success) || (echo ***Error in $done.bat*** && goto exit)

@rem call %~dp0\$regen_build.bat && (echo Success) || (echo ***Error in $regen_build.bat*** && goto exit)

exit /b

:exit

exit /b 999
