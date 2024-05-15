set "TESTBIN_CFG=Release"

call %~dp0\test_with_cfg.bat && (echo Alright) || (echo Problem && goto exit)

:exit
