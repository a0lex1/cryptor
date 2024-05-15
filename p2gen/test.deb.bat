set "TESTBIN_CFG=Debug"

call %~dp0\test_with_cfg.bat && (echo Alright) || (echo Problem && goto exit)

:exit
