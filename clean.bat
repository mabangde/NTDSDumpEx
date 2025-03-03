@echo off
echo [*] Cleaning VS project files...

REM 删除编译临时文件
for /d /r . %%d in (bin,obj) do @if exist "%%d" rd /s /q "%%d"

REM 删除VS IDE缓存
if exist .vs rd /s /q .vs

REM 删除用户配置文件
del /s /q *.suo
del /s /q *.user

echo [√] All temporary files cleaned.
