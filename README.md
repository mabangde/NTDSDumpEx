[![[Forked from] [Badge](https://github.com/zcgonvh/NTDSDumpEx)]([https://img.shields.io/badge/Forked%20from-OriginalProject-blue]
# NTDSDumpEx

NTDS.dit offline dumper with non-elevated

### Usage
	ntdsdumpex.exe <-d ntds.dit> <-k HEX-SYS-KEY | -s system.hiv |-r> [-o out.txt] [-h] [-m] [-p] [-u] [-c]
	-d    path of ntds.dit database
	-k    use specified SYSKEY
	-s    parse SYSKEY from specified system.hiv
	-r    read SYSKEY from registry
	-o    write output into
	-h    dump hash histories(if available)
	-p    dump description and path of home directory
	-m    dump machine accounts
	-u    USE UPPER-CASE-HEX
	-c    dump cleartext passwords(if available)



NOTE : MUST BACKUP database file,and repair it frist(run [esentutl /p /o ntds.dit] command).

### Example:
	Example : ntdsdumpex.exe -r -c
	Example : ntdsdumpex.exe -d ntds.dit -o hash.txt -s system.hiv -c

### Reference Source
`ntds.h`,`ntds.cpp`,`attributes.h` from [ntds_decode](https://github.com/mubix/ntds_decode) (some changed).

`ntreg.c`,`ntreg.h` from search,fix some compatibility on windows,and remove the debug outputs.



### License
GPL

### Modification Notice
This fork includes changes by [mabangde], last modified: 2025-03-03
