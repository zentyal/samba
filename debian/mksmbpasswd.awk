#!/usr/bin/awk -f
BEGIN {FS=":"
	printf("#\n# SMB password file.\n#\n")
	}
{ if ($3 >= 1000) {  
printf( "%s:%s:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:[U          ]:LCT-00000000:%s\n", $1, $3, $5) } }
