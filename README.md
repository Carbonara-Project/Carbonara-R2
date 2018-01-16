# Carbonara-R2
Carbonara plugin for Radare2

```
Usage: radare2> #!pipe carbr2 [OPTIONS]

OPTIONS:
   -h, --help                  show this help
   -e, --exists                check if the current opened file is already on the server
   -p, --proc <name/offset>    analyze only a procedure and upgrade it's info on the server
   -r, --rename                rename each procedure in the binary with the name of a similar procedure in our server if the matching treshold is >= TRESHOLD
   -t, --treshold <int>        set TRESHOLD (optional, default 90)
```
