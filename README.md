# vmlinux-disassembly-symbolizer
A script that adds symbol information from System.map to kernel disassembly listings

# Description
Most Linux distributions ship a stripped kernel, with symbol information available separately 
in a System.map file (e.g. /boot/System.map-$(uname -r)). 
Attempting to directly disassemble vmlinux on such systems will produce a raw disassembly listing, 
having no symbol names at all, as tools like objdump are unaware of System.map. 
This script allows to make the disassembly mostly as beautiful as if the kernel was not stripped, 
extracting the symbol table from the supplied System.map file and annotating the disassembly 
correspondingly.

# Usage
```
./symbolize_vmlinux_disassembly.py /path/to/System.map <(objdump -D /path/to/vmlinux)
```
