# YARA ENGINE

It's a cmd-based YARA engine that scan file or process using single or many YARA files as you choose.



## How to use

First, compile the code (compile it using C++ 17 version or above) then run the file using ```-h``` option (or without any) to print the help page :



[![1](images\1.png)](images\1.png)



you can run it to scan an EXE file (or any file actually) using the ```-f``` option, and to choose a single Yara file to use its rules using the ```-y``` option :

[![2](images\2.png)](images\2.png)

 Or you can choose number of YARA files to scan with using the ```-d``` option to choose a directory :

[![3](images\3.png)](images\3.png)

[![4](images\4.png)](images\4.png)



And if you want to scan a process instead of a file, use the ```-p``` option to specify a PID :

[![5](images\5.png)](images\5.png)

[![6](images\6.png)](images\6.png)

> Note: you can choose to scan a process with a single YARA file or a directory that has many YARA files too.

