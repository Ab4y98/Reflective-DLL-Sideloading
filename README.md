## Reflective-DLL-Sideloading

    . .\Reflective-DLL-Sideloading.ps1
    Invoke-Reflective-DLL-Sideloading -dll {vulnerable_dll} -payload {dll_file}  
    
You can use https://github.com/hasherezade/exe_to_dll to convert your PE to DLL.  
after you run the script copy all the contents from "src" folder to the vulnerable software folder to run the sRDI.  

The script will create/move 3 files in the "src" folder:  
	1. tmp_something (original DLL)
	2. our modified DLL file
	3. shellcode.bin  
The sideloading works this way, first the vulnerable software loads our malicious DLL to load our shellcode, after that it redirect every exported function to the original DLL to make sure that the program doesn't crash.  

![demo](https://s12.gifyu.com/images/SrPgA.gif)

References:  
https://github.com/memN0ps/venom-rs  
https://github.com/Flangvik/SharpDllProxy  
https://github.com/Flangvik/DLLSideloader/  