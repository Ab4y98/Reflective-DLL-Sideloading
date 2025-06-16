## Reflective-DLL-Sideloading  

    . .\Reflective-DLL-Sideloading.ps1  
    Invoke-Reflective-DLL-Sideloading -dll {vulnerable_dll} -payload {dll_file}  

## Prerequisites:

1. Use [exe_to_dll](https://github.com/hasherezade/exe_to_dll) to convert your PE to DLL. 

2. Install [Visual Studio Build Tools 2019](https://aka.ms/vs/16/release/vs_buildtools.exe)

3. .NET Core 3.1

4. [Rust](https://www.rust-lang.org/tools/install) (Cargo)

After you run the script copy all the contents from "src" folder to the vulnerable software folder to run the sRDI.  

The script will create/move 3 files in the "src" folder:    
	1. tmp_something (original DLL)  
	2. our modified DLL file  
	3. shellcode.bin  
	
The sideloading works this way, first the vulnerable software loads our malicious DLL to load our shellcode, after that it redirect every exported function to the original DLL to make sure that the program doesn't crash.  

IMPORTANT: the reflection currently only works on x64 executables .

References:  
https://github.com/memN0ps/venom-rs  
https://github.com/Flangvik/SharpDllProxy  
https://github.com/Flangvik/DLLSideloader/  
