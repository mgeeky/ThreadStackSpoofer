#pragma once

#include <windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>


typedef void  (WINAPI* typeSleep)(
    DWORD dwMilis
    );

typedef BOOL(__stdcall* typeStackWalk64)(
    DWORD                            MachineType,
    HANDLE                           hProcess,
    HANDLE                           hThread,
    LPSTACKFRAME64                   StackFrame,
    PVOID                            ContextRecord,
    PREAD_PROCESS_MEMORY_ROUTINE64   ReadMemoryRoutine,
    PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
    PGET_MODULE_BASE_ROUTINE64       GetModuleBaseRoutine,
    PTRANSLATE_ADDRESS_ROUTINE64     TranslateAddress
    );

typedef BOOL(__stdcall* typeSymInitialize)(
    IN HANDLE hProcess,
    IN LPCSTR UserSearchPath,
    IN BOOL fInvadeProcess
    );

typedef std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)> HandlePtr;

struct CallStackFrame
{
    ULONG_PTR calledFrom;
    ULONG_PTR stackAddr;
    ULONG_PTR frameAddr;
    ULONG_PTR origFrameAddr;
    ULONG_PTR retAddr;
    ULONG_PTR overwriteWhat;
};

static const size_t MaxStackFramesToSpoof = 64;
struct StackTraceSpoofingMetadata
{
    HMODULE             hDbghelp;
    typeStackWalk64     pStackWalk64;
    LPVOID              pSymFunctionTableAccess64;
    LPVOID              pSymGetModuleBase64;
    bool                initialized;
    CallStackFrame      spoofedFrame[MaxStackFramesToSpoof];
    CallStackFrame      mimicFrame[MaxStackFramesToSpoof];
    size_t              spoofedFrames;
    size_t              mimickedFrames;
};

struct HookedSleep
{
    typeSleep origSleep;
    BYTE    sleepStub[16];
};

struct HookTrampolineBuffers
{
    // (Input) Buffer containing bytes that should be restored while unhooking.
    BYTE* originalBytes;
    DWORD originalBytesSize;

    // (Output) Buffer that will receive bytes present prior to trampoline installation/restoring.
    BYTE* previousBytes;
    DWORD previousBytesSize;
};


template<class... Args>
void log(Args... args)
{
    std::stringstream oss;
    (oss << ... << args);

    std::cout << oss.str() << std::endl;
}

static const size_t Frames_To_Preserve = 2;
static const DWORD Shellcode_Memory_Protection = PAGE_EXECUTE_READ;

bool hookSleep();
bool injectShellcode(std::vector<uint8_t>& shellcode);
bool readShellcode(const char* path, std::vector<uint8_t>& shellcode);
void walkCallStack(HANDLE hThread, CallStackFrame* frames, size_t maxFrames, size_t* numOfFrames, bool onlyBeaconFrames, size_t framesToPreserve = Frames_To_Preserve);
bool initStackSpoofing();
bool fastTrampoline(bool installHook, BYTE* addressToHook, LPVOID jumpAddress, HookTrampolineBuffers* buffers = NULL);
void spoofCallStack(bool overwriteOrRestore);
void WINAPI MySleep(DWORD _dwMilliseconds);