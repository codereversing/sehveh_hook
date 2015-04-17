#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

const DWORD func_addr = 0x00401000;
const DWORD func_addr_offset = func_addr + 0x1;

void print_parameters(PCONTEXT debug_context) {
    printf("EAX: %X EBX: %X ECX: %X EDX: %X\n",
        debug_context->Eax, debug_context->Ebx, debug_context->Ecx, debug_context->Edx);
    printf("ESP: %X EBP: %X\n",
        debug_context->Esp, debug_context->Ebp);
    printf("ESI: %X EDI: %X\n",
        debug_context->Esi, debug_context->Edi);
    printf("Parameters\n"
        "HWND: %X\n"
        "text: %s\n"
        "length: %i\n",
        (HWND)(*(DWORD*)(debug_context->Esp + 0x4)),
        (char*)(*(DWORD*)(debug_context->Esp + 0x8)),
        (int)(*(DWORD*)(debug_context->Esp + 0xC)));
    
}

void modify_text(PCONTEXT debug_context) {
    char* text = (char*)(*(DWORD*)(debug_context->Esp + 0x8));
    int length = strlen(text);
    _snprintf(text, length, "REPLACED");
}

void __declspec(naked) change_text_stub(void) {
    __asm {
        push ebp
        jmp [func_addr_offset]
    }
}

LONG WINAPI ExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo) {
    if(ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if((DWORD)ExceptionInfo->ExceptionRecord->ExceptionAddress == func_addr) {
            PCONTEXT debug_context = ExceptionInfo->ContextRecord;
            printf("Breakpoint hit!\n");
            print_parameters(debug_context);
            modify_text(debug_context);
            debug_context->Eip = (DWORD)&change_text_stub;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void set_breakpoints(void) {
    HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if(hTool32 != INVALID_HANDLE_VALUE) {
        THREADENTRY32 thread_entry32;
        thread_entry32.dwSize = sizeof(THREADENTRY32);
        FILETIME exit_time, kernel_time, user_time;
        FILETIME creation_time;
        FILETIME prev_creation_time;
        prev_creation_time.dwLowDateTime = 0xFFFFFFFF;
        prev_creation_time.dwHighDateTime = INT_MAX;
        HANDLE hMainThread = NULL;
        if(Thread32First(hTool32, &thread_entry32)) {
            do {
                if(thread_entry32.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(thread_entry32.th32OwnerProcessID)
                    && thread_entry32.th32OwnerProcessID == GetCurrentProcessId()
                    && thread_entry32.th32ThreadID != GetCurrentThreadId()) {
                        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                            FALSE, thread_entry32.th32ThreadID);
                        GetThreadTimes(hThread, &creation_time, &exit_time, &kernel_time, &user_time);
                        if(CompareFileTime(&creation_time, &prev_creation_time) == -1) {
                            memcpy(&prev_creation_time, &creation_time, sizeof(FILETIME));
                            if(hMainThread != NULL)
                                CloseHandle(hMainThread);
                            hMainThread = hThread;
                        }
                        else
                            CloseHandle(hThread);
                }
                thread_entry32.dwSize = sizeof(THREADENTRY32);
            } while(Thread32Next(hTool32, &thread_entry32));
            AddVectoredExceptionHandler(1, ExceptionFilter);
            CONTEXT thread_context = {CONTEXT_DEBUG_REGISTERS};
            thread_context.Dr0 = func_addr;
            thread_context.Dr7 = (1 << 0);
            SetThreadContext(hMainThread, &thread_context);
            CloseHandle(hMainThread);
        }
        CloseHandle(hTool32);
    }
}

int APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if(reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        if(AllocConsole()) {
            freopen("CONOUT$", "w", stdout);
            SetConsoleTitle(L"Console");
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            printf("DLL loaded.\n");
        }
        set_breakpoints();
    }
    return TRUE;
}