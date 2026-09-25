#include "core/protos.h"
#include "core/util.h"
#include <cctype>
#include <cstring>
#include <map>
#include <mutex>
#include <set>

// ------------------------------------------------------------------ parsing

bool is_identifier(const std::string& s)
{
    if (s.empty() || !(std::isalpha((unsigned char)s[0]) || s[0] == '_'))
        return false;
    for (char c : s)
        if (!(std::isalnum((unsigned char)c) || c == '_'))
            return false;
    return true;
}

bool is_reserved_word(const std::string& s)
{
    static const std::set<std::string> words = {
        "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum",
        "extern", "float", "for", "goto", "if", "inline", "int", "long", "register", "restrict", "return",
        "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void",
        "volatile", "while", "bool", "_Bool", "true", "false", "NULL", "nullptr", "class", "new", "delete",
        "this", "template", "namespace", "operator", "__asm"};
    return words.count(s) != 0;
}

namespace {

// words that only describe a type: never a parameter's name
bool type_word(const std::string& s)
{
    static const std::set<std::string> words = {"char", "short", "int", "long", "float", "double", "void", "signed",
        "unsigned", "const", "volatile", "struct", "union", "enum", "bool", "_Bool", "restrict", "__int64",
        "__int32", "__int16", "__int8", "wchar_t"};
    return words.count(s) != 0;
}

// calling convention words: dropped from the return type; some say the callee pops its arguments
bool convention(const std::string& w, bool& callee_pops)
{
    static const std::set<std::string> pops = {"WINAPI", "__stdcall", "_stdcall", "NTAPI", "APIENTRY", "CALLBACK",
        "PASCAL", "WSAAPI", "NTSYSAPI", "NTSYSCALLAPI"};
    static const std::set<std::string> other = {"__cdecl", "_cdecl", "__fastcall", "__thiscall", "__vectorcall",
        "WINAPIV", "CDECL", "extern", "static", "inline", "__declspec(dllimport)", "WINBASEAPI", "WINUSERAPI",
        "WINADVAPI", "DECLSPEC_IMPORT", "_Check_return_", "__attribute__((noreturn))"};
    if (pops.count(w)) {
        callee_pops = true;
        return true;
    }
    return other.count(w) != 0;
}

std::string squeeze(std::string s)
{
    // one space between words, "char *" -> "char*"
    std::string out;
    bool space = false;
    for (char c : s) {
        if (std::isspace((unsigned char)c)) {
            space = true;
            continue;
        }
        if (space && !out.empty() && c != '*' && c != '&' && c != ')' && c != ']' && out.back() != '(')
            out += ' ';
        space = false;
        out += c;
    }
    return out;
}

// "const char* s" -> type "const char*", name "s"; "DWORD" -> type "DWORD", no name
void split_param(const std::string& text, proto_param& p)
{
    std::string t = util::trim(text);
    // a function pointer: "int (*cmp)(const void*, const void*)"
    size_t fp = t.find("(*");
    if (fp != std::string::npos) {
        size_t e = t.find(')', fp);
        std::string nm = e == std::string::npos ? std::string() : util::trim(t.substr(fp + 2, e - fp - 2));
        if (is_identifier(nm)) {
            p.name = nm;
            p.type = squeeze(t.substr(0, fp + 2) + t.substr(e));
            return;
        }
        p.type = squeeze(t);
        return;
    }
    std::string arr;
    size_t br = t.find('[');
    if (br != std::string::npos) {
        arr = t.substr(br);
        t = util::trim(t.substr(0, br));
    }
    size_t end = t.size();
    size_t start = end;
    while (start > 0 && (std::isalnum((unsigned char)t[start - 1]) || t[start - 1] == '_'))
        start--;
    std::string last = t.substr(start, end - start);
    std::string rest = util::trim(t.substr(0, start));
    bool rest_is_qualifier = rest.empty() || rest == "const" || rest == "struct" || rest == "union" ||
                             rest == "enum" || rest == "unsigned" || rest == "signed" || rest == "volatile";
    if (!last.empty() && !type_word(last) && !rest_is_qualifier) {
        p.name = last;
        p.type = squeeze(rest + arr);
    } else {
        p.type = squeeze(t + arr);
    }
}

} // namespace

bool parse_prototype(const std::string& text, prototype& out, std::string& err)
{
    out = prototype();
    std::string t = util::trim(text);
    while (!t.empty() && (t.back() == ';' || std::isspace((unsigned char)t.back())))
        t.pop_back();
    size_t open = t.find('(');
    size_t close = t.rfind(')');
    if (open == std::string::npos || close == std::string::npos || close < open) {
        err = "write it like: int name(char* text, int size)";
        return false;
    }
    // the head: return type, calling convention, name
    std::string head = util::trim(t.substr(0, open));
    std::vector<std::string> words;
    for (const std::string& w : util::split(head, " \t"))
        if (!w.empty())
            words.push_back(w);
    if (words.empty()) {
        err = "the function needs a name";
        return false;
    }
    std::string name = words.back();
    words.pop_back();
    while (!name.empty() && name[0] == '*') { // "char *strdup(...)"
        words.push_back("*");
        name = name.substr(1);
    }
    if (!is_identifier(name)) {
        err = "\"" + name + "\" isn't a name a function can have";
        return false;
    }
    std::string ret;
    for (const std::string& w : words) {
        if (convention(w, out.stdcall))
            continue;
        ret += (ret.empty() ? "" : " ") + w;
    }
    out.name = name;
    out.ret = ret.empty() ? "int" : squeeze(ret);
    // the parameters, split at the top level commas
    std::string inner = t.substr(open + 1, close - open - 1);
    std::vector<std::string> parts;
    int depth = 0;
    std::string cur;
    for (char c : inner) {
        if (c == '(' || c == '[')
            depth++;
        if (c == ')' || c == ']')
            depth--;
        if (c == ',' && depth == 0) {
            parts.push_back(cur);
            cur.clear();
            continue;
        }
        cur += c;
    }
    if (!util::trim(cur).empty() || !parts.empty())
        parts.push_back(cur);
    if (parts.size() == 1 && util::trim(parts[0]) == "void")
        parts.clear();
    std::set<std::string> seen;
    for (size_t i = 0; i < parts.size(); i++) {
        std::string p = util::trim(parts[i]);
        if (p == "...") {
            out.variadic = true;
            continue;
        }
        if (p.empty()) {
            err = "an empty parameter";
            return false;
        }
        proto_param pp;
        split_param(p, pp);
        if (pp.name.empty())
            pp.name = "a" + std::to_string(out.params.size() + 1);
        if (is_reserved_word(pp.name)) {
            err = "\"" + pp.name + "\" can't be a parameter's name";
            return false;
        }
        if (!seen.insert(pp.name).second) {
            err = "two parameters are called " + pp.name;
            return false;
        }
        if (pp.type.empty())
            pp.type = "int";
        out.params.push_back(pp);
    }
    if (out.variadic)
        out.stdcall = false; // a variadic function can't pop what it doesn't know
    return true;
}

std::string format_prototype(const prototype& p)
{
    std::string s = p.ret + " " + p.name + "(";
    for (size_t i = 0; i < p.params.size(); i++) {
        if (i)
            s += ", ";
        const std::string& ty = p.params[i].type;
        size_t fp = ty.find("(*)");
        if (fp != std::string::npos) // a function pointer: the name goes inside
            s += ty.substr(0, fp + 2) + p.params[i].name + ty.substr(fp + 2);
        else
            s += ty + " " + p.params[i].name;
    }
    if (p.variadic)
        s += p.params.empty() ? "..." : ", ...";
    if (p.params.empty() && !p.variadic)
        s += "void";
    return s + ")";
}

// ------------------------------------------------------------------ the table
//
// one prototype per line. a % in the name stands for the ansi (A) and wide (W) versions,
// with LPCTSTR / LPTSTR / TCHAR spelled for each. WINAPI marks the callee-pops functions.
// each chunk stays under 16 KB, the longest string literal msvc takes.

namespace {

const char* const table_kernel32 = R"(
HANDLE WINAPI CreateFile%(LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
BOOL WINAPI ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
BOOL WINAPI WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
BOOL WINAPI CloseHandle(HANDLE hObject)
BOOL WINAPI DeleteFile%(LPCTSTR lpFileName)
BOOL WINAPI CopyFile%(LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName, BOOL bFailIfExists)
BOOL WINAPI MoveFile%(LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName)
BOOL WINAPI MoveFileEx%(LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName, DWORD dwFlags)
DWORD WINAPI GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh)
BOOL WINAPI GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize)
DWORD WINAPI SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)
BOOL WINAPI SetFilePointerEx(HANDLE hFile, LARGE_INTEGER liDistanceToMove, PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod)
BOOL WINAPI SetEndOfFile(HANDLE hFile)
BOOL WINAPI FlushFileBuffers(HANDLE hFile)
DWORD WINAPI GetFileAttributes%(LPCTSTR lpFileName)
BOOL WINAPI SetFileAttributes%(LPCTSTR lpFileName, DWORD dwFileAttributes)
BOOL WINAPI GetFileTime(HANDLE hFile, LPFILETIME lpCreationTime, LPFILETIME lpLastAccessTime, LPFILETIME lpLastWriteTime)
BOOL WINAPI SetFileTime(HANDLE hFile, const FILETIME* lpCreationTime, const FILETIME* lpLastAccessTime, const FILETIME* lpLastWriteTime)
HANDLE WINAPI FindFirstFile%(LPCTSTR lpFileName, LPWIN32_FIND_DATA lpFindFileData)
BOOL WINAPI FindNextFile%(HANDLE hFindFile, LPWIN32_FIND_DATA lpFindFileData)
BOOL WINAPI FindClose(HANDLE hFindFile)
BOOL WINAPI CreateDirectory%(LPCTSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
BOOL WINAPI RemoveDirectory%(LPCTSTR lpPathName)
DWORD WINAPI GetTempPath%(DWORD nBufferLength, LPTSTR lpBuffer)
UINT WINAPI GetTempFileName%(LPCTSTR lpPathName, LPCTSTR lpPrefixString, UINT uUnique, LPTSTR lpTempFileName)
DWORD WINAPI GetCurrentDirectory%(DWORD nBufferLength, LPTSTR lpBuffer)
BOOL WINAPI SetCurrentDirectory%(LPCTSTR lpPathName)
DWORD WINAPI GetFullPathName%(LPCTSTR lpFileName, DWORD nBufferLength, LPTSTR lpBuffer, LPTSTR* lpFilePart)
UINT WINAPI GetSystemDirectory%(LPTSTR lpBuffer, UINT uSize)
UINT WINAPI GetWindowsDirectory%(LPTSTR lpBuffer, UINT uSize)
UINT WINAPI GetDriveType%(LPCTSTR lpRootPathName)
DWORD WINAPI GetLogicalDrives(void)
BOOL WINAPI GetVolumeInformation%(LPCTSTR lpRootPathName, LPTSTR lpVolumeNameBuffer, DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPTSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize)
BOOL WINAPI GetDiskFreeSpaceEx%(LPCTSTR lpDirectoryName, PULARGE_INTEGER lpFreeBytesAvailableToCaller, PULARGE_INTEGER lpTotalNumberOfBytes, PULARGE_INTEGER lpTotalNumberOfFreeBytes)
DWORD WINAPI GetModuleFileName%(HMODULE hModule, LPTSTR lpFilename, DWORD nSize)
HMODULE WINAPI GetModuleHandle%(LPCTSTR lpModuleName)
BOOL WINAPI GetModuleHandleEx%(DWORD dwFlags, LPCTSTR lpModuleName, HMODULE* phModule)
HMODULE WINAPI LoadLibrary%(LPCTSTR lpLibFileName)
HMODULE WINAPI LoadLibraryEx%(LPCTSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
BOOL WINAPI FreeLibrary(HMODULE hLibModule)
FARPROC WINAPI GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
LPVOID WINAPI VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
LPVOID WINAPI VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
BOOL WINAPI VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
BOOL WINAPI VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
BOOL WINAPI VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
BOOL WINAPI VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
SIZE_T WINAPI VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
SIZE_T WINAPI VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
BOOL WINAPI ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
BOOL WINAPI WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
HANDLE WINAPI OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
BOOL WINAPI CreateProcess%(LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
BOOL WINAPI TerminateProcess(HANDLE hProcess, UINT uExitCode)
void WINAPI ExitProcess(UINT uExitCode)
HANDLE WINAPI GetCurrentProcess(void)
DWORD WINAPI GetCurrentProcessId(void)
HANDLE WINAPI GetCurrentThread(void)
DWORD WINAPI GetCurrentThreadId(void)
DWORD WINAPI GetProcessId(HANDLE Process)
BOOL WINAPI GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode)
BOOL WINAPI GetExitCodeThread(HANDLE hThread, LPDWORD lpExitCode)
HANDLE WINAPI CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
HANDLE WINAPI CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
HANDLE WINAPI OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId)
void WINAPI ExitThread(DWORD dwExitCode)
BOOL WINAPI TerminateThread(HANDLE hThread, DWORD dwExitCode)
DWORD WINAPI ResumeThread(HANDLE hThread)
DWORD WINAPI SuspendThread(HANDLE hThread)
BOOL WINAPI GetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
BOOL WINAPI SetThreadContext(HANDLE hThread, const CONTEXT* lpContext)
DWORD WINAPI QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData)
DWORD WINAPI WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)
DWORD WINAPI WaitForMultipleObjects(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds)
void WINAPI Sleep(DWORD dwMilliseconds)
DWORD WINAPI SleepEx(DWORD dwMilliseconds, BOOL bAlertable)
HANDLE WINAPI CreateMutex%(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCTSTR lpName)
HANDLE WINAPI OpenMutex%(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCTSTR lpName)
BOOL WINAPI ReleaseMutex(HANDLE hMutex)
HANDLE WINAPI CreateEvent%(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCTSTR lpName)
HANDLE WINAPI OpenEvent%(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCTSTR lpName)
BOOL WINAPI SetEvent(HANDLE hEvent)
BOOL WINAPI ResetEvent(HANDLE hEvent)
HANDLE WINAPI CreateSemaphore%(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitialCount, LONG lMaximumCount, LPCTSTR lpName)
BOOL WINAPI ReleaseSemaphore(HANDLE hSemaphore, LONG lReleaseCount, LPLONG lpPreviousCount)
void WINAPI InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
void WINAPI EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
void WINAPI LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
void WINAPI DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection)
DWORD WINAPI GetLastError(void)
void WINAPI SetLastError(DWORD dwErrCode)
DWORD WINAPI GetTickCount(void)
ULONGLONG WINAPI GetTickCount64(void)
BOOL WINAPI QueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount)
BOOL WINAPI QueryPerformanceFrequency(LARGE_INTEGER* lpFrequency)
void WINAPI GetSystemTime(LPSYSTEMTIME lpSystemTime)
void WINAPI GetLocalTime(LPSYSTEMTIME lpSystemTime)
void WINAPI GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)
void WINAPI GetSystemInfo(LPSYSTEM_INFO lpSystemInfo)
void WINAPI GetNativeSystemInfo(LPSYSTEM_INFO lpSystemInfo)
BOOL WINAPI GetVersionEx%(LPOSVERSIONINFO lpVersionInformation)
DWORD WINAPI GetVersion(void)
BOOL WINAPI GetComputerName%(LPTSTR lpBuffer, LPDWORD nSize)
DWORD WINAPI GetEnvironmentVariable%(LPCTSTR lpName, LPTSTR lpBuffer, DWORD nSize)
BOOL WINAPI SetEnvironmentVariable%(LPCTSTR lpName, LPCTSTR lpValue)
DWORD WINAPI ExpandEnvironmentStrings%(LPCTSTR lpSrc, LPTSTR lpDst, DWORD nSize)
LPTSTR WINAPI GetCommandLine%(void)
void WINAPI OutputDebugString%(LPCTSTR lpOutputString)
BOOL WINAPI IsDebuggerPresent(void)
BOOL WINAPI CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent)
BOOL WINAPI IsWow64Process(HANDLE hProcess, PBOOL Wow64Process)
LPVOID WINAPI HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
BOOL WINAPI HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
LPVOID WINAPI HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)
SIZE_T WINAPI HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem)
HANDLE WINAPI HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)
BOOL WINAPI HeapDestroy(HANDLE hHeap)
HANDLE WINAPI GetProcessHeap(void)
HLOCAL WINAPI LocalAlloc(UINT uFlags, SIZE_T uBytes)
HLOCAL WINAPI LocalFree(HLOCAL hMem)
HGLOBAL WINAPI GlobalAlloc(UINT uFlags, SIZE_T dwBytes)
HGLOBAL WINAPI GlobalFree(HGLOBAL hMem)
LPVOID WINAPI GlobalLock(HGLOBAL hMem)
BOOL WINAPI GlobalUnlock(HGLOBAL hMem)
HANDLE WINAPI CreateFileMapping%(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCTSTR lpName)
HANDLE WINAPI OpenFileMapping%(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCTSTR lpName)
LPVOID WINAPI MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap)
BOOL WINAPI UnmapViewOfFile(LPCVOID lpBaseAddress)
BOOL WINAPI CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize)
HANDLE WINAPI CreateNamedPipe%(LPCTSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
BOOL WINAPI ConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped)
BOOL WINAPI PeekNamedPipe(HANDLE hNamedPipe, LPVOID lpBuffer, DWORD nBufferSize, LPDWORD lpBytesRead, LPDWORD lpTotalBytesAvail, LPDWORD lpBytesLeftThisMessage)
BOOL WINAPI DeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped)
BOOL WINAPI DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions)
HANDLE WINAPI CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
BOOL WINAPI Process32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
BOOL WINAPI Process32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
BOOL WINAPI Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
BOOL WINAPI Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
BOOL WINAPI Module32First(HANDLE hSnapshot, LPMODULEENTRY32 lpme)
BOOL WINAPI Module32Next(HANDLE hSnapshot, LPMODULEENTRY32 lpme)
BOOL WINAPI Module32FirstW(HANDLE hSnapshot, LPMODULEENTRY32W lpme)
BOOL WINAPI Module32NextW(HANDLE hSnapshot, LPMODULEENTRY32W lpme)
BOOL WINAPI Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte)
BOOL WINAPI Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte)
int WINAPI MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar)
int WINAPI WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar)
int WINAPI lstrlen%(LPCTSTR lpString)
LPTSTR WINAPI lstrcpy%(LPTSTR lpString1, LPCTSTR lpString2)
LPTSTR WINAPI lstrcpyn%(LPTSTR lpString1, LPCTSTR lpString2, int iMaxLength)
LPTSTR WINAPI lstrcat%(LPTSTR lpString1, LPCTSTR lpString2)
int WINAPI lstrcmp%(LPCTSTR lpString1, LPCTSTR lpString2)
int WINAPI lstrcmpi%(LPCTSTR lpString1, LPCTSTR lpString2)
LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
LONG WINAPI UnhandledExceptionFilter(struct _EXCEPTION_POINTERS* ExceptionInfo)
void WINAPI RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR* lpArguments)
PVOID WINAPI AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
ULONG WINAPI RemoveVectoredExceptionHandler(PVOID Handle)
DWORD WINAPI TlsAlloc(void)
LPVOID WINAPI TlsGetValue(DWORD dwTlsIndex)
BOOL WINAPI TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue)
BOOL WINAPI TlsFree(DWORD dwTlsIndex)
DWORD WINAPI FormatMessage%(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPTSTR lpBuffer, DWORD nSize, va_list* Arguments)
UINT WINAPI WinExec(LPCSTR lpCmdLine, UINT uCmdShow)
HANDLE WINAPI GetStdHandle(DWORD nStdHandle)
BOOL WINAPI WriteConsole%(HANDLE hConsoleOutput, const void* lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved)
BOOL WINAPI ReadConsole%(HANDLE hConsoleInput, LPVOID lpBuffer, DWORD nNumberOfCharsToRead, LPDWORD lpNumberOfCharsRead, PCONSOLE_READCONSOLE_CONTROL pInputControl)
BOOL WINAPI AllocConsole(void)
BOOL WINAPI FreeConsole(void)
BOOL WINAPI SetConsoleCtrlHandler(PHANDLER_ROUTINE HandlerRoutine, BOOL Add)
BOOL WINAPI GetUserName%(LPTSTR lpBuffer, LPDWORD pcbBuffer)
HRSRC WINAPI FindResource%(HMODULE hModule, LPCTSTR lpName, LPCTSTR lpType)
HGLOBAL WINAPI LoadResource(HMODULE hModule, HRSRC hResInfo)
LPVOID WINAPI LockResource(HGLOBAL hResData)
DWORD WINAPI SizeofResource(HMODULE hModule, HRSRC hResInfo)
BOOL WINAPI DisableThreadLibraryCalls(HMODULE hLibModule)
BOOL WINAPI FlushInstructionCache(HANDLE hProcess, LPCVOID lpBaseAddress, SIZE_T dwSize)
BOOL WINAPI SetThreadPriority(HANDLE hThread, int nPriority)
BOOL WINAPI SetPriorityClass(HANDLE hProcess, DWORD dwPriorityClass)
DWORD WINAPI GetFileType(HANDLE hFile)
BOOL WINAPI GetOverlappedResult(HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred, BOOL bWait)
BOOL WINAPI CreateHardLink%(LPCTSTR lpFileName, LPCTSTR lpExistingFileName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
UINT WINAPI SetErrorMode(UINT uMode)
DWORD WINAPI GetShortPathName%(LPCTSTR lpszLongPath, LPTSTR lpszShortPath, DWORD cchBuffer)
BOOL WINAPI GetComputerNameEx%(COMPUTER_NAME_FORMAT NameType, LPTSTR lpBuffer, LPDWORD nSize)
LCID WINAPI GetUserDefaultLCID(void)
LANGID WINAPI GetUserDefaultUILanguage(void)
LANGID WINAPI GetSystemDefaultLangID(void)
)";

const char* const table_windows = R"(
LONG WINAPI RegOpenKeyEx%(HKEY hKey, LPCTSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
LONG WINAPI RegOpenKey%(HKEY hKey, LPCTSTR lpSubKey, PHKEY phkResult)
LONG WINAPI RegCreateKeyEx%(HKEY hKey, LPCTSTR lpSubKey, DWORD Reserved, LPTSTR lpClass, DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition)
LONG WINAPI RegCreateKey%(HKEY hKey, LPCTSTR lpSubKey, PHKEY phkResult)
LONG WINAPI RegQueryValueEx%(HKEY hKey, LPCTSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
LONG WINAPI RegSetValueEx%(HKEY hKey, LPCTSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE* lpData, DWORD cbData)
LONG WINAPI RegGetValue%(HKEY hkey, LPCTSTR lpSubKey, LPCTSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData)
LONG WINAPI RegDeleteKey%(HKEY hKey, LPCTSTR lpSubKey)
LONG WINAPI RegDeleteValue%(HKEY hKey, LPCTSTR lpValueName)
LONG WINAPI RegEnumKeyEx%(HKEY hKey, DWORD dwIndex, LPTSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved, LPTSTR lpClass, LPDWORD lpcchClass, PFILETIME lpftLastWriteTime)
LONG WINAPI RegEnumValue%(HKEY hKey, DWORD dwIndex, LPTSTR lpValueName, LPDWORD lpcchValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
LONG WINAPI RegCloseKey(HKEY hKey)
BOOL WINAPI OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle)
BOOL WINAPI OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle)
BOOL WINAPI AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength)
BOOL WINAPI LookupPrivilegeValue%(LPCTSTR lpSystemName, LPCTSTR lpName, PLUID lpLuid)
BOOL WINAPI GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength)
SC_HANDLE WINAPI OpenSCManager%(LPCTSTR lpMachineName, LPCTSTR lpDatabaseName, DWORD dwDesiredAccess)
SC_HANDLE WINAPI CreateService%(SC_HANDLE hSCManager, LPCTSTR lpServiceName, LPCTSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCTSTR lpBinaryPathName, LPCTSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCTSTR lpDependencies, LPCTSTR lpServiceStartName, LPCTSTR lpPassword)
SC_HANDLE WINAPI OpenService%(SC_HANDLE hSCManager, LPCTSTR lpServiceName, DWORD dwDesiredAccess)
BOOL WINAPI StartService%(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCTSTR* lpServiceArgVectors)
BOOL WINAPI ControlService(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus)
BOOL WINAPI DeleteService(SC_HANDLE hService)
BOOL WINAPI CloseServiceHandle(SC_HANDLE hSCObject)
BOOL WINAPI StartServiceCtrlDispatcher%(const SERVICE_TABLE_ENTRY* lpServiceStartTable)
SERVICE_STATUS_HANDLE WINAPI RegisterServiceCtrlHandler%(LPCTSTR lpServiceName, LPHANDLER_FUNCTION lpHandlerProc)
BOOL WINAPI SetServiceStatus(SERVICE_STATUS_HANDLE hServiceStatus, LPSERVICE_STATUS lpServiceStatus)
BOOL WINAPI CryptAcquireContext%(HCRYPTPROV* phProv, LPCTSTR szContainer, LPCTSTR szProvider, DWORD dwProvType, DWORD dwFlags)
BOOL WINAPI CryptReleaseContext(HCRYPTPROV hProv, DWORD dwFlags)
BOOL WINAPI CryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH* phHash)
BOOL WINAPI CryptHashData(HCRYPTHASH hHash, const BYTE* pbData, DWORD dwDataLen, DWORD dwFlags)
BOOL WINAPI CryptGetHashParam(HCRYPTHASH hHash, DWORD dwParam, BYTE* pbData, DWORD* pdwDataLen, DWORD dwFlags)
BOOL WINAPI CryptDestroyHash(HCRYPTHASH hHash)
BOOL WINAPI CryptDeriveKey(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY* phKey)
BOOL WINAPI CryptImportKey(HCRYPTPROV hProv, const BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey)
BOOL WINAPI CryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen)
BOOL WINAPI CryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen)
BOOL WINAPI CryptDestroyKey(HCRYPTKEY hKey)
BOOL WINAPI CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer)
int WINAPI MessageBox%(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
int WINAPI MessageBoxEx%(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType, WORD wLanguageId)
HWND WINAPI FindWindow%(LPCTSTR lpClassName, LPCTSTR lpWindowName)
HWND WINAPI FindWindowEx%(HWND hWndParent, HWND hWndChildAfter, LPCTSTR lpszClass, LPCTSTR lpszWindow)
int WINAPI GetWindowText%(HWND hWnd, LPTSTR lpString, int nMaxCount)
BOOL WINAPI SetWindowText%(HWND hWnd, LPCTSTR lpString)
int WINAPI GetClassName%(HWND hWnd, LPTSTR lpClassName, int nMaxCount)
HWND WINAPI GetForegroundWindow(void)
HWND WINAPI GetDesktopWindow(void)
BOOL WINAPI ShowWindow(HWND hWnd, int nCmdShow)
BOOL WINAPI IsWindowVisible(HWND hWnd)
BOOL WINAPI EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam)
DWORD WINAPI GetWindowThreadProcessId(HWND hWnd, LPDWORD lpdwProcessId)
SHORT WINAPI GetAsyncKeyState(int vKey)
SHORT WINAPI GetKeyState(int nVirtKey)
BOOL WINAPI GetKeyboardState(PBYTE lpKeyState)
UINT WINAPI MapVirtualKey%(UINT uCode, UINT uMapType)
HHOOK WINAPI SetWindowsHookEx%(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId)
BOOL WINAPI UnhookWindowsHookEx(HHOOK hhk)
LRESULT WINAPI CallNextHookEx(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam)
BOOL WINAPI GetMessage%(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax)
BOOL WINAPI PeekMessage%(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg)
BOOL WINAPI TranslateMessage(const MSG* lpMsg)
LRESULT WINAPI DispatchMessage%(const MSG* lpMsg)
BOOL WINAPI PostMessage%(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
LRESULT WINAPI SendMessage%(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
void WINAPI PostQuitMessage(int nExitCode)
ATOM WINAPI RegisterClassEx%(const WNDCLASSEX* lpwcx)
ATOM WINAPI RegisterClass%(const WNDCLASS* lpWndClass)
HWND WINAPI CreateWindowEx%(DWORD dwExStyle, LPCTSTR lpClassName, LPCTSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
LRESULT WINAPI DefWindowProc%(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
BOOL WINAPI DestroyWindow(HWND hWnd)
HDC WINAPI GetDC(HWND hWnd)
int WINAPI ReleaseDC(HWND hWnd, HDC hDC)
BOOL WINAPI OpenClipboard(HWND hWndNewOwner)
BOOL WINAPI CloseClipboard(void)
BOOL WINAPI EmptyClipboard(void)
HANDLE WINAPI GetClipboardData(UINT uFormat)
HANDLE WINAPI SetClipboardData(UINT uFormat, HANDLE hMem)
BOOL WINAPI GetCursorPos(LPPOINT lpPoint)
BOOL WINAPI SetCursorPos(int X, int Y)
UINT WINAPI SendInput(UINT cInputs, LPINPUT pInputs, int cbSize)
void WINAPI keybd_event(BYTE bVk, BYTE bScan, DWORD dwFlags, ULONG_PTR dwExtraInfo)
int WINAPI GetSystemMetrics(int nIndex)
UINT_PTR WINAPI SetTimer(HWND hWnd, UINT_PTR nIDEvent, UINT uElapse, TIMERPROC lpTimerFunc)
BOOL WINAPI KillTimer(HWND hWnd, UINT_PTR uIDEvent)
HICON WINAPI LoadIcon%(HINSTANCE hInstance, LPCTSTR lpIconName)
HCURSOR WINAPI LoadCursor%(HINSTANCE hInstance, LPCTSTR lpCursorName)
int WINAPI LoadString%(HINSTANCE hInstance, UINT uID, LPTSTR lpBuffer, int cchBufferMax)
int wsprintf%(LPTSTR lpOut, LPCTSTR lpFmt, ...)
int WINAPI wvsprintf%(LPTSTR lpOut, LPCTSTR lpFmt, va_list arglist)
HINSTANCE WINAPI ShellExecute%(HWND hwnd, LPCTSTR lpOperation, LPCTSTR lpFile, LPCTSTR lpParameters, LPCTSTR lpDirectory, INT nShowCmd)
BOOL WINAPI ShellExecuteEx%(SHELLEXECUTEINFO* pExecInfo)
HRESULT WINAPI SHGetFolderPath%(HWND hwnd, int csidl, HANDLE hToken, DWORD dwFlags, LPTSTR pszPath)
BOOL WINAPI SHGetSpecialFolderPath%(HWND hwnd, LPTSTR pszPath, int csidl, BOOL fCreate)
LPWSTR* WINAPI CommandLineToArgvW(LPCWSTR lpCmdLine, int* pNumArgs)
HRESULT WINAPI URLDownloadToFile%(LPUNKNOWN pCaller, LPCTSTR szURL, LPCTSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB)
HINTERNET WINAPI InternetOpen%(LPCTSTR lpszAgent, DWORD dwAccessType, LPCTSTR lpszProxy, LPCTSTR lpszProxyBypass, DWORD dwFlags)
HINTERNET WINAPI InternetConnect%(HINTERNET hInternet, LPCTSTR lpszServerName, INTERNET_PORT nServerPort, LPCTSTR lpszUserName, LPCTSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
HINTERNET WINAPI InternetOpenUrl%(HINTERNET hInternet, LPCTSTR lpszUrl, LPCTSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext)
HINTERNET WINAPI HttpOpenRequest%(HINTERNET hConnect, LPCTSTR lpszVerb, LPCTSTR lpszObjectName, LPCTSTR lpszVersion, LPCTSTR lpszReferrer, LPCTSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
BOOL WINAPI HttpSendRequest%(HINTERNET hRequest, LPCTSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)
BOOL WINAPI HttpQueryInfo%(HINTERNET hRequest, DWORD dwInfoLevel, LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex)
BOOL WINAPI InternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)
BOOL WINAPI InternetWriteFile(HINTERNET hFile, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten)
BOOL WINAPI InternetCloseHandle(HINTERNET hInternet)
HINTERNET WINAPI WinHttpOpen(LPCWSTR pszAgentW, DWORD dwAccessType, LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags)
HINTERNET WINAPI WinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved)
HINTERNET WINAPI WinHttpOpenRequest(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags)
BOOL WINAPI WinHttpSendRequest(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext)
BOOL WINAPI WinHttpReceiveResponse(HINTERNET hRequest, LPVOID lpReserved)
BOOL WINAPI WinHttpReadData(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)
BOOL WINAPI WinHttpCloseHandle(HINTERNET hInternet)
int WINAPI WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData)
int WINAPI WSACleanup(void)
int WINAPI WSAGetLastError(void)
SOCKET WINAPI WSASocket%(int af, int type, int protocol, LPWSAPROTOCOL_INFO lpProtocolInfo, GROUP g, DWORD dwFlags)
int WINAPI closesocket(SOCKET s)
int WINAPI ioctlsocket(SOCKET s, long cmd, u_long* argp)
NTSTATUS NTAPI NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
NTSTATUS NTAPI NtQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength)
NTSTATUS NTAPI NtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
NTSTATUS NTAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
NTSTATUS NTAPI NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
NTSTATUS NTAPI NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
NTSTATUS NTAPI NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead)
NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten)
NTSTATUS NTAPI NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList)
NTSTATUS NTAPI NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
NTSTATUS NTAPI NtClose(HANDLE Handle)
NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress)
NTSTATUS NTAPI NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval)
NTSTATUS NTAPI NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
NTSTATUS NTAPI NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
NTSTATUS NTAPI NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation)
NTSTATUS NTAPI LdrLoadDll(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle)
NTSTATUS NTAPI LdrGetProcedureAddress(PVOID ModuleHandle, PANSI_STRING FunctionName, WORD Ordinal, PVOID* FunctionAddress)
PVOID NTAPI RtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size)
BOOLEAN NTAPI RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress)
void NTAPI RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString)
void NTAPI RtlMoveMemory(void* Destination, const void* Source, SIZE_T Length)
void NTAPI RtlZeroMemory(void* Destination, SIZE_T Length)
)";

const char* const table_libc = R"(
int printf(const char* format, ...)
int fprintf(FILE* stream, const char* format, ...)
int sprintf(char* str, const char* format, ...)
int snprintf(char* str, size_t size, const char* format, ...)
int vprintf(const char* format, va_list ap)
int vfprintf(FILE* stream, const char* format, va_list ap)
int vsprintf(char* str, const char* format, va_list ap)
int vsnprintf(char* str, size_t size, const char* format, va_list ap)
int scanf(const char* format, ...)
int sscanf(const char* str, const char* format, ...)
int fscanf(FILE* stream, const char* format, ...)
int puts(const char* s)
int fputs(const char* s, FILE* stream)
char* fgets(char* s, int size, FILE* stream)
char* gets(char* s)
int putchar(int c)
int getchar(void)
int fputc(int c, FILE* stream)
int fgetc(FILE* stream)
int putc(int c, FILE* stream)
int getc(FILE* stream)
int ungetc(int c, FILE* stream)
FILE* fopen(const char* pathname, const char* mode)
FILE* fdopen(int fd, const char* mode)
FILE* freopen(const char* pathname, const char* mode, FILE* stream)
int fclose(FILE* stream)
size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream)
size_t fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream)
int fseek(FILE* stream, long offset, int whence)
long ftell(FILE* stream)
void rewind(FILE* stream)
int fflush(FILE* stream)
int feof(FILE* stream)
int ferror(FILE* stream)
int fileno(FILE* stream)
int setvbuf(FILE* stream, char* buf, int mode, size_t size)
int remove(const char* pathname)
int rename(const char* oldpath, const char* newpath)
FILE* tmpfile(void)
FILE* popen(const char* command, const char* type)
int pclose(FILE* stream)
void perror(const char* s)
void* malloc(size_t size)
void* calloc(size_t nmemb, size_t size)
void* realloc(void* ptr, size_t size)
void free(void* ptr)
void* memcpy(void* dest, const void* src, size_t n)
void* memmove(void* dest, const void* src, size_t n)
void* memset(void* s, int c, size_t n)
int memcmp(const void* s1, const void* s2, size_t n)
void* memchr(const void* s, int c, size_t n)
size_t strlen(const char* s)
size_t strnlen(const char* s, size_t maxlen)
char* strcpy(char* dest, const char* src)
char* strncpy(char* dest, const char* src, size_t n)
char* strcat(char* dest, const char* src)
char* strncat(char* dest, const char* src, size_t n)
int strcmp(const char* s1, const char* s2)
int strncmp(const char* s1, const char* s2, size_t n)
int strcasecmp(const char* s1, const char* s2)
int strncasecmp(const char* s1, const char* s2, size_t n)
int _stricmp(const char* s1, const char* s2)
int _strnicmp(const char* s1, const char* s2, size_t n)
int stricmp(const char* s1, const char* s2)
char* strchr(const char* s, int c)
char* strrchr(const char* s, int c)
char* strstr(const char* haystack, const char* needle)
char* strpbrk(const char* s, const char* accept)
size_t strspn(const char* s, const char* accept)
size_t strcspn(const char* s, const char* reject)
char* strtok(char* str, const char* delim)
char* strtok_r(char* str, const char* delim, char** saveptr)
char* strdup(const char* s)
char* _strdup(const char* s)
char* strndup(const char* s, size_t n)
char* strerror(int errnum)
long strtol(const char* nptr, char** endptr, int base)
unsigned long strtoul(const char* nptr, char** endptr, int base)
long long strtoll(const char* nptr, char** endptr, int base)
unsigned long long strtoull(const char* nptr, char** endptr, int base)
double strtod(const char* nptr, char** endptr)
int atoi(const char* nptr)
long atol(const char* nptr)
long long atoll(const char* nptr)
double atof(const char* nptr)
char* _itoa(int value, char* str, int radix)
int toupper(int c)
int tolower(int c)
int isalpha(int c)
int isdigit(int c)
int isspace(int c)
int isalnum(int c)
int isupper(int c)
int islower(int c)
int isprint(int c)
int isxdigit(int c)
int ispunct(int c)
int abs(int j)
long labs(long j)
int rand(void)
void srand(unsigned int seed)
time_t time(time_t* tloc)
clock_t clock(void)
struct tm* localtime(const time_t* timep)
struct tm* gmtime(const time_t* timep)
size_t strftime(char* s, size_t max, const char* format, const struct tm* tm)
time_t mktime(struct tm* tm)
void exit(int status)
void _exit(int status)
void abort(void)
int atexit(void (*function)(void))
char* getenv(const char* name)
int setenv(const char* name, const char* value, int overwrite)
int putenv(char* string)
int system(const char* command)
void qsort(void* base, size_t nmemb, size_t size, int (*compar)(const void*, const void*))
void* bsearch(const void* key, const void* base, size_t nmemb, size_t size, int (*compar)(const void*, const void*))
size_t wcslen(const wchar_t* s)
wchar_t* wcscpy(wchar_t* dest, const wchar_t* src)
wchar_t* wcsncpy(wchar_t* dest, const wchar_t* src, size_t n)
wchar_t* wcscat(wchar_t* dest, const wchar_t* src)
int wcscmp(const wchar_t* s1, const wchar_t* s2)
int wcsncmp(const wchar_t* s1, const wchar_t* s2, size_t n)
int _wcsicmp(const wchar_t* s1, const wchar_t* s2)
wchar_t* wcschr(const wchar_t* s, wchar_t c)
wchar_t* wcsrchr(const wchar_t* s, wchar_t c)
wchar_t* wcsstr(const wchar_t* haystack, const wchar_t* needle)
int wprintf(const wchar_t* format, ...)
int swprintf(wchar_t* ws, size_t size, const wchar_t* format, ...)
size_t mbstowcs(wchar_t* dest, const char* src, size_t n)
size_t wcstombs(char* dest, const wchar_t* src, size_t n)
char* setlocale(int category, const char* locale)
int raise(int sig)
void longjmp(jmp_buf env, int val)
int setjmp(jmp_buf env)
void __stack_chk_fail(void)
int __printf_chk(int flag, const char* format, ...)
int __fprintf_chk(FILE* stream, int flag, const char* format, ...)
int __sprintf_chk(char* str, int flag, size_t strlen, const char* format, ...)
int __snprintf_chk(char* str, size_t maxlen, int flag, size_t strlen, const char* format, ...)
void* __memcpy_chk(void* dest, const void* src, size_t len, size_t destlen)
void* __memset_chk(void* dest, int c, size_t len, size_t destlen)
char* __strcpy_chk(char* dest, const char* src, size_t destlen)
int __libc_start_main(int (*main)(int, char**, char**), int argc, char** argv, void (*init)(void), void (*fini)(void), void (*rtld_fini)(void), void* stack_end)
int __cxa_atexit(void (*func)(void*), void* arg, void* dso_handle)
void __cxa_finalize(void* d)
void* _Znwm(unsigned long size)
void* _Znam(unsigned long size)
void _ZdlPv(void* ptr)
void _ZdaPv(void* ptr)
)";

const char* const table_posix = R"(
int open(const char* pathname, int flags, ...)
int openat(int dirfd, const char* pathname, int flags, ...)
int creat(const char* pathname, mode_t mode)
int close(int fd)
ssize_t read(int fd, void* buf, size_t count)
ssize_t write(int fd, const void* buf, size_t count)
ssize_t pread(int fd, void* buf, size_t count, off_t offset)
ssize_t pwrite(int fd, const void* buf, size_t count, off_t offset)
off_t lseek(int fd, off_t offset, int whence)
int stat(const char* pathname, struct stat* statbuf)
int fstat(int fd, struct stat* statbuf)
int lstat(const char* pathname, struct stat* statbuf)
int access(const char* pathname, int mode)
int unlink(const char* pathname)
int mkdir(const char* pathname, mode_t mode)
int rmdir(const char* pathname)
int chdir(const char* path)
char* getcwd(char* buf, size_t size)
int chmod(const char* pathname, mode_t mode)
int chown(const char* pathname, uid_t owner, gid_t group)
ssize_t readlink(const char* pathname, char* buf, size_t bufsiz)
int symlink(const char* target, const char* linkpath)
DIR* opendir(const char* name)
struct dirent* readdir(DIR* dirp)
int closedir(DIR* dirp)
pid_t fork(void)
int execve(const char* pathname, char* const* argv, char* const* envp)
int execv(const char* pathname, char* const* argv)
int execvp(const char* file, char* const* argv)
int execl(const char* pathname, const char* arg, ...)
int execlp(const char* file, const char* arg, ...)
pid_t waitpid(pid_t pid, int* wstatus, int options)
pid_t wait(int* wstatus)
int kill(pid_t pid, int sig)
pid_t getpid(void)
pid_t getppid(void)
uid_t getuid(void)
uid_t geteuid(void)
int setuid(uid_t uid)
int setgid(gid_t gid)
int pipe(int* pipefd)
int dup(int oldfd)
int dup2(int oldfd, int newfd)
void* mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset)
int munmap(void* addr, size_t length)
int mprotect(void* addr, size_t len, int prot)
int ioctl(int fd, unsigned long request, ...)
int fcntl(int fd, int cmd, ...)
int socket(int domain, int type, int protocol)
int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
int bind(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
int listen(int sockfd, int backlog)
int accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen)
ssize_t send(int sockfd, const void* buf, size_t len, int flags)
ssize_t recv(int sockfd, void* buf, size_t len, int flags)
ssize_t sendto(int sockfd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr, socklen_t addrlen)
ssize_t recvfrom(int sockfd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen)
int select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout)
int poll(struct pollfd* fds, nfds_t nfds, int timeout)
int getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res)
void freeaddrinfo(struct addrinfo* res)
struct hostent* gethostbyname(const char* name)
int gethostname(char* name, size_t len)
unsigned long inet_addr(const char* cp)
char* inet_ntoa(struct in_addr in)
int inet_pton(int af, const char* src, void* dst)
const char* inet_ntop(int af, const void* src, char* dst, socklen_t size)
uint16_t htons(uint16_t hostshort)
uint16_t ntohs(uint16_t netshort)
uint32_t htonl(uint32_t hostlong)
uint32_t ntohl(uint32_t netlong)
int setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen)
int getsockopt(int sockfd, int level, int optname, void* optval, socklen_t* optlen)
int shutdown(int sockfd, int how)
unsigned int sleep(unsigned int seconds)
int usleep(useconds_t usec)
int nanosleep(const struct timespec* req, struct timespec* rem)
unsigned int alarm(unsigned int seconds)
int gettimeofday(struct timeval* tv, struct timezone* tz)
int clock_gettime(clockid_t clockid, struct timespec* tp)
int pthread_create(pthread_t* thread, const pthread_attr_t* attr, void* (*start_routine)(void*), void* arg)
int pthread_join(pthread_t thread, void** retval)
int pthread_detach(pthread_t thread)
pthread_t pthread_self(void)
int pthread_mutex_init(pthread_mutex_t* mutex, const pthread_mutexattr_t* attr)
int pthread_mutex_lock(pthread_mutex_t* mutex)
int pthread_mutex_unlock(pthread_mutex_t* mutex)
int pthread_mutex_destroy(pthread_mutex_t* mutex)
void* dlopen(const char* filename, int flags)
void* dlsym(void* handle, const char* symbol)
int dlclose(void* handle)
char* dlerror(void)
long ptrace(int request, pid_t pid, void* addr, void* data)
int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
long syscall(long number, ...)
int getopt(int argc, char* const* argv, const char* optstring)
int getopt_long(int argc, char* const* argv, const char* optstring, const struct option* longopts, int* longindex)
long sysconf(int name)
int sigaction(int signum, const struct sigaction* act, struct sigaction* oldact)
sighandler_t signal(int signum, sighandler_t handler)
int isatty(int fd)
int uname(struct utsname* buf)
int chroot(const char* path)
int setsid(void)
int daemon(int nochdir, int noclose)
)";

// every table line with a % becomes an A and a W version
void expand(const std::string& line, std::vector<std::string>& out)
{
    if (line.find('%') == std::string::npos) {
        out.push_back(line);
        return;
    }
    for (int wide = 0; wide < 2; wide++) {
        std::string s = line;
        auto swap = [&](const std::string& from, const std::string& to) {
            for (size_t at = s.find(from); at != std::string::npos; at = s.find(from, at + to.size()))
                s.replace(at, from.size(), to);
        };
        swap("LPCTSTR", wide ? "LPCWSTR" : "LPCSTR");
        swap("LPTSTR", wide ? "LPWSTR" : "LPSTR");
        swap("TCHAR", wide ? "WCHAR" : "CHAR");
        swap("LPWIN32_FIND_DATA", wide ? "LPWIN32_FIND_DATAW" : "LPWIN32_FIND_DATAA");
        swap("LPSTARTUPINFO", wide ? "LPSTARTUPINFOW" : "LPSTARTUPINFOA");
        swap("LPOSVERSIONINFO", wide ? "LPOSVERSIONINFOW" : "LPOSVERSIONINFOA");
        swap("%", wide ? "W" : "A");
        out.push_back(s);
    }
}

const std::map<std::string, prototype>& table()
{
    static std::map<std::string, prototype> t;
    static std::once_flag once;
    std::call_once(once, [] {
        for (const char* chunk : {table_kernel32, table_windows, table_libc, table_posix})
            for (const std::string& raw : util::split(chunk, "\n")) {
                std::string line = util::trim(raw);
                if (line.empty())
                    continue;
                std::vector<std::string> lines;
                expand(line, lines);
                for (const std::string& l : lines) {
                    prototype p;
                    std::string err;
                    if (parse_prototype(l, p, err))
                        t[p.name] = p;
                }
            }
    });
    return t;
}

} // namespace

const prototype* known_prototype(const std::string& name)
{
    const std::map<std::string, prototype>& t = table();
    std::string n = name;
    // the ways a binary spells an import: __imp_X, j_X (a thunk), X@plt, X@@GLIBC_2.2.5, _X@8
    for (const char* pre : {"__imp__", "__imp_", "_imp_", "j_", "__"}) {
        size_t len = strlen(pre);
        if (n.compare(0, len, pre) == 0 && t.count(n.substr(len)))
            return &t.find(n.substr(len))->second;
    }
    size_t at = n.find('@');
    if (at != std::string::npos && at > 0)
        n = n.substr(0, at);
    auto it = t.find(n);
    if (it == t.end() && n.size() > 1 && n[0] == '_') // _CreateFileW@28
        it = t.find(n.substr(1));
    if (it == t.end() && n.compare(0, 2, "j_") == 0)
        it = t.find(n.substr(2));
    return it == t.end() ? nullptr : &it->second;
}
