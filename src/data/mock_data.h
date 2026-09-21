#pragma once

struct func_entry {
    const char* name;
    unsigned int addr;
    unsigned int size;
};

struct disasm_line {
    unsigned int addr;
    const char* bytes;
    const char* mnemonic;
    const char* operands;
    const char* comment;
    int kind;
};

struct string_entry {
    unsigned int addr;
    unsigned int len;
    const char* text;
};

struct segment_entry {
    const char* name;
    unsigned int start;
    unsigned int end;
    const char* perms;
};

struct import_entry {
    unsigned int addr;
    const char* dll;
    const char* name;
};

inline func_entry mock_funcs[] = {
    {"start", 0x401000, 0x120},
    {"main_loop", 0x401120, 0x2a0},
    {"sub_4013c0", 0x4013c0, 0x90},
    {"parse_header", 0x401450, 0x140},
    {"decrypt_block", 0x401590, 0x1e0},
    {"win_main", 0x401770, 0x110},
    {"check_license", 0x401880, 0xc0},
    {"load_plugins", 0x401940, 0x170},
    {"sub_401ab0", 0x401ab0, 0x60},
    {"dispatch_cmd", 0x401b10, 0x220},
    {"log_error", 0x401d30, 0x80},
    {"alloc_buf", 0x401db0, 0xa0},
};

inline disasm_line mock_lines[] = {
    {0x401000, "55", "push", "ebp", "", 0},
    {0x401001, "8b ec", "mov", "ebp, esp", "", 0},
    {0x401003, "83 ec 20", "sub", "esp, 0x20", "; frame", 0},
    {0x401006, "e8 15 03 00 00", "call", "parse_header", "; xref", 2},
    {0x40100b, "85 c0", "test", "eax, eax", "", 0},
    {0x40100d, "74 12", "jz", "0x401021", "; taken", 1},
    {0x40100f, "68 00 30 40 00", "push", "offset 0x403000", "; \"MZ header\"", 0},
    {0x401014, "e8 77 05 00 00", "call", "decrypt_block", "", 2},
    {0x401019, "83 c4 04", "add", "esp, 4", "", 0},
    {0x40101c, "eb 05", "jmp", "0x401023", "", 1},
    {0x401021, "33 c0", "xor", "eax, eax", "; else", 0},
    {0x401023, "8b e5", "mov", "esp, ebp", "", 0},
    {0x401025, "5d", "pop", "ebp", "", 0},
    {0x401026, "c3", "ret", "", "", 3},
    {0x401120, "55", "push", "ebp", "; proc main_loop", 0},
    {0x401121, "8b ec", "mov", "ebp, esp", "", 0},
    {0x401123, "e8 58 fe ff ff", "call", "sub_4013c0", "", 2},
    {0x401128, "eb fe", "jmp", "0x401128", "; loop", 1},
};

inline string_entry mock_strings[] = {
    {0x403000, 9, "MZ header"},
    {0x403010, 14, "decrypt failed"},
    {0x403024, 12, "kernel32.dll"},
    {0x403034, 13, "LoadLibraryA"},
    {0x403044, 13, "ida style view"},
    {0x403060, 11, "parse error"},
    {0x403074, 7, "plugins"},
    {0x403080, 12, "license check"},
    {0x403090, 8, "cmd: %s"},
    {0x4030a0, 10, "alloc fail"},
};

inline segment_entry mock_segments[] = {
    {".text", 0x401000, 0x402000, "r-x"},
    {".rdata", 0x403000, 0x404000, "r--"},
    {".data", 0x404000, 0x405000, "rw-"},
    {".rsrc", 0x405000, 0x406000, "r--"},
};

inline import_entry mock_imports[] = {
    {0x402000, "kernel32.dll", "LoadLibraryA"},
    {0x402004, "kernel32.dll", "GetProcAddress"},
    {0x402008, "kernel32.dll", "VirtualAlloc"},
    {0x40200c, "user32.dll", "MessageBoxA"},
    {0x402010, "msvcrt.dll", "memcpy"},
    {0x402014, "msvcrt.dll", "strlen"},
    {0x402018, "ws2_32.dll", "recv"},
};

inline const char* mock_regs[][2] = {
    {"eax", "0x00000001"},
    {"ebx", "0x00403000"},
    {"ecx", "0x00000014"},
    {"edx", "0x00000000"},
    {"esi", "0x0019ff40"},
    {"edi", "0x00401120"},
    {"ebp", "0x0019ff50"},
    {"esp", "0x0019ff30"},
    {"eip", "0x0040100b"},
};

inline unsigned char mock_hex[256] = {
    0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
};
