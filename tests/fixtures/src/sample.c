// test program for the ceasta test suite. rebuild with tests/fixtures/build.sh
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#define EXPORT __declspec(dllexport)
#define NOINLINE __declspec(noinline)
#else
#define EXPORT __attribute__((visibility("default")))
#define NOINLINE __attribute__((noinline))
#endif

static const char* names[] = {"zero", "one", "two", "three", "four", "five", "six"};

EXPORT int ceasta_add(int a, int b)
{
    return a + b;
}

NOINLINE unsigned checksum(const char* s)
{
    unsigned h = 5381;
    while (*s)
        h = h * 33 + (unsigned char)*s++;
    return h;
}

static volatile int sink;

// dense switch where every case does different work, so it becomes a jump table
NOINLINE int classify(int x)
{
    switch (x) {
    case 0: sink = 1; return (int)checksum("zero");
    case 1: sink = 2; return (int)checksum("one") + 1;
    case 2: puts("two"); return 2;
    case 3: sink += 3; return sink;
    case 4: return ceasta_add(x, 40);
    case 5: puts("five"); return 5;
    case 6: sink ^= 6; return sink * 3;
    case 7: return (int)checksum(names[x % 7]);
    default: return -1;
    }
}

int main(int argc, char** argv)
{
    const char* msg = "hello from ceasta";
    unsigned c = checksum(msg);
    printf("%s %u %d %d\n", msg, c, classify(argc), ceasta_add(argc, 2));
    if (argc > 5) {
#ifdef _WIN32
        MessageBoxA(NULL, "never shown", "ceasta", MB_OK);
#endif
        abort();
    }
    printf("%s\n", names[argc % 7]);
    return argv[0] ? 0 : 1;
}
