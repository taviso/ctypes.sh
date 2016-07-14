#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

struct nested {
    int a;
    struct {    // anonymous
        int b;
        struct {    // named
            int c;
            struct {
                int d;
            };
        } named;
    };
} nested;

struct hasunion {
    int a;
    union {         // named
        uint8_t b;
        uint16_t c;
        uint32_t d;
        uint64_t e;
        double f;
    } g;
    union {         // anonymous
        uint8_t h;
        uint16_t i;
    };
} hasunion;

struct manytypes {
    uint8_t a;
    uint16_t b;
    uint32_t c;
    uint64_t d;
    double e;
    float f;
    void *g;
    void **h;
} manytypes;

struct hasarray {
    int a[32];
    int b[0];
} hasarray;

struct hasenum {
    enum { a, b, c, d } e;
    enum { f, g = ULONG_MAX } h; // force type to be a long
} hasenum;

typedef struct {
    int a;
    long b;
} unnamed_t;
unnamed_t unnamed;

struct mixedpack {
#pragma pack(push, 1)
    uint8_t a;
    uint32_t b;
#pragma pack(16)
    uint8_t c;
    uint32_t d;
#pragma pack(pop)
} mixedpack;

// Things that might not work, but should in future and shouldn't crash.
struct complexarray {
    int a[2][2][2];
    int b[2][2];
    int c[2];
    struct {
        int d;
        int e;
    } f[2];
} complexarray;

struct complexunion {
    union {
        struct {
            int a;
            int b;
        } c;
        int d;
        char e[3];
    };
} complexunion;

struct bitfields {
    unsigned a:1;
    unsigned b:2;
    unsigned c:3;
    unsigned d:4;
} bitfields;

