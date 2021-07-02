#include "util.h"
#include<string.h>
int rbe16(const unsigned char *p)
{
    int v = p[0] << 8 | p[1];
    return v;
}

/* helper, read a big-endian 32 bit int from memory */
int rbe32(const unsigned char *p)
{
    int v = p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
    return v;
}

/* helper, read a native-endian 32 bit int from memory */
int rne32(const unsigned char *p)
{
    /* On x86 we could just cast, but that might not meet
    * arm alignment requirements. */
    int d = 0;
    memcpy(&d, p, 4);
    return d;
}

/* helper, write a little-endian 16 bit int to memory */
void le16(unsigned char *p, int v)
{
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
}

/* helper, write a big-endian 32 bit int to memory */
void be32(unsigned char *p, int v)
{
    p[0] = (v >> 24) & 0xff;
    p[1] = (v >> 16) & 0xff;
    p[2] = (v >> 8) & 0xff;
    p[3] = v & 0xff;
}

/* helper, write a big-endian 16 bit int to memory */
void be16(unsigned char *p, int v)
{
    p[0] = (v >> 8) & 0xff;
    p[1] = v & 0xff;
}

void le32(unsigned char *p, int v)
{
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}