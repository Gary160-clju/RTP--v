#ifndef UTIL_H
#define UTIL_H

int rbe16(const unsigned char *p);
/* helper, read a big-endian 32 bit int from memory */
int rbe32(const unsigned char *p);
/* helper, read a native-endian 32 bit int from memory */
int rne32(const unsigned char *p);
/* helper, write a little-endian 16 bit int to memory */
void le16(unsigned char *p, int v);
/* helper, write a big-endian 32 bit int to memory */
void be32(unsigned char *p, int v);
/* helper, write a big-endian 16 bit int to memory */
void be16(unsigned char *p, int v);
void le32(unsigned char *p, int v);
#endif
