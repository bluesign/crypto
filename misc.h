// +build relic

#ifndef _REL_MISC_INCLUDE_H
#define _REL_MISC_INCLUDE_H

#include "relic.h"

typedef uint8_t byte;

#define BITS_TO_BYTES(x) ((x+7)>>3)
#define BITS_TO_DIGITS(x) ((x+63)>>6)
#define MIN(a,b) ((a)>(b)?(b):(a))

// Most of the functions are written for ALLOC=AUTO not ALLOC=DYNAMIC

// Debug related functions
void    _bytes_print(char*, byte*, int);
void    _fp_print(char*, fp_st*);
void    _bn_print(char*, bn_st*);
void    _ep_print(char*, ep_st*);
void    _ep2_print(char*, ep2_st*);
void    _seed_relic(byte*, int);
void    _bn_randZr(bn_t);
void    _G1scalarGenMult(ep_st*, const bn_st*);
ep_st*  _hashToG1(const byte* data, const int len);

#endif