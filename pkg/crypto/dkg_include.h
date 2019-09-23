
#ifndef _REL_DKG_INCLUDE_H
#define _REL_DKG_INCLUDE_H

#include "relic.h"
#include "misc.h"

void _polynomialImage(byte* out, bn_st* a, const int a_size, const int x, ep2_st* y);
void _G2polynomialImages(ep2_st* y, int len_y, ep2_st* A, int len_A);
void write_ep2st_vector(byte* out, ep2_st* A, const int len);
void read_ep2st_vector(ep2_st* A, byte* src, const int len);

#endif