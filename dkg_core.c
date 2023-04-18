// +build relic

#include "dkg_include.h"


#define N_max 250
#define N_bits_max 8  // log(250)  
#define T_max  ((N_max-1)/2)

// computes P(x) = a_0 + a_1*x + .. + a_n x^n (mod r)
// r being the order of G1, 
// and writes P(x) in out and P(x).g2 in y if y is non NULL
// x being a small integer (byte).
void Fr_polynomial_image_write(byte* out, E2* y, const Fr* a, const int a_size, const byte x){
    Fr image;
    Fr_polynomial_image(&image, y, a, a_size, x);
    // exports the result
    Fr_write_bytes(out, &image);
}

// computes P(x) = a_0 + a_1 * x + .. + a_n * x^n  where P is in Fr[X].
// a_i are all in Fr, `a_size` - 1 is P's degree, x is a small integer less than 255.
// The function writes P(x) in `image` and P(x).g2 in `y` if `y` is non NULL
void Fr_polynomial_image(Fr* image, E2* y, const Fr* a, const int a_size, const byte x){
    Fr_set_zero(image); 
    // convert `x` to Montgomery form
    Fr xR;
    Fr_set_limb(&xR, (limb_t)x);
    Fr_to_montg(&xR, &xR);

    for (int i = a_size-1; i >= 0; i--) {
        Fr_mul_montg(image, image, &xR); 
        Fr_add(image, image, &a[i]); // image is in normal form
    }
    // compute y = P(x).g2
    if (y) {
        G2_mult_gen(y, image);
    }
}

// computes Q(x) = A_0 + A_1*x + ... +  A_n*x^n  in G2
// and stores the point in y
static void E2_polynomial_image(E2* y, const E2* A, const int len_A, const byte x){        
    E2_set_infty(y);
    for (int i = len_A-1; i >= 0 ; i--) {
        E2_mult_small_expo(y, y, x); // TODO: to bench against a specific version of mult with 8 bits expo
        E2_add(y, y, &A[i]);
    }
}


// computes y[i] = Q(i+1) for all participants i ( 0 <= i < len_y)
// where Q(x) = A_0 + A_1*x + ... +  A_n*x^n  in G2[X]
void E2_polynomial_images(E2* y, const int len_y, const E2* A, const int len_A) {
    for (byte i=0; i<len_y; i++) {
        //y[i] = Q(i+1)
        E2_polynomial_image(y+i , A, len_A, i+1);
    }
}

// export an array of G2 into an array of bytes by concatenating
// all serializations of G2 points in order.
// the array must be of length (len * G2_SER_BYTES).
void G2_vector_write_bytes(byte* out, const E2* A, const int len) {
    byte* p = out;
    for (int i=0; i<len; i++){
        E2_write_bytes(p, &A[i]);
        p += G2_SER_BYTES;
    }
}

// The function imports an array of E2 points from a concatenated array of bytes.
// The bytes array is supposed to be in (len * G2_SER_BYTES) 
BLST_ERROR E2_vector_read_bytes(E2* A, const byte* src, const int len){
    byte* p = (byte*) src;
    for (int i=0; i<len; i++){
        int read_ret = E2_read_bytes(&A[i], p, G2_SER_BYTES);
        if (read_ret != BLST_SUCCESS)
            return read_ret;
        p += G2_SER_BYTES;
    }
    // TODO: add G2 subgroup check
    return BLST_SUCCESS;
}

// checks the discrete log relationship in G2.
// - returns 1 if g2^x = y, where g2 is the generator of G2
// - returns 0 otherwise.
bool_t G2_check_log(const Fr* x, const E2* y) {
    E2 tmp;
    G2_mult_gen(&tmp, x);
    return E2_is_equal(&tmp, y);
}
