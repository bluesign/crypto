#include "dkg_include.h"

// computes P(x) = a_0 + a_1*x + .. + a_n x^n in F_r
// where `x` is a small integer (byte) and `degree` is P's degree n.
// P(x) is written in `out` and P(x).g2 is written in `y` if `y` is non NULL.
void Fr_polynomial_image_write(byte *out, E2 *y, const Fr *a, const int degree,
                               const byte x) {
  Fr image;
  Fr_polynomial_image(&image, y, a, degree, x);
  // exports the result
  Fr_write_bytes(out, &image);
}

// computes P(x) = a_0 + a_1 * x + .. + a_n * x^n  where P is in Fr[X].
// a_i are all in Fr, `degree` is P's degree, x is a small integer less than
// 255. The function writes P(x) in `image` and P(x).g2 in `y` if `y` is non
// NULL
void Fr_polynomial_image(Fr *image, E2 *y, const Fr *a, const int degree,
                         const byte x) {
  Fr_set_zero(image);
  // convert `x` to Montgomery form
  Fr xR;
  Fr_set_limb(&xR, (limb_t)x);
  Fr_to_montg(&xR, &xR);

  for (int i = degree; i >= 0; i--) {
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
static void E2_polynomial_image(E2 *y, const E2 *A, const int degree,
                                const byte x) {
  E2_set_infty(y);
  for (int i = degree; i >= 0; i--) {
    E2_mult_small_expo(y, y, x);
    E2_add(y, y, &A[i]);
  }
}

// computes y[i] = Q(i+1) for all participants i ( 0 <= i < len_y)
// where Q(x) = A_0 + A_1*x + ... +  A_n*x^n  in G2[X]
void E2_polynomial_images(E2 *y, const int len_y, const E2 *A,
                          const int degree) {
  for (byte i = 0; i < len_y; i++) {
    // y[i] = Q(i+1)
    E2_polynomial_image(y + i, A, degree, i + 1);
  }
}

// export an array of G2 into an array of bytes by concatenating
// all serializations of G2 points in order.
// the array must be of length (len * G2_SER_BYTES).
void G2_vector_write_bytes(byte *out, const E2 *A, const int len) {
  byte *p = out;
  for (int i = 0; i < len; i++) {
    E2_write_bytes(p, &A[i]);
    p += G2_SER_BYTES;
  }
}

// The function imports an array of `n` E2 points from a concatenated array of
// bytes. The bytes array is supposed to be of size (n * G2_SER_BYTES).
// 
// If return is `VALID`, output vector is guaranteed to be in E2.
ERROR E2_vector_read_bytes(E2 *A, const byte *src, const int n) {
  byte *p = (byte *)src;
  for (int i = 0; i < n; i++) {
    int read_ret = E2_read_bytes(&A[i], p, G2_SER_BYTES);
    if (read_ret != VALID)
      return read_ret;
    p += G2_SER_BYTES;
  }
  // TODO: add G2 subgroup check?
  return VALID;
}

// checks the discrete log relationship in G2.
// - returns 1 if g2^x = y, where g2 is the generator of G2
// - returns 0 otherwise.
bool G2_check_log(const Fr *x, const E2 *y) {
  E2 tmp;
  G2_mult_gen(&tmp, x);
  return E2_is_equal(&tmp, y);
}
