
#define SYM(name) name

#define PTR(name)  Fx_##name
#define Llit(name) .Lit##name
#define Lpic(name) .Lpic##name
#define Lnam(name) Nam_##name


#define SLOW(name) \
.global SYM(name); .weak SYM(name); \
.thumb; \
.thumb_func; \
.type	SYM(name), %function; \
.align	2; \
SYM(name): \
  push  {r0-r3, lr}; \
  ldr	r0, 9f; \
  bl    __resolve_ssl; \
  mov	ip, r0; \
  pop   {r0-r3, lr}; \
  bx    ip; \
9:.word SSL_##name; \
Lnam(name): \
  .asciz #name; \
  .size	SYM(name), .-SYM(name);


#include "android_crypto.h"
#include "android_ssl.h"


.set Id, 0
#define ASSIGN(name) .set SSL_##name, Id; .set Id, Id + 1;

  SSL_LIST(ASSIGN, ASSIGN)

.set SSL_crypto__begin, Id
.globl SSL_crypto__begin

  CRYPTO_LIST(ASSIGN, ASSIGN)


.syntax unified
.arch armv7-a
.text

  SSL_LIST(SLOW, SLOW)
  CRYPTO_LIST(SLOW, SLOW)


#define RECORD(name)  PTR(name): .word 0; .word Lnam(name);

.data
.align 4
.global __ssl_funcs
__ssl_funcs:

  SSL_LIST(RECORD, RECORD)
  CRYPTO_LIST(RECORD, RECORD)

.word 0
.word 0

