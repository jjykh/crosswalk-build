
#define SYM(name) name##_56

#define PTR(name)  Fx_##name
#define Llit(name) .Lit##name
#define Lpic(name) .Lpic##name
#define Lnam(name) Nam_##name

#define FAST(name) \
.global SYM(name); .weak SYM(name); \
.thumb; \
.thumb_func; \
.type	SYM(name), %function; \
.align	2; \
SYM(name): \
  ldr	r3, Llit(name); \
Lpic(name): \
  add	r3, pc; \
  ldr	r3, [r3]; \
  ldr	r3, [r3]; \
  bx	r3; \
Lnam(name): \
  .asciz #name; \
  .align 2; \
Llit(name): \
  .word	PTR(name)(GOT_PREL)+(.-(Lpic(name)+4)); \
  .size	SYM(name), .-SYM(name);

#define SLOWqq(name) \
.global SYM(name); .weak SYM(name); \
.thumb; \
.thumb_func; \
.type	SYM(name), %function; \
.align	2; \
SYM(name): \
  push	{r4}; \
  ldr	r4, Llit(name); \
Lpic(name): \
  add	r4, pc; \
  ldr	r4, [r4]; \
  ldr	r4, [r4]; \
  mov	ip, r4; \
  pop	{r4}; \
  bx	ip; \
Lnam(name): \
  .asciz #name; \
  .align 2; \
Llit(name): \
  .word	PTR(name)(GOT_PREL)+(.-(Lpic(name)+4)); \
  .size	SYM(name), .-SYM(name);

#define SLOWyy(name) \
.global SYM(name); .weak SYM(name); \
.thumb; \
.thumb_func; \
.type	SYM(name), %function; \
.align	2; \
SYM(name): \
  push	{r4, r5, r6, lr}; \
  ldr	r4, Llit(name); \
Lpic(name): \
  add	r4, pc; \
  ldr	r4, [r4]; \
  mov   r6, r4; \
  ldr	r4, [r4]; \
  mov   r5, r4; \
  blx   r4; \
  pop	{r4, r5, r6, pc}; \
  .align 2; \
Llit(name): \
  .word	PTR(name)(GOT_PREL)+(.-(Lpic(name)+4)); \
Lnam(name): \
  .asciz #name; \
  .size	SYM(name), .-SYM(name);

#define SLOWbad(name) \
.global SYM(name); \
.thumb; \
.thumb_func; \
.type	SYM(name), %function; \
.align	2; \
SYM(name): \
  push	{r0, r1, r2, r3, lr}; \
  ldr	r1, 2f; \
  mov   r2, r1; \
  mov   r3, pc; \
1:add	r1, pc; \
  ldr	r0, [r1]; \
  bl    __resolve; \
  mov	ip, r0; \
  pop	{r0, r1, r2, r3}; \
  blx   ip; \
  pop	{pc}; \
  .align 2; \
2:.word	PTR(name)(GOT_PREL)+(.-(1b+4)); \
Lnam(name): \
  .asciz #name; \
  .size	SYM(name), .-SYM(name);

#define SLOWok(name) \
.global SYM(name); .weak SYM(name); \
.thumb; \
.thumb_func; \
.type	SYM(name), %function; \
.align	2; \
SYM(name): \
  push  {r0-r3, lr}; \
  adr	r0, Lnam(name); \
  bl    __resolve2; \
  mov	ip, r0; \
  pop   {r0-r3, lr}; \
  bx    ip; \
Lnam(name): \
  .asciz #name; \
  .size	SYM(name), .-SYM(name);

#define SLOW(name) \
.global SYM(name); .weak SYM(name); \
.thumb; \
.thumb_func; \
.type	SYM(name), %function; \
.align	2; \
SYM(name): \
  push  {r0-r3, lr}; \
  ldr	r0, 9f; \
  bl    __resolve3; \
  mov	ip, r0; \
  pop   {r0-r3, lr}; \
  bx    ip; \
9:.word ICU_##name; \
Lnam(name): \
  .asciz #name; \
  .size	SYM(name), .-SYM(name);


#include "android_icuuc.h"
#include "android_icui18n.h"


.set Id, 0
#define ASSIGN(name) .set ICU_##name, Id; .set Id, Id + 1;

  UC_LIST(ASSIGN, ASSIGN)

.set ICU_i18n__begin, Id
.globl ICU_i18n__begin

  I18N_LIST(ASSIGN, ASSIGN)


.syntax unified
.arch armv7-a
.text

  UC_LIST(SLOW, SLOW)
  I18N_LIST(SLOW, SLOW)


#define RECORD(name)  .globl PTR(name); PTR(name): .word 0; .word Lnam(name);

.data
.align 4
.global __icu_funcs_begin
__icu_funcs_begin:

  UC_LIST(RECORD, RECORD)

.global __icu_i18n_funcs
__icu_i18n_funcs:

  I18N_LIST(RECORD, RECORD)

.global __icu_funcs_end
__icu_funcs_end:

