
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
  bl    __resolve_expat; \
  mov	ip, r0; \
  pop   {r0-r3, lr}; \
  bx    ip; \
9:.word EXPAT_##name; \
Lnam(name): \
  .asciz #name; \
  .size	SYM(name), .-SYM(name);


#define FX_LIST(F, S) \
  S(XmlUtf8Encode) \
  S(XmlInitEncodingNS) \
  S(XML_ErrorString) \
  S(XML_GetErrorCode) \
  S(XML_ParserFree) \
  S(XML_ParseBuffer) \
  S(XML_StopParser) \
  S(XML_GetBuffer) \
  S(XML_SetElementHandler) \
  S(XML_SetEntityDeclHandler) \
  S(XML_SetUserData) \
  S(XML_ParserCreate_MM) \
  S(XML_SetCharacterDataHandler) \
  S(XML_GetCurrentColumnNumber) \
  S(XML_GetCurrentLineNumber) \


.set Id, 0
#define ASSIGN(name) .set EXPAT_##name, Id; .set Id, Id + 1;

  FX_LIST(ASSIGN, ASSIGN)


.syntax unified
.arch armv7-a
.text

  FX_LIST(SLOW, SLOW)


#define RECORD(name)  PTR(name): .word 0; .word Lnam(name);

.data
.align 4
.global __expat_funcs
__expat_funcs:

  FX_LIST(RECORD, RECORD)


