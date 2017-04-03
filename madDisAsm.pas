// ***************************************************************
//  madDisAsm.pas             version:  2.1d  ·  date: 2006-09-11
//  -------------------------------------------------------------
//  mini mini x86 disassembler
//  -------------------------------------------------------------
//  Copyright (C) 1999 - 2006 www.madshi.net, All Rights Reserved
// ***************************************************************

// 2006-09-11 2.1d (1) another little bug in ParseFunction fixed
//                 (2) several little bugs in cleartext disasm fixed
//                 (3) support for SSE3 added
//                 (4) limited support for 64bit modules added
//                 (5) some preparation for 64bit disassembling
//                 (6) minimal debug info only: function names were missing
// 2005-06-19 2.1c (1) little bug in ParseFunction fixed
//                 (2) line numbers were not shown for project initialization
// 2004-10-22 2.1b support for BCB try..whatever blocks added
// 2004-07-11 2.1a (1) line numbers are added to disassembling (Delphi only)
//                 (2) some disassembling cleartext tweaking
// 2004-04-25 2.1  (1) structured exception handling is detected + parsed now
//                 (2) special support for Delphi try..except blocks
//                 (3) special support for Delphi try..finally blocks
//                 (4) special support for Delphi safecall handling blocks
//                 (5) Delphi @Halt call is interpreted as "end of function"
// 2004-01-01 2.0b (1) ParseFunction "not interceptable" false alarm fixed
//                 (2) TryRead improved
// 2003-11-10 2.0a (1) jumps/calls to the very next instruction are ignored now
//                 (2) text output of function parts speeded up (for madExcept)
// 2003-06-09 2.0  (1) rewritten from scratch, full support for mmx/sse2/3dnow!
//                 (2) now we have a full disassembler including text output
//                 (3) the disassembler keeps track of the register contents
//                     -> should improve the detection of call/jmp targets
//                 (4) TryRead gets rid of unwanted debugger exception warnings
// 2002-11-26 1.2c ParseFunction stops at the end of module's code section
// 2002-11-07 1.2b (1) GetImageNtHeaders + PImageExportDirectory -> madTools
//                 (2) ParseFunction: case/switch statements are interpreted
//                 (3) ParseFunction: little gaps between code areas are parsed
// 2001-07-22 1.2a all remote stuff was moved to the new package "madRemote"
// 2001-07-08 1.2  (1) CreateRemoteThread added (works also in win9x)
//                 (2) Alloc/FreeMemEx added
// 2001-06-04 1.1e (1) some changes in "TFunctionInfo"
//                 (2) ParseFunction parameter "acceptOutsideCode" added
//                 (3) "TCodeInfo.Call" added
// 2001-05-25 1.1d (1) only targets with 4 byte length are accepted as far calls
//                 (2) CopyFunction works better now inside of the IDE in win9x
// 2001-04-16 1.1c bug (relocating absolute targets) in CopyFunction fixed
// 2001-02-23 1.1b little bug in ParseFunction fixed
// 2001-01-07 1.1a FreeCopiedFunction added
// 2000-12-22 1.1  CopyFunction added and some minor changes
// 2000-11-23 1.0e minor bug fixes in ParseCode + ParseFunction

unit madDisAsm;

{$I mad.inc}

interface

uses Windows, madTypes, madTools, madStrings;

// ***************************************************************

{ $define cstyle}
{ $define amd64}

type
  // result type for ParseCode
  TCodeInfo = record
    IsValid     : boolean;   // was the specified code pointer valid?
    Opcode      : word;      // Opcode, one byte ($00xx) or two byte ($0fxx)
    ModRm       : byte;      // ModRm byte, if available, otherwise 0
    Call        : boolean;   // is this instruction a call?
    Jmp         : boolean;   // is this instruction a jmp?
    RelTarget   : boolean;   // is this target relative (or absolute)?
    Target      : pointer;   // absolute target address
    PTarget     : pointer;   // pointer to the target information in the code
    PPTarget    : TPPointer; // pointer to pointer to the target information
    TargetSize  : integer;   // size of the target information in bytes (1/2/4)
    Enlargeable : boolean;   // can the target size of this opcode be extended?
    This        : pointer;   // where does this instruction begin?
    Next        : pointer;   // next code location
  end;

// disassembles the specified "code"
// you can loop through code blocks by using "result.Next"
function ParseCode (code: pointer                    ) : TCodeInfo; overload;
function ParseCode (code: pointer; var disAsm: string) : TCodeInfo; overload;

type
  // result type for ParseFunction
  TFunctionInfo = record
    IsValid        : boolean;
    EntryPoint     : pointer;
    CodeBegin      : pointer;
    CodeLen        : integer;
    LastErrorAddr  : pointer;
    LastErrorNo    : cardinal;
    LastErrorStr   : string;
    CodeAreas      : array of record
                       AreaBegin     : pointer;
                       AreaEnd       : pointer;
                       CaseBlock     : boolean;
                       OnExceptBlock : boolean;
                       CalledFrom    : pointer;
                       Registers     : array [0..{$ifdef amd64}15{$else}7{$endif}] of pointer;
                     end;
    FarCalls       : array of record
                       Call          : boolean;  // is it a CALL or a JMP?
                       CodeAddr1     : pointer;  // beginning of call instruction
                       CodeAddr2     : pointer;  // beginning of next instruction
                       Target        : pointer;
                       RelTarget     : boolean;
                       PTarget       : pointer;
                       PPTarget      : TPPointer;
                     end;
    UnknownTargets : array of record
                       Call          : boolean;
                       CodeAddr1     : pointer;
                       CodeAddr2     : pointer;
                     end;
    Interceptable  : boolean;
    Copy           : record
                       IsValid       : boolean;
                       BufferLen     : integer;
                       LastErrorAddr : pointer;
                       LastErrorNo   : cardinal;
                       LastErrorStr  : string;
                     end;
  end;
  TPFunctionInfo = ^TFunctionInfo;

// disassembles the complete function beginning at "func"
// the result tells you whether you can copy this function to another process
// (and which call targets you have to correct for this purpose)
// and whether you can intercept this function by overwriting the code
function ParseFunction (func: pointer                    ) : TFunctionInfo; overload;
function ParseFunction (func: pointer; var disAsm: string) : TFunctionInfo; overload;

// ***************************************************************

const
  // error codes
  CErrorBase_DisAsm              = $770000;
  CErrorNo_UnknownTarget         = CErrorBase_DisAsm + 0;
  CErrorNo_InvalidCode           = CErrorBase_DisAsm + 1;
  CErrorNo_CodeNotInterceptable  = CErrorBase_DisAsm + 2;
  CErrorNo_BadFunction           = CErrorBase_DisAsm + 3;
  CErrorNo_DoubleHook            = CErrorBase_DisAsm + 4;
  CErrorStr_UnknownTarget        = 'This target can''t be seen in the assembler code.';
  CErrorStr_InvalidCode          = 'Invalid code!';
  CErrorStr_CodeNotInterceptable = 'This code is not interceptable due to it''s design.';
  CErrorStr_BadFunction          = 'The specified function is bad.';
  CErrorStr_DoubleHook           = 'This code was already hooked by another hooking library.';

// ***************************************************************
// internal stuff

function kernel32handle : dword;
function ntdllhandle : dword;
function KernelProc (api: string; doubleCheck: boolean = false) : pointer;
function NtProc (api: string; doubleCheck: boolean = false) : pointer;
function GetExportDirectory (code: pointer; out module: cardinal; out pexp: PImageExportDirectory) : boolean;
function SolveW9xDebugMode (code: pointer) : pointer;
function Magic   : cardinal;
function Magic95 : boolean;
function ParseCode_ (code: pointer; tryRead_: dword) : TCodeInfo;
function ParseFunction_ (func                    : pointer;
                         tryRead_                : dword;
                         HandleAnyExceptionAddr  : pointer;
                         HandleOnExceptionAddr   : pointer;
                         HandleAutoExceptionAddr : pointer;
                         HandleFinallyAddr       : pointer;
                         Halt0Addr               : pointer) : TFunctionInfo;
function ParseFunctionEx (func: pointer; var disAsm: string; exceptAddr: pointer;
                          maxLines: integer; autoDelimiters: boolean) : TFunctionInfo;

var GetProcNameFromMapFile : function  (proc: pointer) : string  = nil;
    GetLineNumber          : procedure (proc: pointer; var line: integer; var minAddr, maxAddr: pointer) = nil;
    BcbInitExceptBlockLDTC : pointer = nil;

const
  CKernel32           = (* kernel32.dll       *)  #$3E#$30#$27#$3B#$30#$39#$66#$67#$7B#$31#$39#$39;
  CReadProcessMemory  = (* ReadProcessMemory  *)  #$07#$30#$34#$31#$05#$27#$3A#$36#$30#$26#$26#$18#$30#$38#$3A#$27#$2C;
  CWriteProcessMemory = (* WriteProcessMemory *)  #$02#$27#$3C#$21#$30#$05#$27#$3A#$36#$30#$26#$26#$18#$30#$38#$3A#$27#$2C;

function  StartTryRead : dword;
procedure EndTryRead (tryRead: dword);
function  TryRead  (src, dst: pointer; count: integer; tryRead: dword = 0) : boolean;
function  TryWrite (src, dst: pointer; count: integer; tryRead: dword = 0) : boolean;

// ***************************************************************

implementation

{$ifdef cstyle}
function IntToHexEx(value    : int64;
                    minLen   : integer = 1;
                    fillChar : char    = '0') : string; 
begin
  result := madStrings.IntToHexEx(value);
  Delete(result, 1, 1);
  if (minLen < 0) or (fillChar in ['0'..'9','A'..'F','a'..'f']) then begin
    result := FillStr(result, minLen, fillChar);
    result := UpStr(result) + 'h';
  end else begin
    result := UpStr(result) + 'h';
    result := FillStr(result, minLen, fillChar);
  end;
end;
{$endif}

// ***************************************************************

function GetHandleAnyExceptionAddr : pointer;
asm
  mov eax, offset System.@HandleAnyException
end;

function GetHandleOnExceptionAddr : pointer;
asm
  mov eax, offset System.@HandleOnException
end;

function GetHandleAutoExceptionAddr : pointer;
asm
  mov eax, offset System.@HandleAutoException
end;

function GetHandleFinallyAddr : pointer;
asm
  mov eax, offset System.@HandleFinally
end;

function GetHalt0Addr : pointer;
asm
  mov eax, offset System.@Halt0
end;

// ***************************************************************

const
  fInvalid = $ffff;  // invalid opcode

  fReg     = $0007;  // bit mask
  fNoReg   = $0000;  // no register information available for this opcode
  fRegAl   = $0001;  // no modrm byte: al register
  fRegEax  = $0002;  // no modrm byte: (e)ax register
  fRegO8   = $0004;  // no modrm byte: byte register depending on opcode
  fRegO32  = $0005;  // no modrm byte: (d)word register depending on opcode
  fRegEaxO = $0006;  // no modrm byte: fRegEax + fRegO32
  fRegDxA  = $0007;  // no modrm byte: dx register + (e)ax/al register
  fReg8    = $0001;  // byte register specified by modrm byte
  fReg16   = $0002;  // word register specified by modrm byte
  fRegxx   = $0003;  // segment/cr/dr register specified by modrm byte
  fReg32   = $0004;  // (d)word register specified by modrm byte
  fReg64   = $0005;  // qword register specified by modrm byte
  fRegSt   = $0006;  // st floating point register specified by modrm byte
  fReg128  = $0007;  // oword register specified by modrm byte

  fMod     = $0038;  // bit mask
  fModOpc  = $0008;  // real flags are stored in COpcodeFlagsEx
  fMod8    = $0010;  // byte register/memory
  fMod16   = $0018;  // word register/memory
  fMod32   = $0020;  // (d)word register/memory
  fMod64   = $0028;  // qword register/memory
  fMod80   = $0030;  // st floating point register/memory
  fMod128  = $0038;  // oword register/memory

  f66      = $00C0;  // bit mask
  f66R     = $0040;  // 66 prefix changes size of register  -> 16 (sse: 128)
  f66M     = $0080;  // 66 prefix changes size of modrm     -> 16 (sse: 128)
  f66RM    = $00C0;  // 66 prefix changes size of reg+modrm -> 16 (sse: 128)

  fPtr     = $0100;  // disassembler shows "xword/byte ptr" or "[$xxx]"

  fOrder   = $0200;  // swapped order -> modrm or immediate data comes first

  fI       = $0C00;  // bit mask
  fI8      = $0400;  // immediate byte available
  fI16     = $0800;  // immediate word available
  fI32     = $0C00;  // immediate (d)word available

  fJmpRel  = $1000;  // this opcode is a relative jump/call

  fClr     = $e000;  // bit mask
  fClrR    = $2000;  // clear modrm register/memory specified
  fClrM    = $4000;  // clear register specified by modrm byte
  fClrO    = $6000;  // clear register depending on opcode
  fClrA    = $8000;  // clear eax
  fClrRM   = $a000;  // fClrR + fClrM
  fClrMA   = $c000;  // fClrM + fClrA
  fClrOA   = $e000;  // fClrO + fClrA

  // flags for one byte opcodes
  COpcodeFlags : array [$00..$ff] of word =
    ((fReg8   + fMod8   +                fOrder +                fClrM ),  // 00 /r       add     r/mb, rb          (r)
     (fReg32  + fMod32  + f66RM +        fOrder +                fClrM ),  // 01 /r       add     r/m?, r?          (r)
     (fReg8   + fMod8   +                                        fClrR ),  // 02 /r       add     rb, r/mb          r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 03 /r       add     r?, r/m?          r
     (fRegAl  +                                   fI8  +         fClrA ),  // 04 ib       add     al, ib            eax
     (fRegEax +           f66R  +                 fI32 +         fClrA ),  // 05 i?       add     (e)ax, i?         eax
     {$ifdef amd64}
       (fInvalid                                                         ),  // -----
       (fInvalid                                                         ),  // -----
     {$else}
       (fNoReg                                                           ),  // 06          push    es
       (fNoReg                                                           ),  // 07          pop     es
     {$endif}
     (fReg8   + fMod8   +                fOrder +                fClrM ),  // 08 /r       or      r/mb, rb          (r)
     (fReg32  + fMod32  + f66RM +        fOrder +                fClrM ),  // 09 /r       or      r/m?, r?          (r)
     (fReg8   + fMod8   +                                        fClrR ),  // 0a /r       or      rb, r/mb          r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0b /r       or      r?, r/m?          r
     (fRegAl  +                                   fI8  +         fClrA ),  // 0c ib       or      al, ib            eax
     (fRegEax +           f66R  +                 fI32 +         fClrA ),  // 0d i?       or      (e)ax, i?         eax
     {$ifdef amd64}
       (fInvalid                                                         ),  // -----
     {$else}
       (fNoReg                                                           ),  // 0e          push    cs
     {$endif}
     (fNoReg                                                           ),  // 0f          < extra table below >

     (fReg8   + fMod8   +                fOrder +                fClrM ),  // 10 /r       adc     r/mb, rb          (r)
     (fReg32  + fMod32  + f66RM +        fOrder +                fClrM ),  // 11 /r       adc     r/m?, r?          (r)
     (fReg8   + fMod8   +                                        fClrR ),  // 12 /r       adc     rb, r/mb          r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 13 /r       adc     r?, r/m?          r
     (fRegAl  +                                   fI8  +         fClrA ),  // 14 ib       adc     al, ib            eax
     (fRegEax +           f66R  +                 fI32 +         fClrA ),  // 15 i?       adc     (e)ax, i?         eax
     {$ifdef amd64}
       (fInvalid                                                         ),  // -----
       (fInvalid                                                         ),  // -----
     {$else}
       (fNoReg                                                           ),  // 16          push    ss
       (fNoReg                                                           ),  // 17          pop     ss
     {$endif}
     (fReg8   + fMod8   +                fOrder +                fClrM ),  // 18 /r       sbb     r/mb, rb          (r)
     (fReg32  + fMod32  + f66RM +        fOrder +                fClrM ),  // 19 /r       sbb     r/m?, i?          (r)
     (fReg8   + fMod8   +                                        fClrR ),  // 1a /r       sbb     rb, r/mb          r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 1b /r       sbb     r?, r/m?          r
     (fRegAl  +                                   fI8  +         fClrA ),  // 1c ib       sbb     al, ib            eax
     (fRegEax +           f66R  +                 fI32 +         fClrA ),  // 1d i?       sbb     (e)ax, i?         eax
     {$ifdef amd64}
       (fInvalid                                                         ),  // -----
       (fInvalid                                                         ),  // -----
     {$else}
       (fNoReg                                                           ),  // 1e          push    ds
       (fNoReg                                                           ),  // 1f          pop     ds
     {$endif}

     (fReg8   + fMod8   +                fOrder +                fClrM ),  // 20 /r       and     r/mb, rb          (r)
     (fReg32  + fMod32  + f66RM +        fOrder +                fClrM ),  // 21 /r       and     r/m?, r?          (r)
     (fReg8   + fMod8   +                                        fClrR ),  // 22 /r       and     rb, r/mb          r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 23 /r       and     r?, r/m?          r
     (fRegAl  +                                   fI8  +         fClrA ),  // 24 ib       and     al, ib            eax
     (fRegEax +           f66R  +                 fI32 +         fClrA ),  // 25 i?       and     (e)ax, i?         eax
     (fNoReg                                                           ),  // 26          PREFIX: es segment override
     {$ifdef amd64}
       (fInvalid                                                         ),  // -----
     {$else}
       (fNoReg  +                                                  fClrA ),  // 27          daa                       eax
     {$endif}
     (fReg8   + fMod8   +                fOrder +                fClrM ),  // 28 /r       sub     r/mb, rb          (r)
     (fReg32  + fMod32  + f66RM +        fOrder +                fClrM ),  // 29 /r       sub     r/m?, r?          (r)
     (fReg8   + fMod8   +                                        fClrR ),  // 2a /r       sub     rb, r/mb          r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 2b /r       sub     r?, r/m?          r
     (fRegAl  +                                   fI8  +         fClrA ),  // 2c ib       sub     al, ib            eax
     (fRegEax +           f66R  +                 fI32 +         fClrA ),  // 2d i?       sub     (e)ax, i?         eax
     (fNoReg                                                           ),  // 2e          PREFIX: cs segment override / branch not taken hint
     {$ifdef amd64}
       (fInvalid                                                         ),  // -----
     {$else}
       (fNoReg  +                                                  fClrA ),  // 2f          das                       eax
     {$endif}

     (fReg8   + fMod8   +                fOrder +                fClrM ),  // 30 /r       xor     r/mb, rb          (r)
     (fReg32  + fMod32  + f66RM +        fOrder +                fClrM ),  // 31 /r       xor     r/m?, r?          (r)
     (fReg8   + fMod8   +                                        fClrR ),  // 32 /r       xor     rb, r/mb          r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 33 /r       xor     r?, r/m?          r
     (fRegAl  +                                   fI8  +         fClrA ),  // 34 ib       xor     al, ib            eax
     (fRegEax +           f66R  +                 fI32 +         fClrA ),  // 35 i?       xor     (e)ax, i?         eax
     (fNoReg                                                           ),  // 36          PREFIX: SS segment override
     {$ifdef amd64}
       (fInvalid                                                         ),  // -----
     {$else}
       (fNoReg  +                                                  fClrA ),  // 37          aaa                       eax
     {$endif}
     (fReg8   + fMod8   +                fOrder                        ),  // 38 /r       cmp     r/mb, rb
     (fReg32  + fMod32  + f66RM +        fOrder                        ),  // 39 /r       cmp     r/m?, r?
     (fReg8   + fMod8                                                  ),  // 3a /r       cmp     rb, r/mb
     (fReg32  + fMod32  + f66RM                                        ),  // 3b /r       cmp     r?, r/m?
     (fRegAl  +                                   fI8                  ),  // 3c ib       cmp     al, ib
     (fRegEax +           f66R  +                 fI32                 ),  // 3d i?       cmp     (e)ax, i?
     (fNoReg                                                           ),  // 3e          PREFIX: DS segment override / branch taken hint
     {$ifdef amd64}
       (fInvalid                                                         ),  // -----
     {$else}
       (fNoReg  +                                                  fClrA ),  // 3f          aas                       eax
     {$endif}

     {$ifdef amd64}
       (fNoReg                                                           ),  // 40          PREFIX: REX
       (fNoReg                                                           ),  // 41          
       (fNoReg                                                           ),  // 42          
       (fNoReg                                                           ),  // 43          
       (fNoReg                                                           ),  // 44          
       (fNoReg                                                           ),  // 45          
       (fNoReg                                                           ),  // 46          
       (fNoReg                                                           ),  // 47          
       (fNoReg                                                           ),  // 48          
       (fNoReg                                                           ),  // 49          
       (fNoReg                                                           ),  // 4a          
       (fNoReg                                                           ),  // 4b          
       (fNoReg                                                           ),  // 4c          
       (fNoReg                                                           ),  // 4d          
       (fNoReg                                                           ),  // 4e          
       (fNoReg                                                           ),  // 4f
     {$else}
       (fRegO32 +           f66R  +                                fClrO ),  // 40          inc     (e)ax             r
       (fRegO32 +           f66R  +                                fClrO ),  // 41          inc     (e)cx             r
       (fRegO32 +           f66R  +                                fClrO ),  // 42          inc     (e)dx             r
       (fRegO32 +           f66R  +                                fClrO ),  // 43          inc     (e)bx             r
       (fRegO32 +           f66R  +                                fClrO ),  // 44          inc     (e)sp             r
       (fRegO32 +           f66R  +                                fClrO ),  // 45          inc     (e)bp             r
       (fRegO32 +           f66R  +                                fClrO ),  // 46          inc     (e)si             r
       (fRegO32 +           f66R  +                                fClrO ),  // 47          inc     (e)di             r
       (fRegO32 +           f66R  +                                fClrO ),  // 48          dec     (e)ax             r
       (fRegO32 +           f66R  +                                fClrO ),  // 49          dec     (e)cx             r
       (fRegO32 +           f66R  +                                fClrO ),  // 4a          dec     (e)dx             r
       (fRegO32 +           f66R  +                                fClrO ),  // 4b          dec     (e)bx             r
       (fRegO32 +           f66R  +                                fClrO ),  // 4c          dec     (e)sp             r
       (fRegO32 +           f66R  +                                fClrO ),  // 4d          dec     (e)bp             r
       (fRegO32 +           f66R  +                                fClrO ),  // 4e          dec     (e)si             r
       (fRegO32 +           f66R  +                                fClrO ),  // 4f          dec     (e)di             r
     {$endif}

     (fRegO32 +           f66R                                         ),  // 50          push    (e)ax
     (fRegO32 +           f66R                                         ),  // 51          push    (e)cx
     (fRegO32 +           f66R                                         ),  // 52          push    (e)dx
     (fRegO32 +           f66R                                         ),  // 53          push    (e)bx
     (fRegO32 +           f66R                                         ),  // 54          push    (e)sp
     (fRegO32 +           f66R                                         ),  // 55          push    (e)bp
     (fRegO32 +           f66R                                         ),  // 56          push    (e)si
     (fRegO32 +           f66R                                         ),  // 57          push    (e)di
     (fRegO32 +           f66R  +                                fClrO ),  // 58          pop     (e)ax             r
     (fRegO32 +           f66R  +                                fClrO ),  // 59          pop     (e)cx             r
     (fRegO32 +           f66R  +                                fClrO ),  // 5a          pop     (e)dx             r
     (fRegO32 +           f66R  +                                fClrO ),  // 5b          pop     (e)bx             r
     (fRegO32 +           f66R  +                                fClrO ),  // 5c          pop     (e)sp             r
     (fRegO32 +           f66R  +                                fClrO ),  // 5d          pop     (e)bp             r
     (fRegO32 +           f66R  +                                fClrO ),  // 5e          pop     (e)si             r
     (fRegO32 +           f66R  +                                fClrO ),  // 5f          pop     (e)di             r

     {$ifdef amd64}
       (fInvalid                                                         ),  // -----
       (fInvalid                                                         ),  // -----
       (fInvalid                                                         ),  // -----
       (fReg32  + fMod32  + f66R  + fPtr +                         fClrR ),  // 63 /r       movsxd  rq, r/md          r
     {$else}
       (fNoReg                                                           ),  // 60          pusha(d)
       (fNoReg  +                                                  fClrA ),  // 61          popa(d)                   edi esi ebp ebx edx ecx eax
       (fReg32  + fMod32  + f66RM                                        ),  // 62 /r       bound   r?, m?&?
       (fReg16  + fMod16  +                fOrder +                fClrM ),  // 63 /r       arpl    r/mw, rw          (r)
     {$endif}
     (fNoReg                                                           ),  // 64          PREFIX: fs segment override
     (fNoReg                                                           ),  // 65          PREFIX: gs segment override
     (fNoReg                                                           ),  // 66          PREFIX: operand size override
     (fNoReg                                                           ),  // 67          PREFIX: address size override
     (fNoReg  +                                   fI32                 ),  // 68 i?       push    i?
     (fReg32  + fMod32  + f66RM +                 fI32 +         fClrR ),  // 69 /r i?    imul    r?, [r/m?,] i?    r
     (fNoReg  +                                   fI8                  ),  // 6a ib       push    ib
     (fReg32  + fMod32  + f66RM +                 fI8  +         fClrR ),  // 6b /r ib    imul    r?, [r/m?,] ib    r
     (fNoReg                                                           ),  // 6c          insb                      edi
     (fNoReg                                                           ),  // 6d          insw/insd                 edi
     (fNoReg                                                           ),  // 6e          outsb                     esi
     (fNoReg                                                           ),  // 6f          outsw/d                   esi

     (fNoReg  +                                   fI8  + fJmpRel       ),  // 70 cb       jo      relb
     (fNoReg  +                                   fI8  + fJmpRel       ),  // 71 cb       jno     relb
     (fNoReg  +                                   fI8  + fJmpRel       ),  // 72 cb       jb      relb
     (fNoReg  +                                   fI8  + fJmpRel       ),  // 73 cb       jnb     relb
     (fNoReg  +                                   fI8  + fJmpRel       ),  // 74 cb       jz      relb
     (fNoReg  +                                   fI8  + fJmpRel       ),  // 75 cb       jnz     relb
     (fNoReg  +                                   fI8  + fJmpRel       ),  // 76 cb       jbe     relb
     (fNoReg  +                                   fI8  + fJmpRel       ),  // 77 cb       ja      relb
     (fNoReg  +                                   fI8  + fJmpRel       ),  // 78 cb       js      relb
     (fNoReg  +                                   fI8  + fJmpRel       ),  // 79 cb       jns     relb
     (fNoReg  +                                   fI8  + fJmpRel       ),  // 7a cb       jp      relb
     (fNoReg  +                                   fI8  + fJmpRel       ),  // 7b cb       jnp     relb
     (fNoReg  +                                   fI8  + fJmpRel       ),  // 7c cb       jl      relb
     (fNoReg  +                                   fI8  + fJmpRel       ),  // 7d cb       jge     relb
     (fNoReg  +                                   fI8  + fJmpRel       ),  // 7e cb       jle     relb
     (fNoReg  +                                   fI8  + fJmpRel       ),  // 7f cb       jg      relb

     (fNoReg  + fMod8   +         fPtr +          fI8                  ),  // 80 /x ib    xxx     r/mb, ib          (r)  -  add/or/adc/sbb/and/sub/xor/cmp
     (fNoReg  + fMod32  + f66M  + fPtr +          fI32                 ),  // 81 /x i?    xxx     r/m?, i?          (r)
     {$ifdef amd64}
       (fInvalid                                                         ),  // -----
     {$else}
       (fNoReg  + fMod8   +         fPtr +          fI8                  ),  // 82 /x ib    xxx     r/mb, ib          (r)
     {$endif}
     (fNoReg  + fMod32  + f66M  + fPtr +          fI8                  ),  // 83 /x ib    xxx     r/m?, ib          (r)
     (fReg8   + fMod8   +                fOrder                        ),  // 84 /r       test    r/mb, rb
     (fReg32  + fMod32  + f66RM +        fOrder                        ),  // 85 /r       test    r/m?, r?
     (fReg8   + fMod8   +                                        fClrRM),  // 86 /r       xchg    rb, r/mb          (r) r
     (fReg32  + fMod32  + f66RM +                                fClrRM),  // 87 /r       xchg    r?, r/m?          (r) r
     (fReg8   + fMod8   +                fOrder +                fClrM ),  // 88 /r       mov     r/mb, rb          (r)
     (fReg32  + fMod32  + f66RM +        fOrder +                fClrM ),  // 89 /r       mov     r/m?, r?          (r)
     (fReg8   + fMod8   +                                        fClrR ),  // 8a /r       mov     rb, r/mb          r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 8b /r       mov     r?, r/m?          r
     (fRegxx  + fMod32  + f66RM +        fOrder +                fClrM ),  // 8c /r       mov     r/m?, sreg        (r)
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 8d /r       lea     r?, m             r
     (fRegxx  + fMod16  + f66RM + fPtr                                 ),  // 8e /r       mov     sreg, r/m?
     (fNoReg  + fMod32  + f66M  + fPtr                                 ),  // 8f /0       pop     m?

     (fNoReg                                                           ),  // 90          nop
     (fRegEaxO+           f66R  +                                fClrOA),  // 91          xchg    (e)ax, (e)cx      r eax
     (fRegEaxO+           f66R  +                                fClrOA),  // 92          xchg    (e)ax, (e)dx      r eax
     (fRegEaxO+           f66R  +                                fClrOA),  // 93          xchg    (e)ax, (e)bx      r eax
     (fRegEaxO+           f66R  +                                fClrOA),  // 94          xchg    (e)ax, (e)sp      r eax
     (fRegEaxO+           f66R  +                                fClrOA),  // 95          xchg    (e)ax, (e)bp      r eax
     (fRegEaxO+           f66R  +                                fClrOA),  // 96          xchg    (e)ax, (e)si      r eax
     (fRegEaxO+           f66R  +                                fClrOA),  // 97          xchg    (e)ax, (e)di      r eax
     (fNoReg  +                                                  fClrA ),  // 98          cbw/cwde                  eax
     (fNoReg                                                           ),  // 99          cwd/cdq                   edx
     {$ifdef amd64}
       (fInvalid                                                         ),  // -----
     {$else}
       (fNoReg                                                           ),  // 9a c? cw    call    cw:c?
     {$endif}
     (fNoReg                                                           ),  // 9b          wait
     (fNoReg                                                           ),  // 9c          pushf(d)
     (fNoReg                                                           ),  // 9d          popf(d)
     (fNoReg                                                           ),  // 9e          sahf
     (fNoReg  +                                                  fClrA ),  // 9f          lahf                      eax

     (fRegAl  +                   fPtr +                         fClrA ),  // a0          mov     al, moffsb        eax
     (fRegEax +           f66R  + fPtr +                         fClrA ),  // a1          mov     (e)ax, moffs?     eax
     (fRegAl  +                   fPtr + fOrder                        ),  // a2          mov     moffsb, al
     (fRegEax +           f66R  + fPtr + fOrder                        ),  // a3          mov     moffs?, (e)ax
     (fNoReg                                                           ),  // a4          movsb                     esi edi
     (fNoReg                                                           ),  // a5          movsw/d                   esi edi
     (fNoReg                                                           ),  // a6          cmpsb                     esi edi
     (fNoReg                                                           ),  // a7          cmpsd/w                   esi edi
     (fRegAl  +                                   fI8                  ),  // a8 ib       test    al, ib
     (fRegEax +           f66R  +                 fI32                 ),  // a9 i?       test    (e)ax, i?
     (fNoReg                                                           ),  // aa          stosb                     edi
     (fNoReg                                                           ),  // ab          stosw/d                   edi
     (fNoReg  +                                                  fClrA ),  // ac          lodsb                     eax esi
     (fNoReg  +                                                  fClrA ),  // ad          lodsw/d                   eax esi
     (fNoReg                                                           ),  // ae          scasb                     edi
     (fNoReg                                                           ),  // af          scasw/d                   edi

     (fRegO8  +                                   fI8  +         fClrO ),  // b0 ib       mov     rb, ib            r
     (fRegO8  +                                   fI8  +         fClrO ),  // b1 ib       mov     rb, ib            r
     (fRegO8  +                                   fI8  +         fClrO ),  // b2 ib       mov     rb, ib            r
     (fRegO8  +                                   fI8  +         fClrO ),  // b3 ib       mov     rb, ib            r
     (fRegO8  +                                   fI8  +         fClrO ),  // b4 ib       mov     rb, ib            r
     (fRegO8  +                                   fI8  +         fClrO ),  // b5 ib       mov     rb, ib            r
     (fRegO8  +                                   fI8  +         fClrO ),  // b6 ib       mov     rb, ib            r
     (fRegO8  +                                   fI8  +         fClrO ),  // b7 ib       mov     rb, ib            r
     (fRegO32 +           f66R  +                 fI32 +         fClrO ),  // b8 i?       mov     (e)ax, i?         r
     (fRegO32 +           f66R  +                 fI32 +         fClrO ),  // b9 i?       mov     (e)cx, i?         r
     (fRegO32 +           f66R  +                 fI32 +         fClrO ),  // ba i?       mov     (e)dx, i?         r
     (fRegO32 +           f66R  +                 fI32 +         fClrO ),  // bb i?       mov     (e)bx, i?         r
     (fRegO32 +           f66R  +                 fI32 +         fClrO ),  // bc i?       mov     (e)sp, i?         r
     (fRegO32 +           f66R  +                 fI32 +         fClrO ),  // bd i?       mov     (e)bp, i?         r
     (fRegO32 +           f66R  +                 fI32 +         fClrO ),  // be i?       mov     (e)si, i?         r
     (fRegO32 +           f66R  +                 fI32 +         fClrO ),  // bf i?       mov     (e)di, i?         r

     (fNoReg  + fMod8   +         fPtr +          fI8  +         fClrM ),  // c0 /x ib    xxx     r/mb, ib          (r)  -  rol/ror/rcl/rcr/shl/shr/sar
     (fNoReg  + fMod32  + f66M  + fPtr +          fI8  +         fClrM ),  // c1 /x ib    xxx     r/m?, ib          (r)
     (fNoReg  +                                   fI16                 ),  // c2 iw       ret     iw
     (fNoReg                                                           ),  // c3          ret
     {$ifdef amd64}
       (fInvalid                                                         ),  // -----
       (fInvalid                                                         ),  // -----
     {$else}
       (fReg32  + fMod32  + f66RM +                                fClrR ),  // c4 /r       les     r?, m16:?         r
       (fReg32  + fMod32  + f66RM +                                fClrR ),  // c5 /r       lds     r?, m16:?         r
     {$endif}
     (fNoReg  + fMod8   +         fPtr +          fI8  +         fClrM ),  // c6 /0 ib    mov     r/mb, ib          (r)
     (fNoReg  + fMod32  + f66M  + fPtr +          fI32 +         fClrM ),  // c7 /0 i?    mov     r/m?, i?          (r)
     (fNoReg                                                           ),  // c8 iw ib    enter   iw, ib            ebp
     (fNoReg                                                           ),  // c9          leave                     ebp
     (fNoReg  +                                   fI16                 ),  // ca iw       ret     iw
     (fNoReg                                                           ),  // cb          ret
     (fNoReg                                                           ),  // cc          int 3
     (fNoReg  +                                   fI8                  ),  // cd ib       int     ib
     {$ifdef amd64}
       (fInvalid                                                         ),  // -----
     {$else}
       (fNoReg                                                           ),  // ce          into
     {$endif}
     (fNoReg                                                           ),  // cf          iret(d)

     (fNoReg  + fMod8   +         fPtr +                         fClrM ),  // d0 /x       xxx     r/mb, 1           (r)  -  rol/ror/rcl/rcr/shl/shr/sar
     (fNoReg  + fMod32  + f66M  + fPtr +                         fClrM ),  // d1 /x       xxx     r/m?, 1           (r)
     (fNoReg  + fMod8   +         fPtr +                         fClrM ),  // d2 /x       xxx     r/mb, cl          (r)
     (fNoReg  + fMod32  + f66M  + fPtr +                         fClrM ),  // d3 /x       xxx     r/m?, cl          (r)
     {$ifdef amd64}
       (fInvalid                                                         ),  // -----
       (fInvalid                                                         ),  // -----
       (fInvalid                                                         ),  // -----
     {$else}
       (fNoReg  +                                   fI8  +         fClrA ),  // d4 ib       aam                       eax
       (fNoReg  +                                   fI8  +         fClrA ),  // d5 ib       aad                       eax
       (fNoReg                                                           ),  // d6          salc
     {$endif}
     (fNoReg  +                                                  fClrA ),  // d7          xlatb                     eax
     (fModOpc                                                          ),  // d8 /r       xxx     mdreal/st, st(1)
     (fModOpc                                                          ),  // d9 /x/r     xxx
     (fModOpc                                                          ),  // da /x/r     xxx
     (fModOpc                                                          ),  // db /x/r     xxx
     (fModOpc                                                          ),  // dc /r       xxx     mdreal/st(1), st
     (fModOpc                                                          ),  // dd /x/r     xxx
     (fModOpc                                                          ),  // de /x/r     xxx
     (fModOpc                                                          ),  // df /x/r     xxx

     (fNoReg  +                                   fI8  + fJmpRel       ),  // e0 cb       loopne  relb              ecx
     (fNoReg  +                                   fI8  + fJmpRel       ),  // e1 cb       loope   relb              ecx
     (fNoReg  +                                   fI8  + fJmpRel       ),  // e2 cb       loop    relb              ecx
     (fNoReg  +                                   fI8  + fJmpRel       ),  // e3 cb       jcxz    relb
     (fRegAl  +                                   fI8  +         fClrA ),  // e4 ib       in      al, ib            eax
     (fRegEax +           f66R  +                 fI8  +         fClrA ),  // e5 ib       in      (e)ax, ib         eax
     (fRegAl  +                          fOrder + fI8                  ),  // e6 ib       out     ib, al
     (fRegEax +           f66R  +        fOrder + fI8                  ),  // e7 ib       out     ib, (e)ax
     (fNoReg  +                                   fI32 + fJmpRel       ),  // e8 c?       call    rel?
     (fNoReg  +                                   fI32 + fJmpRel       ),  // e9 c?       jmp     rel?
     {$ifdef amd64}
       (fInvalid                                                         ),  // -----
     {$else}
       (fNoReg                                                           ),  // ea c? cw    jmp     ptr16:?
     {$endif}
     (fNoReg  +                                   fI8  + fJmpRel       ),  // eb cb       jmp     relb
     (fRegDxA +                                                  fClrA ),  // ec          in      al, dx            eax
     (fRegDxA +           f66R  +                                fClrA ),  // ed          in      (e)ax, dx         eax
     (fRegDxA +                          fOrder                        ),  // ee          out     dx, al
     (fRegDxA +           f66R  +        fOrder                        ),  // ef          out     dx, (e)ax

     (fNoReg                                                           ),  // f0          PREFIX: lock
     (fNoReg                                                           ),  // f1          int01
     (fNoReg                                                           ),  // f2          PREFIX: repne             +ecx
     (fNoReg                                                           ),  // f3          PREFIX: rep(e)            +ecx
     (fNoReg                                                           ),  // f4          hlt
     (fNoReg                                                           ),  // f5          cmc
     (fModOpc                                                          ),  // f6 /x (ib)  xxx     r/mb (,ib)        (r) (eax)  -  test/not/neg/mul/imul/div/idiv
     (fModOpc                                                          ),  // f7 /x (i?)  xxx     r/m? (,i?)        (r) (eax)
     (fNoReg                                                           ),  // f8          clc
     (fNoReg                                                           ),  // f9          stc
     (fNoReg                                                           ),  // fa          cli
     (fNoReg                                                           ),  // fb          sti
     (fNoReg                                                           ),  // fc          cld
     (fNoReg                                                           ),  // fd          std
     (fNoReg  + fMod8   +         fPtr +                         fClrM ),  // fe /x       xxx     r/mb              (r)  -  inc/dec
     (fNoReg  + fMod32  + f66M  + fPtr                                 )); // ff /x       xxx     r/m?              (r)  -  inc/dec/call/call/jmp/jmp/push

  // flags for two byte opcodes ($0f $xx)
  COpcodeFlags0f : array [$00..$ff] of word =
    ((fNoReg  + fMod16  +         fPtr                                 ),  // 0f 00 /x    xxx     r/mw              (r)  -  sldt/str/lldt/ltr/verr/verw
     (fNoReg  + fMod16                                                 ),  // 0f 01 /x    xxx     r/m?              (r)  -  sgdt/sidt/lgdt/lidt/smsw/-/lmsw/invlpg
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f 02 /r    lar     r?, r/m?          r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f 03 /r    lsl     r?, r/m?          r
     (fInvalid                                                         ),  // -----
     (fNoReg                                                           ),  // 0f 05       syscall (AMD)
     (fNoReg                                                           ),  // 0f 06       clts
     (fNoReg                                                           ),  // 0f 07       sysret (AMD)
     (fNoReg                                                           ),  // 0f 08       invd
     (fNoReg                                                           ),  // 0f 09       wbinvd
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fNoReg  + fMod8   +         fPtr                                 ),  // 0f 0d /x    prefetch(w) r/mb
     (fNoReg                                                           ),  // 0f 0e       femms
     (fReg64  + fMod64  +         fPtr +          fI8                  ),  // 0f 0f xx    xxx     pq, qq

     (fReg128 + fMod128                                                ),  // 0f 10 /r    movups  xmm, xmm/m
     (fReg128 + fMod128 +                fOrder                        ),  // 0f 11 /r    movups  xmm/m, xmm
     (fReg128 + fMod128                                                ),  // 0f 12 /r    movlps  xmm, m
     (fReg128 + fMod128 +                fOrder                        ),  // 0f 13 /r    movlps  m, xmm
     (fReg128 + fMod128                                                ),  // 0f 14 /r    unpcklps xmm, xmm/m
     (fReg128 + fMod128                                                ),  // 0f 15 /r    unpckhps xmm, xmm/m
     (fReg128 + fMod128                                                ),  // 0f 16 /r    movhps  xmm, m
     (fReg128 + fMod128 +                fOrder                        ),  // 0f 17 /r    movhps  m, xmm
     (fNoReg  + fMod8   +         fPtr                                 ),  // 0f 18 /x    prefetchxxx
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----

     (fRegxx  + fMod32  +                fOrder +                fClrM ),  // 0f 20 /r    mov     rd, cr0-4         r
     (fRegxx  + fMod32  +                fOrder +                fClrM ),  // 0f 21 /r    mov     rd, dr0-7         r
     (fRegxx  + fMod32                                                 ),  // 0f 22 /r    mov     cr0-4, rd
     (fRegxx  + fMod32                                                 ),  // 0f 23 /r    mov     dr0-7, rd
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fReg128 + fMod128                                                ),  // 0f 28 /r    movaps  xmm, xmm/m
     (fReg128 + fMod128 +                fOrder                        ),  // 0f 29 /r    movaps  xmm/m, xmm
     (fReg128 + fMod64                                                 ),  // 0f 2a /r    cvtpi2ps xmm, mm/r/m
     (fReg128 + fMod128 +                fOrder                        ),  // 0f 2b /r    movntps m, xmm
     (fReg64  + fMod128                                                ),  // 0f 2c /r    cvttps2pi m/r, xmm/m      (r)
     (fReg64  + fMod128                                                ),  // 0f 2d /r    cvtps2pi  m/r, xmm/m      (r)
     (fReg128 + fMod128                                                ),  // 0f 2e /r    ucomiss xmm, xmm/m
     (fReg128 + fMod128                                                ),  // 0f 2f /r    comiss  xmm, xmm/m

     (fNoReg                                                           ),  // 0f 30       wrmsr
     (fNoReg  +                                                  fClrA ),  // 0f 31       rdtsc                     edx eax
     (fNoReg  +                                                  fClrA ),  // 0f 32       rdmsr                     edx eax
     (fNoReg  +                                                  fClrA ),  // 0f 33       rdpmc                     edx eax
     (fNoReg                                                           ),  // 0f 34       sysenter
     (fNoReg                                                           ),  // 0f 35       sysexit
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----

     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f 40 /r    cmovo   r?,r/m?           r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f 41 /r    cmovno  r?,r/m?           r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f 42 /r    cmovb   r?,r/m?           r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f 43 /r    cmovnb  r?,r/m?           r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f 44 /r    cmovz   r?,r/m?           r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f 45 /r    cmovnz  r?,r/m?           r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f 46 /r    cmovbe  r?,r/m?           r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f 47 /r    cmova   r?,r/m?           r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f 48 /r    cmovs   r?,r/m?           r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f 49 /r    cmovns  r?,r/m?           r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f 4a /r    cmovp   r?,r/m?           r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f 4b /r    cmovnp  r?,r/m?           r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f 4c /r    cmovl   r?,r/m?           r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f 4d /r    cmovge  r?,r/m?           r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f 4e /r    cmovle  r?,r/m?           r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f 4f /r    cmovg   r?,r/m?           r

     (fReg32  + fMod128 +                                        fClrM ),  // 0f 50 /r    movmskps r, xmm           r
     (fReg128 + fMod128                                                ),  // 0f 51 /r    sqrtps  xmm, xmm/m
     (fReg128 + fMod128                                                ),  // 0f 52 /r    rsqrtps xmm, xmm/m
     (fReg128 + fMod128                                                ),  // 0f 53 /r    rcpps   xmm, xmm/m
     (fReg128 + fMod128                                                ),  // 0f 54 /r    andps   xmm, xmm/m
     (fReg128 + fMod128                                                ),  // 0f 55 /r    andnps  xmm, xmm/m
     (fReg128 + fMod128                                                ),  // 0f 56 /r    orps    xmm, xmm/m
     (fReg128 + fMod128                                                ),  // 0f 57 /r    xorps   xmm, xmm/m
     (fReg128 + fMod128                                                ),  // 0f 58 /r    addps   xmm, xmm/m
     (fReg128 + fMod128                                                ),  // 0f 59 /r    mulps   xmm, xmm/m
     (fReg128 + fMod128                                                ),  // 0f 5a /r    cvtps2pd xmm, xmm/m
     (fReg128 + fMod128                                                ),  // 0f 5b /r    cvtdq2ps xmm, xmm/m
     (fReg128 + fMod128                                                ),  // 0f 5c /r    subps   xmm, xmm/m
     (fReg128 + fMod128                                                ),  // 0f 5d /r    minps   xmm, xmm/m
     (fReg128 + fMod128                                                ),  // 0f 5e /r    divps   xmm, xmm/m
     (fReg128 + fMod128                                                ),  // 0f 5f /r    maxps   xmm, xmm/m

     (fReg64  + fMod64  + f66RM                                        ),  // 0f 60 /r    punpcklbw mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f 61 /r    punpcklwd mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f 62 /r    punpckldq mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f 63 /r    packsswb mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f 64 /r    pcmpgtb mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f 65 /r    pcmpgtw mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f 66 /r    pcmpgtd mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f 67 /r    packuswb mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f 68 /r    punpckhbw mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f 69 /r    punpckhwd mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f 6a /r    punpckhdq mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f 6b /r    packssdw mm1, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f 6c /r    punpcklqdq xmm, xmm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f 6d /r    punpckhqdq xmm, xmm/m
     (fReg64  + fMod32  + f66R                                         ),  // 0f 6e /r    movd    mm, r/md
     (fReg64  + fMod64  + f66RM                                        ),  // 0f 6f /r    movq    mm, mm/m

     (fReg64  + fMod64  + f66RM +                 fI8                  ),  // 0f 70 /r ib pshufw  mm, mm/m, ib
     (fNoReg  + fMod64  + f66M  +                 fI8                  ),  // 0f 71 /x ib xxx     (x)mm, ib
     (fNoReg  + fMod64  + f66M  +                 fI8                  ),  // 0f 72 /x ib xxx     (x)mm, ib
     (fNoReg  + fMod64  + f66M  +                 fI8                  ),  // 0f 73 /x ib xxx     (x)mm, ib
     (fReg64  + fMod64  + f66RM                                        ),  // 0f 74 /r    pcmpeqb mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f 75 /r    pcmpeqw mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f 76 /r    pcmpeqd mm, mm/m
     (fNoReg                                                           ),  // 0f 77       emms
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fReg128 + fMod128 + f66RM                                        ),  // 0f 7c /r    haddpd  xmm, xmm/m
     (fReg128 + fMod128 + f66RM                                        ),  // 0f 7d /r    hsubpd  xmm, xmm/m
     (fReg64  + fMod32  + f66R  +        fOrder                        ),  // 0f 7e /r    movd    r/md, mm          (r)
     (fReg64  + fMod64  + f66RM +        fOrder                        ),  // 0f 7f /r    movq    mm/m, mm

     (FNoReg  +                                   fI32 + fJmpRel       ),  // 0f 80 c?    jo      relb
     (FNoReg  +                                   fI32 + fJmpRel       ),  // 0f 81 c?    jno     relb
     (FNoReg  +                                   fI32 + fJmpRel       ),  // 0f 82 c?    jb      relb
     (FNoReg  +                                   fI32 + fJmpRel       ),  // 0f 83 c?    jnb     relb
     (FNoReg  +                                   fI32 + fJmpRel       ),  // 0f 84 c?    jz      relb
     (FNoReg  +                                   fI32 + fJmpRel       ),  // 0f 85 c?    jnz     relb
     (FNoReg  +                                   fI32 + fJmpRel       ),  // 0f 86 c?    jbe     relb
     (FNoReg  +                                   fI32 + fJmpRel       ),  // 0f 87 c?    ja      relb
     (FNoReg  +                                   fI32 + fJmpRel       ),  // 0f 88 c?    js      relb
     (FNoReg  +                                   fI32 + fJmpRel       ),  // 0f 89 c?    jns     relb
     (FNoReg  +                                   fI32 + fJmpRel       ),  // 0f 8a c?    jp      relb
     (FNoReg  +                                   fI32 + fJmpRel       ),  // 0f 8b c?    jnp     relb
     (FNoReg  +                                   fI32 + fJmpRel       ),  // 0f 8c c?    jl      relb
     (FNoReg  +                                   fI32 + fJmpRel       ),  // 0f 8d c?    jge     relb
     (FNoReg  +                                   fI32 + fJmpRel       ),  // 0f 8e c?    jle     relb
     (FNoReg  +                                   fI32 + fJmpRel       ),  // 0f 8f c?    jg      relb

     (fNoReg  + fMod8   +         fPtr +                         fClrM ),  // 0f 90       seto    r/mb              (r)
     (fNoReg  + fMod8   +         fPtr +                         fClrM ),  // 0f 91       setno   r/mb              (r)
     (fNoReg  + fMod8   +         fPtr +                         fClrM ),  // 0f 92       setb    r/mb              (r)
     (fNoReg  + fMod8   +         fPtr +                         fClrM ),  // 0f 93       setae   r/mb              (r)
     (fNoReg  + fMod8   +         fPtr +                         fClrM ),  // 0f 94       sete    r/mb              (r)
     (fNoReg  + fMod8   +         fPtr +                         fClrM ),  // 0f 95       setne   r/mb              (r)
     (fNoReg  + fMod8   +         fPtr +                         fClrM ),  // 0f 96       setbe   r/mb              (r)
     (fNoReg  + fMod8   +         fPtr +                         fClrM ),  // 0f 97       seta    r/mb              (r)
     (fNoReg  + fMod8   +         fPtr +                         fClrM ),  // 0f 98       sets    r/mb              (r)
     (fNoReg  + fMod8   +         fPtr +                         fClrM ),  // 0f 99       setns   r/mb              (r)
     (fNoReg  + fMod8   +         fPtr +                         fClrM ),  // 0f 9a       setp    r/mb              (r)
     (fNoReg  + fMod8   +         fPtr +                         fClrM ),  // 0f 9b       setnp   r/mb              (r)
     (fNoReg  + fMod8   +         fPtr +                         fClrM ),  // 0f 9c       setl    r/mb              (r)
     (fNoReg  + fMod8   +         fPtr +                         fClrM ),  // 0f 9d       setge   r/mb              (r)
     (fNoReg  + fMod8   +         fPtr +                         fClrM ),  // 0f 9e       setle   r/mb              (r)
     (fNoReg  + fMod8   +         fPtr +                         fClrM ),  // 0f 9f       setg    r/mb              (r)

     (fNoReg                                                           ),  // 0f a0       push    fs
     (fNoReg                                                           ),  // 0f a1       pop     fs
     (fNoReg  +                                                  fClrA ),  // 0f a2       cpuid                     eax ebx ecx edx
     (fReg32  + fMod32  + f66RM +        fOrder                        ),  // 0f a3       bt      r/m?, r?
     (fReg32  + fMod32  + f66RM + fPtr + fOrder + fI8  +         fClrM ),  // 0f a4 ib    shld    r/m?, r?, ib      (r)
     (fReg32  + fMod32  + f66RM + fPtr + fOrder +                fClrM ),  // 0f a5       shld    r/m?, r?, cl      (r)
     (fReg8   + fMod8   +                fOrder +                fClrMA),  // 0f a6 /r    cmpxchg r/mb, rb          (r) eax
     (fReg32  + fMod32  + f66RM +        fOrder +                fClrMA),  // 0f a7 /r    cmpxchg r/m?, r?          (r) eax
     (fNoReg                                                           ),  // 0f a8       push    gs
     (fNoReg                                                           ),  // 0f a9       pop     gs
     (fNoReg                                                           ),  // 0f aa       rsm
     (fReg32  + fMod32  + f66RM +        fOrder +                fClrM ),  // 0f ab       bts     r/m?, r?          (r)
     (fReg32  + fMod32  + f66RM + fPtr + fOrder + fI8  +         fClrM ),  // 0f ac ib    shrd    r/m?, r?, ib      (r)
     (fReg32  + fMod32  + f66RM + fPtr + fOrder +                fClrM ),  // 0f ad       shrd    r/m?, r?, cl      (r)
     (fNoReg  + fMod32                                                 ),  // 0f ae /x    xxx     (m)
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f af /r    imul    r?, r/m?          r

     (fReg8   + fMod8   +                fOrder +                fClrMA),  // 0f b0 /r    cmpxchg r/mb, rb          (r) eax
     (fReg32  + fMod32  + f66RM +        fOrder +                fClrMA),  // 0f b1 /r    cmpxchg r/m?, r?          (r) eax
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f b2 /r    lss     r?, m16:?         r
     (fReg32  + fMod32  + f66RM +        fOrder +                fClrM ),  // 0f b3       btr     r/m?, r?          (r)
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f b4 /r    lfs     r?, m16:?         r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f b5 /r    lgs     r?, m16:?         r
     (fReg32  + fMod8   + f66R  + fPtr +                         fClrR ),  // 0f b6 /r    movzx   r?, r/mb          r
     (fReg32  + fMod16  + f66R  + fPtr +                         fClrR ),  // 0f b7 /r    movzx   rd, r/mw          r
     (fInvalid                                                         ),  // -----
     (fInvalid                                                         ),  // -----
     (fNoReg  + fMod32  + f66M  + fPtr +          fI8                  ),  // 0f ba /x ib btx     r/m?, ib          (r)  -  bt/bts/btr/btc
     (fReg32  + fMod32  + f66RM +        fOrder +                fClrM ),  // 0f bb       btc     r/m?, r?          (r)
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f bc       bsf     r?, r/m?          r
     (fReg32  + fMod32  + f66RM +                                fClrR ),  // 0f bd       bsr     r?, r/m?          r
     (fReg32  + fMod8   + f66R  + fPtr +                         fClrR ),  // 0f be /r    movsx   r?, r/mb          r
     (fReg32  + fMod16  + f66R  + fPtr +                         fClrR ),  // 0f bf /r    movsx   rd, r/mw          r

     (fReg8   + fMod8   +                fOrder +                fClrRM),  // 0f c0 /r    xadd    r/mb, rb          (r) r
     (fReg32  + fMod32  + f66RM +        fOrder +                fClrRM),  // 0f c1 /r    xadd    r/m?, r?          (r) r
     (fReg128 + fMod128 +                         fI8                  ),  // 0f c2 /r ib cmpps   xmm, xmm/m, ib
     (fReg32  + fMod32  +                fOrder                        ),  // 0f c3 /r    movnti  md, rd
     (fReg64  + fMod32  + f66R  +                 fI8                  ),  // 0f c4 /r ib pinsrw  mm, rd/mw, ib
     (fReg32  + fMod64  + f66M  +                 fI8  +         fClrR ),  // 0f c5 /r ib pextrw  rd, mm, ib        r
     (fReg128 + fMod128 +                         fI8                  ),  // 0f c6 /r ib shufps  xmm, xmm/m, ib
     (fNoReg  + fMod64  +         fPtr +                         fClrA ),  // 0f c7 /1 mq cmpxchg8b mq              edx eax
     (fRegO32 +                                                  fClrO ),  // 0f c8       bswap   (e)ax             r
     (fRegO32 +                                                  fClrO ),  // 0f c9       bswap   (e)cx             r
     (fRegO32 +                                                  fClrO ),  // 0f ca       bswap   (e)dx             r
     (fRegO32 +                                                  fClrO ),  // 0f cb       bswap   (e)bx             r
     (fRegO32 +                                                  fClrO ),  // 0f cc       bswap   (e)sp             r
     (fRegO32 +                                                  fClrO ),  // 0f cd       bswap   (e)bp             r
     (fRegO32 +                                                  fClrO ),  // 0f ce       bswap   (e)si             r
     (fRegO32 +                                                  fClrO ),  // 0f cf       bswap   (e)di             r

     (fReg128 + fMod128 + f66RM                                        ),  // 0f d0 /r    addsubpd xmm, xmm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f d1 /r    psrlw   mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f d2 /r    psrld   mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f d3 /r    psrlq   mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f d4 /r    paddq   mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f d5 /r    pmullw  mm, mm/m
     (fReg64  + fMod64  + f66RM +        fOrder                        ),  // 0f d6 /r    movq    xmm/m, xmm
     (fReg32  + fMod64  + f66M  +                                fClrR ),  // 0f d7 /r    pmovmskb rd, mm           r
     (fReg64  + fMod64  + f66RM                                        ),  // 0f d8 /r    psubusb mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f d9 /r    psubusw mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f da /r    pminub  mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f db /r    pand    mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f dc /r    paddusb mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f dd /r    paddusw mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f de /r    pmaxub  mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f df /r    pandn   mm, mm/m

     (fReg64  + fMod64  + f66RM                                        ),  // 0f e0 /r    pavgb   mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f e1 /r    psraw   mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f e2 /r    psrad   mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f e3 /r    pavgw   mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f e4 /r    pmulhuw mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f e5 /r    pmulhw  mm, mm/m
     (fReg128 + fMod128                                                ),  // 0f e6 /r    cvttpd2dq xmm, xmm/m
     (fReg64  + fMod64  + f66RM +        fOrder                        ),  // 0f e7 /r    movntq  m, mm
     (fReg64  + fMod64  + f66RM                                        ),  // 0f e8 /r    psubsb  mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f e9 /r    psubsw  mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f ea /r    pminsw  mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f eb /r    por     mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f ec /r    paddsb  mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f ed /r    paddsw  mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f ee /r    pmaxsw  mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f ef /r    pxor    mm, mm/m

     (fReg128 + fMod128                                                ),  // 0f f0 /r    lddqu   xmm, m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f f1 /r    psllw   mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f f2 /r    pslld   mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f f3 /r    psllq   mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f f4 /r    pmuludq mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f f5 /r    pmaddwd mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f f6 /r    psadbw  mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f f7 /r    maskmovq mm, mm
     (fReg64  + fMod64  + f66RM                                        ),  // 0f f8 /r    psubb   mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f f9 /r    psubw   mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f fa /r    psubd   mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f fb /r    psubq   mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f fc /r    paddb   mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f fd /r    paddw   mm, mm/m
     (fReg64  + fMod64  + f66RM                                        ),  // 0f fe /r    paddd   mm, mm/m
     (fNoReg                                                           )); // -----

  // flags for some opcodes which differ a lot depending on the modrm byte
  COpcodeFlagsEx : array [0..9] of record
              opcode : byte;
              flags  : array [0..15] of word;
            end =
    ((opcode : $f6;
      flags  : (fNoReg + fMod8 + fPtr + fI8,                               // f6 /0 ib    test    r/mb, ib
                fInvalid,                                                  // -----
                fNoReg + fMod8 + fPtr + fClrM,                             // f6 /2       not     r/mb              (r)
                fNoReg + fMod8 + fPtr + fClrM,                             // f6 /3       neg     r/mb              (r)
                fNoReg + fMod8 + fPtr + fClrA,                             // f6 /4       mul     r/mb              eax
                fNoReg + fMod8 + fPtr + fClrA,                             // f6 /5       imul    r/mb              eax
                fNoReg + fMod8 + fPtr + fClrA,                             // f6 /6       div     r/mb              eax
                fNoReg + fMod8 + fPtr + fClrA,                             // f6 /7       idiv    r/mb              eax
                fNoReg + fMod8 + fPtr + fI8,
                fInvalid,
                fNoReg + fMod8 + fPtr + fClrM,
                fNoReg + fMod8 + fPtr + fClrM,
                fNoReg + fMod8 + fPtr + fClrA,
                fNoReg + fMod8 + fPtr + fClrA,
                fNoReg + fMod8 + fPtr + fClrA,
                fNoReg + fMod8 + fPtr + fClrA)),
     (opcode : $f7;
      flags  : (fNoReg + fMod32 + f66M + fPtr + fI32,                      // f7 /0 i?    test    r/m?, i?
                fInvalid,                                                  // -----
                fNoReg + fMod32 + f66M + fPtr + fClrM,                     // f7 /2       not     r/m?              (r)
                fNoReg + fMod32 + f66M + fPtr + fClrM,                     // f7 /3       neg     r/m?              (r)
                fNoReg + fMod32 + f66M + fPtr + fClrA,                     // f7 /4       mul     r/m?              eax edx
                fNoReg + fMod32 + f66M + fPtr + fClrA,                     // f7 /5       imul    r/m?              eax edx
                fNoReg + fMod32 + f66M + fPtr + fClrA,                     // f7 /6       div     r/m?              eax edx
                fNoReg + fMod32 + f66M + fPtr + fClrA,                     // f7 /7       idiv    r/m?              eax edx
                fNoReg + fMod32 + f66M + fPtr + fI32,
                fInvalid,
                fNoReg + fMod32 + f66M + fPtr + fClrM,
                fNoReg + fMod32 + f66M + fPtr + fClrM,
                fNoReg + fMod32 + f66M + fPtr + fClrA,
                fNoReg + fMod32 + f66M + fPtr + fClrA,
                fNoReg + fMod32 + f66M + fPtr + fClrA,
                fNoReg + fMod32 + f66M + fPtr + fClrA)),
     (opcode : $d8;
      flags  : (fNoReg + fMod32 + fPtr,                                    // d8 /0       fadd    mdreal
                fNoReg + fMod32 + fPtr,                                    // d8 /1       fmul    mdreal
                fNoReg + fMod32 + fPtr,                                    // d8 /2       fcom    mdreal
                fNoReg + fMod32 + fPtr,                                    // d8 /3       fcomp   mdreal
                fNoReg + fMod32 + fPtr,                                    // d8 /4       fsub    mdreal
                fNoReg + fMod32 + fPtr,                                    // d8 /5       fsubr   mdreal
                fNoReg + fMod32 + fPtr,                                    // d8 /6       fdiv    mdreal
                fNoReg + fMod32 + fPtr,                                    // d8 /7       fdivr   mdreal
                fRegSt + fMod80,                                           // d8 c0+i     fadd    st(0), st(i)
                fRegSt + fMod80,                                           // d8 c8+i     fmul    st(0), st(i)
                fNoReg + fMod80,                                           // d8 d0+i     fcom    st(i)
                fNoReg + fMod80,                                           // d8 d8+i     fcomp   st(i)
                fRegSt + fMod80,                                           // d8 e0+i     fsub    st(0), st(i)
                fRegSt + fMod80,                                           // d8 e8+i     fsubr   st(0), st(i)
                fRegSt + fMod80,                                           // d8 f0+i     fdiv    st(0), st(i)
                fRegSt + fMod80)),                                         // d8 f8+i     fdivr   st(0), st(i)
     (opcode : $d9;
      flags  : (fNoReg + fMod32 + fPtr,                                    // d9 /0       fld     mdreal
                fInvalid,                                                  // -----
                fNoReg + fMod32 + fPtr,                                    // d9 /2       fst     mdreal
                fNoReg + fMod32 + fPtr,                                    // d9 /3       fstp    mdreal
                fNoReg + fMod8  + fPtr,                                    // d9 /4       fldenv  m14/28byte
                fNoReg + fMod16 + fPtr,                                    // d9 /5       fldcw   m2byte
                fNoReg + fMod8  + fPtr,                                    // d9 /6       fnstenv m14/28byte
                fNoReg + fMod16 + fPtr,                                    // d9 /7       fnstcw  m2byte
                fNoReg + fMod80,                                           // d9 c0+i     fld     st(i)
                fNoReg + fMod80,                                           // d9 c8+i     fxch    st(i)
                fNoReg,                                                    // d9 d0       fnop
                fNoReg + fMod80,                                           // d9 d8+i     fstp1   st(i)
                fNoReg,                                                    // d9 e0       fxxx
                fNoReg,                                                    // d9 e8       fxxx
                fNoReg,                                                    // d9 f0       fxxx
                fNoReg)),                                                  // d9 f8       fxxx
     (opcode : $da;
      flags  : (fNoReg + fMod32 + fPtr,                                    // da /0       fiadd   mdint
                fNoReg + fMod32 + fPtr,                                    // da /1       fimul   mdint
                fNoReg + fMod32 + fPtr,                                    // da /2       ficom   mdint
                fNoReg + fMod32 + fPtr,                                    // da /3       ficomp  mdint
                fNoReg + fMod32 + fPtr,                                    // da /4       fisub   mdint
                fNoReg + fMod32 + fPtr,                                    // da /5       fisubr  mdint
                fNoReg + fMod32 + fPtr,                                    // da /6       fidiv   mdint
                fNoReg + fMod32 + fPtr,                                    // da /7       fidivr  mdint
                fRegSt + fMod80,                                           // da c0+i     fcmovb  st(0), st(i)
                fRegSt + fMod80,                                           // da c8+i     fcmove  st(0), st(i)
                fRegSt + fMod80,                                           // da d0+i     fcmovbe st(0), st(i)
                fRegSt + fMod80,                                           // da d8+i     fcmovu  st(0), st(i)
                fInvalid,                                                  // -----
                fNoReg,                                                    // da e9       fucompp
                fInvalid,                                                  // -----
                fInvalid)),                                                // -----
     (opcode : $db;
      flags  : (fNoReg + fMod32 + fPtr,                                    // db /0       fild    mdint
                fNoReg + fMod32 + fPtr,                                    // db /1       fisttp  mdint
                fNoReg + fMod32 + fPtr,                                    // db /2       fist    mdint
                fNoReg + fMod32 + fPtr,                                    // db /3       fistp   mdint
                fInvalid,                                                  // -----
                fNoReg + fMod80 + fPtr,                                    // db /5       fld     m80real
                fInvalid,                                                  // -----
                fNoReg + fMod80 + fPtr,                                    // db /7       fstp    m80real
                fRegSt + fMod80,                                           // db c0+i     fcmovnb st(0), st(i)
                fRegSt + fMod80,                                           // db c8+i     fcmovne st(0), st(i)
                fRegSt + fMod80,                                           // db d0+i     fcmovnbe st(0), st(i)
                fRegSt + fMod80,                                           // db d8+i     fcmovnu st(0), st(i)
                fNoReg,                                                    // db e0       fxxx
                fRegSt + fMod80,                                           // db e8+i     fucomi  st(0), st(i)
                fRegSt + fMod80,                                           // db f0+i     fcomi   st(0), st(i)
                fInvalid)),                                                // -----
     (opcode : $dc;
      flags  : (fNoReg + fMod64 + fPtr,                                    // dc /0       fadd    mqreal
                fNoReg + fMod64 + fPtr,                                    // dc /1       fmul    mqreal
                fNoReg + fMod64 + fPtr,                                    // dc /2       fcom    mqreal
                fNoReg + fMod64 + fPtr,                                    // dc /3       fcomp   mqreal
                fNoReg + fMod64 + fPtr,                                    // dc /4       fsub    mqreal
                fNoReg + fMod64 + fPtr,                                    // dc /5       fsubr   mqreal
                fNoReg + fMod64 + fPtr,                                    // dc /6       fdiv    mqreal
                fNoReg + fMod64 + fPtr,                                    // dc /7       fdivr   mqreal
                fRegSt + fMod80 + fOrder,                                  // dc c0+i     fadd    st(i), st(0)
                fRegSt + fMod80 + fOrder,                                  // dc c8+i     fmul    st(i), st(0)
                fNoReg + fMod80,                                           // dc d0+i     fcom    st(i)
                fNoReg + fMod80,                                           // dc d8+i     fcomp   st(i)
                fRegSt + fMod80 + fOrder,                                  // dc e0+i     fsubr   st(i), st(0)
                fRegSt + fMod80 + fOrder,                                  // dc e8+i     fsub    st(i), st(0)
                fRegSt + fMod80 + fOrder,                                  // dc f0+i     fdivr   st(i), st(0)
                fRegSt + fMod80 + fOrder)),                                // dc f8+i     fdiv    st(i), st(0)
     (opcode : $dd;
      flags  : (fNoReg + fMod64 + fPtr,                                    // dd /0       fld     mqreal
                fNoReg + fMod64 + fPtr,                                    // dd /1       fisttp  mqreal
                fNoReg + fMod64 + fPtr,                                    // dd /2       fst     mqreal
                fNoReg + fMod64 + fPtr,                                    // dd /3       fstp    mqreal
                fNoReg + fMod8  + fPtr,                                    // dd /4       frstor  m94/108byte
                fInvalid,                                                  // -----
                fNoReg + fMod8  + fPtr,                                    // dd /6       fnsave  m94/108byte
                fNoReg + fMod16 + fPtr,                                    // dd /7       fnstsw  m2byte
                fNoReg + fMod80,                                           // dd c0+i     ffree   st(i)
                fNoReg + fMod80,                                           // dd c8+i     xch4    st(i)
                fNoReg + fMod80,                                           // dd d0+i     fst     st(i)
                fNoReg + fMod80,                                           // dd d8+i     fstp    st(i)
                fNoReg + fMod80,                                           // dd e0+i     fucom   st(i)
                fNoReg + fMod80,                                           // dd e8+i     fucomp  st(i)
                fInvalid,                                                  // -----
                fInvalid)),                                                // -----
     (opcode : $de;
      flags  : (fNoReg + fMod16 + fPtr,                                    // de /0       fiadd   mwint
                fNoReg + fMod16 + fPtr,                                    // de /1       fimul   mwint
                fNoReg + fMod16 + fPtr,                                    // de /2       ficom   mwint
                fNoReg + fMod16 + fPtr,                                    // de /3       ficomp  mwint
                fNoReg + fMod16 + fPtr,                                    // de /4       fisub   mwint
                fNoReg + fMod16 + fPtr,                                    // de /5       fisubr  mwint
                fNoReg + fMod16 + fPtr,                                    // de /6       fidiv   mwint
                fNoReg + fMod16 + fPtr,                                    // de /7       fidivr  mwint
                fRegSt + fMod80 + fOrder,                                  // de c0+i     faddp   st(i), st(0)
                fRegSt + fMod80 + fOrder,                                  // de c8+i     fmulp   st(i), st(0)
                fNoReg + fMod80,                                           // de c0+i     fcomp5  st(i)
                fRegSt + fMod80 + fOrder,                                  // de d8+i     fcompp  st(i), st(0)
                fRegSt + fMod80 + fOrder,                                  // de e0+i     fsubrp  st(i), st(0)
                fRegSt + fMod80 + fOrder,                                  // de e8+i     fsubp   st(i), st(0)
                fRegSt + fMod80 + fOrder,                                  // de f0+i     fdivrp  st(i), st(0)
                fRegSt + fMod80 + fOrder)),                                // de f8+i     fdivp   st(i), st(0)
     (opcode : $df;
      flags  : (fNoReg + fMod16 + fPtr,                                    // df /0       fild    mwint
                fNoReg + fMod16 + fPtr,                                    // df /1       fisttp  mwint
                fNoReg + fMod16 + fPtr,                                    // df /2       fist    mwint
                fNoReg + fMod16 + fPtr,                                    // df /3       fistp   mwint
                fNoReg + fMod80 + fPtr,                                    // df /4       fbld    m80dec
                fNoReg + fMod64 + fPtr,                                    // df /5       fild    mqint
                fNoReg + fMod80 + fPtr,                                    // df /6       fbstp   m80bcd
                fNoReg + fMod64 + fPtr,                                    // df /7       fistp   mqint
                fNoReg + fMod80,                                           // df c0+i     ffreep  st(i)
                fNoReg + fMod80,                                           // df c8+i     fxch7   st(i)
                fNoReg + fMod80,                                           // df d0+i     fstp8   st(i)
                fNoReg + fMod80,                                           // df d8+i     fstp9   st(i)
                fNoReg,                                                    // df e0       fnstsw  ax                eax
                fRegSt + fMod80,                                           // df e8+i     fucomip st(0), st(i)
                fRegSt + fMod80,                                           // df f0+i     fcomip  st(0), st(i)
                fInvalid)));                                               // -----

  // register labels (byte/word/segment/dword)
  CRegLabels : array [1..{$ifdef amd64}6, 0..15{$else}4, 0..7{$endif}] of pchar =
    (( 'al',  'cl',  'dl',  'bl',  'ah',  'ch',  'dh',  'bh' {$ifdef amd64}, 'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b' {$endif}),
     ( 'ax',  'cx',  'dx',  'bx',  'sp',  'bp',  'si',  'di' {$ifdef amd64}, 'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w' {$endif}),
     ( 'es',  'cs',  'ss',  'ds',  'fs',  'gs',   nil,   nil {$ifdef amd64},   nil,   nil,    nil,    nil,    nil,    nil,    nil,    nil {$endif}),
     ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi' {$ifdef amd64}, 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d' {$endif})
     {$ifdef amd64},
       ('rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi' {$ifdef amd64}, 'r8',  'r9',  'r10',  'r11',  'r12',  'r13',  'r14',  'r15'  {$endif}),
       ( 'al',  'cl',  'dl',  'bl', 'spl', 'bpl', 'sil', 'dil' {$ifdef amd64},  nil,   nil,    nil,    nil,    nil,    nil,    nil,    nil  {$endif})
     {$endif}
    );

  // conditional labels (%cc)
  Ccc = 'o|no|b|nb|z|nz|be|a|s|ns|p|np|l|ge|le|g';

  // opcode labels (one byte + two byte + mmx/sse/sse2)
  COpcodeLabels =
       'aaa'       +#0'aad'      +#0'aam'      +#0'aas'      +#0'adc'      +#0'add'       +#0'addPS'    +#0'and'
    {$ifdef amd64}
      +#0'andnPS'    +#0'movsxd'   +#0'bound'    +#0'bsf'      +#0'bsr'      +#0'bswap'     +#0'bt'       +#0'btc'
    {$else}
      +#0'andnPS'    +#0'arpl'     +#0'bound'    +#0'bsf'      +#0'bsr'      +#0'bswap'     +#0'bt'       +#0'btc'
    {$endif}
    +#0'btr'       +#0'bts'      +#0'call'     +#0'clc'      +#0'cld'      +#0'cli'       +#0'clts'     +#0'cmc'
    +#0'cmov%cc'   +#0'cmp'      +#0'cmpPS'    +#0'cmpsb'    +#0'cmpxchg'  +#0'cmpxchg8b' +#0'comisS'   +#0'cpuid'
    +#0'cvtPi2PS'  +#0'cvtPS2Pi' +#0'cvttPS2Pi'+#0'daa'      +#0'das'      +#0'dec'       +#0'divPS'    +#0'emms'
    +#0'enter'     +#0'femms'    +#0'hlt'      +#0'imul'     +#0'in'       +#0'inc'       +#0'insb'     +#0'int'
    +#0'int     3' +#0'int01'    +#0'into'     +#0'invd'     +#0'iret'     +#0'j%cc'      +#0'jecxz'    +#0'jmp'
    +#0'lahf'      +#0'lar'      +#0'lds'      +#0'lea'      +#0'leave'    +#0'les'       +#0'lfs'      +#0'lgs'
    +#0'sysret'    +#0'lodsb'    +#0'loop'     +#0'loope'    +#0'loopne'   +#0'lsl'       +#0'lss'      +#0'maxPS'
    +#0'minPS'     +#0'mov'      +#0'movaPS'   +#0'movd'     +#0'movhPS'   +#0'movlPS'    +#0'movmskPS' +#0'movnti'
    +#0'movntPS'   +#0'movsb'    +#0'movsx'    +#0'movzx'    +#0'mulPS'    +#0'nop'       +#0'or'       +#0'orPS'
    +#0'out'       +#0'outsb'    +#0'packssdw' +#0'packsswb' +#0'packuswb' +#0'paddb'     +#0'paddd'    +#0'paddq'
    +#0'paddsb'    +#0'paddsw'   +#0'paddusb'  +#0'paddusw'  +#0'paddw'    +#0'pand'      +#0'pandn'    +#0'pavgb'
    +#0'pavgw'     +#0'pcmpeqb'  +#0'pcmpeqd'  +#0'pcmpeqw'  +#0'pcmpgtb'  +#0'pcmpgtd'   +#0'pcmpgtw'  +#0'pextrw'
    +#0'pinsrw'    +#0'pmaddwd'  +#0'pmaxsw'   +#0'pmaxub'   +#0'pminsw'   +#0'pminub'    +#0'pmovmskb' +#0'pmulhuw'
    +#0'pmulhw'    +#0'pmullw'   +#0'pmuludq'  +#0'pop'      +#0'por'      +#0'psadbw'    +#0'pslld'    +#0'psllq'
    +#0'psllw'     +#0'psrad'    +#0'psraw'    +#0'psrld'    +#0'psrlq'    +#0'psrlw'     +#0'psubb'    +#0'psubd'
    +#0'psubq'     +#0'psubsb'   +#0'psubsw'   +#0'psubusb'  +#0'psubusw'  +#0'psubw'     +#0'punpckhbw'+#0'punpckhdq'
    +#0'punpckhqdq'+#0'punpckhwd'+#0'punpcklbw'+#0'punpckldq'+#0'punpcklwd'+#0'punpcklqdq'+#0'push'     +#0'pxor'
    +#0'rcpPS'     +#0'rdmsr'    +#0'rdpmc'    +#0'rdtsc'    +#0'ret'      +#0'rsm'       +#0'rsqrtPS'  +#0'sahf'
    +#0'salc'      +#0'sbb'      +#0'scasb'    +#0'set%cc'   +#0'shld'     +#0'shrd'      +#0'shufPS'   +#0'sqrtPS'
    +#0'stc'       +#0'std'      +#0'sti'      +#0'stosb'    +#0'sub'      +#0'subPS'     +#0'syscall'  +#0'sysenter'
    +#0'sysexit'   +#0'test'     +#0'ucomisS'  +#0'unpckhPS' +#0'unpcklPS' +#0'wait'      +#0'wbinvd'   +#0'wrmsr'
    +#0'xadd'      +#0'xchg'     +#0'xlat'     +#0'xor'      +#0'xorPS'
    +#0'cwde/cbw'     +#0'cdq/cwd'         +#0'pop     %seg'           +#0'popad/popa'
    {$ifdef amd64}
      +#0'popfq/popf'   +#0'push    %seg'    +#0'pushad/pusha'           +#0'pushfq/pushf'
    {$else}
      +#0'popfd/popf'   +#0'push    %seg'    +#0'pushad/pusha'           +#0'pushfd/pushf'
    {$endif}
    +#0'outsd/outsw'  +#0'insd/insw'       +#0'movsd/movsw'            +#0'cmpsd/cmpsw'
    +#0'lodsd/lodsw'  +#0'stosd/stosw'     +#0'scasd/scasw'            +#0'maskmovq/maskmovdqu'
    +#0'movd///movq'  +#0'movntq/movntdq'  +#0'movq//movdq2q/movq2dq'  +#0'movq/movdqa//movdqu'
    +#0'movuPS//movPS/movPS'                    +#0'prefetch|prefetchw'
    +#0'pshufw/pshufd/pshuflw/pshufhw'          +#0'sgdt|sidt|lgdt|lidt|smsw||lmsw|invlpg'
    +#0'sldt|str|lldt|ltr|verr|verw'            +#0'||||bt|bts|btr|btc'
    +#0'||psrld||psrad||pslld'                  +#0'||psrlq|psrldq|||psllq|pslldq'
    +#0'||psrlw||psraw||psllw'                  +#0'cvtdq2ps/cvtps2dq//cvttps2dq'
    +#0'cvtPs2Pd/cvtPd2Ps/cvtPd2Ps'             +#0'cvttpd2dq//cvtpd2dq/cvtdq2pd'
    +#0'add|or|adc|sbb|and|sub|xor|cmp'         +#0'inc|dec|call|call|jmp|jmp|push'
    +#0'rol|ror|rcl|rcr|shl|shr|sal|sar'        +#0'test||not|neg|mul|imul|div|idiv'
    +#0'add|mul|com|comp|sub|subr|div|divr|add|mul|com|comp|subr|sub|divr|div'
    +#0'movhlPS:movlPS/movlPS/movddup/movsldup'
    +#0'movlhPS:movhPS/movhPS/movlhPS:movhPS/movshdup'
    +#0'prefetchnta|prefetcht0|prefetcht1|prefetcht2|prefetcht3'
    +#0'fxsave|fxrstor|ldmxcsr|stmxcsr||lfence|mfence|sfence:clflush'
    +#0'ld||st|stp|ldenv|ldcw|nstenv|nstcw|ld|xch|nop|stp1|chs-abs---tst-xam|' +
       'ld1-ldl2t-ldl2e-ldpi-ldlg2-ldln2-ldz|2xm1-yl2x-ptan-patan-xtract-prem1-decstp-incstp|' +
       'prem-yl2xp1-sqrt-sincos-rndint-scale-sin-cos'
    +#0'iadd|imul|icom|icomp|isub|isubr|idiv|idivr|cmovb|cmove|cmovbe|cmovu||ucompp'
    +#0'ild|isttp|ist|istp||ld||stp|cmovnb|cmovne|cmovnbe|cmovnu|neni-ndisi-nclex-ninit-nsetpm|ucomi|comi'
    +#0'ld|isttp|st|stp|rstor||nsave|nstsw|free|xch4|st|stp|ucom|ucomp'
    +#0'iadd|imul|icom|icomp|isub|isubr|idiv|idivr|addp|mulp|comp5|compp|subrp|subp|divrp|divp'
    +#0'ild|isttp|ist|istp|bld|ild|bstp|istp|freep|xch7|stp8|stp9|nstsw  ax|ucomip|comip'
    +#0'andPS'
    +#0'addsubpd' // 'addsubpd/addsubpd/addsubps'
    +#0'haddpd'   // 'haddpd/haddpd/haddps'
    +#0'hsubpd'   // 'hsubpd/hsubpd/hsubps'
    +#0'lddqu';   // 'lddqu//lddqu';

  // 3dnow opcode labels
  C3dNowLabels =
     #0#$0c'pi2fw'    +#0#$0d'pi2fd'   +#0#$1c'pf2iw'    +#0#$1d'pf2id'
    +#0#$8a'pfnacc'   +#0#$8e'pfpnacc' +#0#$90'pfcmpge'  +#0#$94'pfmin'
    +#0#$96'pfrcp'    +#0#$97'pfrsqrt' +#0#$9a'pfsub'    +#0#$9e'pfadd'
    +#0#$a0'pfcmpgt'  +#0#$a4'pfmax'   +#0#$a6'pfrcpit1' +#0#$a7'pfrsqit1'
    +#0#$aa'pfsubr'   +#0#$ae'pfacc'   +#0#$b0'pfcmpeq'  +#0#$b4'pfmul'
    +#0#$b6'pfrcpit2' +#0#$b7'pmulhrw' +#0#$bb'pswapd'   +#0#$bf'pavgusb';

  // one byte opcode index into opcode label array
  COpcodeLabelIndex : array [$00..$ff] of byte =
    ($06, $06, $06, $06, $06, $06, $c3, $c0, $57, $57, $57, $57, $57, $57, $c3, $00,
     $05, $05, $05, $05, $05, $05, $c3, $c0, $a2, $a2, $a2, $a2, $a2, $a2, $c3, $c0,
     $08, $08, $08, $08, $08, $08, $00, $24, $ad, $ad, $ad, $ad, $ad, $ad, $00, $25,
     $bc, $bc, $bc, $bc, $bc, $bc, $00, $01, $1a, $1a, $1a, $1a, $1a, $1a, $00, $04,
     $2e, $2e, $2e, $2e, $2e, $2e, $2e, $2e, $26, $26, $26, $26, $26, $26, $26, $26,
     $97, $97, $97, $97, $97, $97, $97, $97, $7c, $7c, $7c, $7c, $7c, $7c, $7c, $7c,
     $c4, $c1, $0b, $0a, $00, $00, $00, $00, $97, $2c, $97, $2c, $2f, $c7, $5a, $c6,
     $36, $36, $36, $36, $36, $36, $36, $36, $36, $36, $36, $36, $36, $36, $36, $36,
     $de, $de, $de, $de, $b2, $b2, $ba, $ba, $4a, $4a, $4a, $4a, $4a, $3c, $4a, $7c,
     $56, $ba, $ba, $ba, $ba, $ba, $ba, $ba, $be, $bf, $13, $b6, $c5, $c2, $a0, $39,
     $4a, $4a, $4a, $4a, $52, $c8, $1c, $c9, $b2, $b2, $ac, $cb, $42, $ca, $a3, $cc,
     $4a, $4a, $4a, $4a, $4a, $4a, $4a, $4a, $4a, $4a, $4a, $4a, $4a, $4a, $4a, $4a,
     $e0, $e0, $9d, $9d, $3e, $3b, $4a, $4a, $29, $3d, $9d, $9d, $31, $30, $33, $35,
     $e0, $e0, $e0, $e0, $03, $02, $a1, $bb, $e2, $e7, $e8, $e9, $e2, $ea, $eb, $ec,
     $45, $44, $43, $37, $2d, $2d, $59, $59, $13, $38, $38, $38, $2d, $2d, $59, $59,
     $00, $32, $00, $00, $2b, $18, $e1, $e1, $14, $a9, $16, $ab, $15, $aa, $df, $df);

  // two byte ($0f $xx) opcode index into opcode label array
  COpcodeLabelIndex0f : array [$00..$ff] of byte =
    ($d6, $d5, $3a, $46, $00, $af, $17, $41, $34, $b7, $00, $00, $00, $d3, $2a, $00,
     $d2, $d2, $e3, $4e, $b5, $b4, $e4, $4d, $e5, $00, $00, $00, $00, $00, $00, $00,
     $4a, $4a, $4a, $4a, $00, $00, $00, $00, $4b, $4b, $21, $51, $23, $22, $b3, $1f,
     $b8, $9c, $9a, $9b, $b0, $b1, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00,
     $19, $19, $19, $19, $19, $19, $19, $19, $19, $19, $19, $19, $19, $19, $19, $19,
     $4f, $a8, $9f, $99, $ed, $09, $58, $bd, $07, $55, $dc, $db, $ae, $49, $27, $48,
     $93, $95, $94, $5c, $6d, $6f, $6e, $5d, $8f, $92, $90, $5b, $96, $91, $4c, $d1,
     $d4, $da, $d8, $d9, $6a, $6c, $6b, $28, $00, $00, $00, $00, $ef, $f0, $ce, $d1,
     $36, $36, $36, $36, $36, $36, $36, $36, $36, $36, $36, $36, $36, $36, $36, $36,
     $a4, $a4, $a4, $a4, $a4, $a4, $a4, $a4, $a4, $a4, $a4, $a4, $a4, $a4, $a4, $a4,
     $c3, $c0, $20, $0f, $a5, $a5, $1d, $1d, $c3, $c0, $9e, $12, $a6, $a6, $e6, $2c,
     $1d, $1d, $47, $11, $3f, $40, $54, $54, $00, $00, $d7, $10, $0c, $0d, $53, $53,
     $b9, $b9, $1b, $50, $71, $70, $a7, $1e, $0e, $0e, $0e, $0e, $0e, $0e, $0e, $0e,
     $ee, $86, $84, $85, $60, $7a, $d0, $77, $8c, $8d, $76, $66, $63, $64, $74, $67,
     $68, $83, $82, $69, $78, $79, $dd, $cf, $8a, $8b, $75, $7d, $61, $62, $73, $98,
     $f1, $81, $7f, $80, $7b, $72, $7e, $cd, $87, $8e, $88, $89, $5e, $65, $5f, $00);

type
  // reg state
  TRegState = array [0..{$ifdef amd64}15{$else}7{$endif}] of pointer;
  TPRegState = ^TRegState;

function ParseCode(code         : pointer;
                   var prfxSeg  : byte;     // 26, 2e, 36, 3e, 64..65 segment override prefix
                   var prfx66   : boolean;  // 66 - operand size prefix
                   var prfx67   : boolean;  // 67 - address size prefix
                   var prfxF0   : boolean;  // f0 - lock prefix
                   var prfxF2   : boolean;  // f2 - repne (or sse2 special size) prefix
                   var prfxF3   : boolean;  // f3 - rep   (or sse2 special size) prefix
                   {$ifdef amd64}
                     var prfxRex  : byte;     // 40..4f - REX prefix
                   {$endif}
                   var opcode   : word;     // instruction opcode, one or two bytes
                   var flgs     : dword;    // flags from one of the const flag tables
                   var labelIdx : integer;  // label index
                   var modRm    : byte;     // modrm byte
                   var sib      : byte;     // sib byte
                   var regPtr   : boolean;  // do the modrm reg/mem bits address a register?
                   var reg      : integer;  // modrm reg/mem bits
                   var multi    : integer;  // modrm multi purpose bits
                   var regScale : integer;  // sib scale register
                   var scale    : integer;  // sib scale factor
                   var dispSize : integer;  // size of displacement data
                   var dispp    : pointer;  // at which address is the displacement data stored?
                   var dispi    : integer;  // displacement data in integer form
                   var dispc    : dword;    // displacement data in dword   form
                   var imLen    : integer;  // size of immediate data
                   {$ifdef amd64}           // immediate value (in integer form, if available)
                     var imVal    : int64;
                   {$else}
                     var imVal    : integer;
                   {$endif}
                   var dw       : integer;  // 4 or 2, depending on the operand size prefix
                   regState     : TPRegState;
                   useRegState  : boolean;
                   tryRead_     : dword     ) : TCodeInfo; overload;

  function CheckPrefix : boolean;
  // strip off all prefixes and react on the important ones
  begin
    result := true;
    case opcode of
      {$ifdef amd64}
        $40..$4f : prfxRex := opcode;
      {$endif}
      $66 : begin
              prfx66 := true;
              // operand size prefix found, so we're working with words now
              dw := 2;
            end;
      $67 : prfx67 := true;
      $f0 : prfxF0 := true;
      $f2 : begin
              prfxF2 := true;
              // f2 is only "repne" in one byte opcodes
              // in two byte opcodes it is used as a special size flag for sse2
              if byte(code^) <> $0f then
                // "repne" usually changes the ecx register
                if regState <> nil then
                  regState^[1] := nil;
            end;
      $f3 : begin
              prfxF3 := true;
              // f3 is only "rep" in one byte opcodes
              // in two byte opcodes it is used as a special size flag for sse2
              if byte(code^) <> $0f then
                // "rep" usually changes the ecx register
                if regState <> nil then
                  regState^[1] := nil;
            end;
      else  // $26, $2e, $36, $3e and $64..$65 are segment override prefixes
            if opcode and $E7 = $26 then
              prfxSeg := (opcode shr 3) and $3 + 1
            else
              if opcode in [$64..$65] then
                prfxSeg := opcode - $60 + 1
              else
                result := false;
    end;
  end;

  procedure ParseModRm;
  // parse the modrm byte (plus the sib byte, if available)
  begin
    modRm  := byte(code^);
    sib    := 0;
    regPtr := modRm and $c0 <> $c0;
    reg    := modRm and $7;
    multi  := (modRm shr 3) and $7;
    scale  := 0;
    inc(dword(code));
    case modRm and $c0 of
      $40 : dispSize := 1;
      $80 : {$ifndef amd64}
              if prfx67 then
                dispSize := 2
              else
            {$endif}
              dispSize := 4;
      else  dispSize := 0;
    end;
    {$ifndef amd64}
      if regPtr and prfx67 then begin
        // the address size prefix has serious effect on modrm pointers
        if (reg >= 0) and (reg <= 3) then begin
          regScale := 6 + reg and 1;
          scale := 1;
        end;
        if (modRm and $c0 = 0) and (reg = 6) then begin
          dispSize := 2;
          reg := -1;
        end else
          case reg of
            0, 1, 7 : reg := 3;
            2, 3, 6 : reg := 5;
            4       : reg := 6;
            5       : reg := 7;
          end;
      end else begin
    {$endif}
      if (reg = 4) and regPtr then begin
        // there's also a sib byte, so let's parse it, too
        sib := byte(code^);
        inc(dword(code));
        reg := sib and $7;
        if (sib and $38 <> $20) {$ifdef amd64} or (prfxRex and $2 <> 0) {$endif} then begin
          scale := 1 shl (sib shr 6);
          regScale := (sib shr 3) and $7;
        end;
      end;
      if (modRm and $c0 = 0) and (reg = 5) then begin
        dispSize := 4;
        reg := -1;
      end;
    {$ifndef amd64}
      end;
    {$endif}
    {$ifdef amd64}
      if prfxRex and $1 <> 0 then
        reg := reg + 8;
      if prfxRex and $4 <> 0 then
        multi := multi + 8;
      if prfxRex and $2 <> 0 then
        regScale := regScale + 8;
    {$endif}
    // store the displacement data pointer
    dispp := code;
    // store the displacement data into dispi and dispc
    case dispSize of
      1 :  begin
             dispi := shortInt(code^);
             dispc :=     byte(code^);
           end;
      2 :  begin
             dispi := smallInt(code^);
             dispc :=     word(code^);
           end;
      4 :  begin
             dispi :=  integer(code^);
             dispc :=    dword(code^);
           end;
      else begin
             dispi := 0;
             dispc := 0;
           end;
    end;
    // skip the displacement data
    inc(dword(code), dispSize);
    result.ModRm := modRm;
  end;

  function ParseImmediateData : integer;
  // how long (if available at all) is the immediate data for the current opcode?
  begin
    case flgs and fI of
      fI8  : result := 1;   // byte immediate data
      fI16 : result := 2;   // word immediate data
      fI32 : {$ifdef amd64}
               if (prfxRex and $8 <> 0) and (opcode >= $b8) and (opcode <= $bf) then
                 result := 8
               else
             {$endif}
                 result := dw;  // dword/word immediate data (operand size prefix)
      else   begin
               result := 0;
               case opcode of
                 $9a, $ea : result := dw + 2;             // call/jmp $wwww:$dddddddd
                 $c8      : result := 3;                  // enter iw, ib
                 $a0..$a3 : {$ifdef amd64}                // mov (e)ax/al <-> [$dddddddd]
                              if prfx67 then result := 4
                              else           result := 8;
                            {$else}
                              if prfx67 then result := 2
                              else           result := 4;
                            {$endif}
               end;
             end;
    end;
    // now store the value in integer form, if it is 1, 2 or 4 bytes long
    case result of
      1 :  imVal := shortInt(code^);  // 1 byte integer immediate data
      2 :  imVal := smallInt(code^);  // 2 byte integer immediate data
      4 :  imVal := integer (code^);  // 4 byte integer immediate data
      {$ifdef amd64}
        8 :  imVal := int64   (code^);  // 8 byte integer immediate data
      {$endif}
      else imVal := 0;
    end;
  end;

  function IsValidOpcode : boolean;
  // is the current opcode/modrm combination valid?
  begin
    // the flags already sort out a lot of invalid opcodes
    result := flgs <> fInvalid;
    if result then
      // but some opcodes are valid only in specific situations
      if opcode > $ff then begin
        case byte(opcode) of
          $00:      result := multi <= 5;
          $01:      result := (multi <> 5) and (regPtr or (multi > 3));
          $0d:      result := regPtr and (multi <= 1);
          $0f:      result := byte(code^) in [$0c..$0d, $1c..$1d, $8a, $8e,
                                              $90, $94, $96..$97, $9a, $9e,
                                              $a0, $a4, $a6..$a7, $aa, $ae,
                                              $b0, $b4, $b6..$b7, $bb, $bf];
          $18:      result := regPtr and (multi <= 3);
          $20, $22: result := not regPtr;
          $21, $23: result := not regPtr;
          $6c, $6d: result := prfx66;
          $71..$72: result := (not regPtr) and (multi in [2, 4, 6]);
          $73:      result := (not regPtr) and (multi in [2, 3, 6, 7]);
          $7c..$7d, $d0:
                    result := prfx66 or prfxF2;
          $ae:      result := ( multi = 7                  ) or
                              ((multi < 4) and      regPtr ) or
                              ((multi > 4) and (not regPtr));
          $b2, $b4..$b5, $c3, $c7:
                    result := regPtr;
          $ba:      result := multi >= 4;
          $d6, $e6: result := prfx66 or prfxF2 or prfxF3;
          $f0:      result := prfxF2;
        end;
      end else
        case byte(opcode) of
          $62, $8d, $c4..$c5:
                    result := regPtr;
          $8c, $8e: result := multi <= 5;
          $d9:      result := regPtr or (not (modRm in [$d1..$d7, $e2..$e3, $e6..$e7, $ef]));
          $da:      result := regPtr or (not (modRm in [$e8, $ea..$ef]));
          $db:      result := regPtr or (not (modRm in [$e5..$e7]));
          $df:      result := regPtr or (not (modRm in [$e1..$e7]));
          $fe:      result := multi <= 1;
          $ff:      result := (multi < 7) and (regPtr or (not (multi in [3, 5])));
        end;
  end;

  procedure CheckTarget;
  // is this a jmp or call instruction?
  begin
    if flgs and fJmpRel <> 0 then begin
      // this is a relative jmp or call instruction, so we know the target
      result.RelTarget   := true;
      result.PTarget     := code;
      result.Target      := pointer(integer(code) + integer(imLen) + integer(imVal));
      result.TargetSize  := imLen;
      result.Enlargeable := not (opcode in [$e0..$e3]);
      if opcode = $e8 then
           result.Call := true
      else result.Jmp  := true;
    end else
      if (opcode = $ff) and (multi in [2..5]) then begin
        // jmp or call, target known or unknown, depending on the modrm byte
        if multi in [2..3] then
             result.Call := true
        else result.Jmp  := true;
        if (reg = -1) and (scale = 0) and (dispSize = 4) then begin
          // just a plain jmp/call [$xxxxxxxx], so we know the target
          result.PPTarget   := dispp;
          result.TargetSize := 4;
          result.IsValid    := TryRead(result.PPTarget^, @result.Target, 4, tryRead_);
        end else
          if useRegState and (regState <> nil) and
             (reg <> -1) and (regState^[reg] <> nil) and
             (scale = 0) and (dispSize = 0) then begin
            // "jmp/call exx" or "jmp/call [exx]" with known register value
            if regPtr then begin
              result.PPTarget := regState^[reg];
              result.IsValid  := TryRead(result.PPTarget^, @result.Target, 4, tryRead_);
            end else begin
              result.PTarget := regState^[reg];
              result.Target  := pointer(result.PTarget^);
            end;
            result.TargetSize := 4;
          end;
      end else
        if      opcode = $9a then result.Call := true   // unknown call
        else if opcode = $ea then result.Jmp  := true;  // unknown jmp
  end;

  procedure CheckRegState;
  // and here we keep track on which value the registers have
  var clr : dword;
      i1  : integer;
  begin
    clr := flgs and fClr;
    // we clear all the register states that the flags tell us
    if (clr = fClrA) or (clr = fClrMA) or (clr = fClrOA) then
      regState^[0] := nil;
    if (not regPtr) and ((clr = fClrM) or (clr = fClrRM) or (clr = fClrMA)) then
      regState^[reg] := nil;
    if (clr = fClrR) or (clr = fClrRM) then
      regState^[multi] := nil;
    if (clr = fClrO) or (clr = fClrOA) then
      regState^[opcode and $7] := nil;
    // a lot of special cases need to be handled manually
    if opcode > $ff then begin
      // here we do that for two byte opcodes
      case byte(opcode) of
        $00:      if (multi <= 1) and (not regPtr) then
                    regState^[reg] := nil;
        $01:      if (multi = 4) and (not regPtr) then
                    regState^[reg] := nil;
        $2c..$2d: if prfxF2 or prfxF3 then
                    regState^[multi] := nil;
        $31..$33, $c7:
                  regState^[2] := nil;
        $7e..$7f: if (not prfxF3) and (not regPtr) then
                    regState^[reg] := nil;
        $a2:      for i1 := 0 to 3 do
                    regState^[i1] := nil;
        $ba:      if (multi >= 5) and (not regPtr) then
                    regState^[reg] := nil;
      end;
    end else
      // here one byte opcodes are handled
      case opcode of
        {$ifndef amd64}
          $61:      for i1 := 0 to 7 do
                      regState^[i1] := nil;
        {$endif}
        $6c..$6d, $aa..$ab, $ae..$af:
                  regState^[7] := nil;
        $6e..$6f, $ac..$ad:
                  regState^[6] := nil;
        $80..$83: if (not regPtr) and (multi <> 7) then
                    regState^[reg] := nil;
        $8b:      if not regPtr then
                    regState^[multi] := regState^[reg];
        $99:      regState^[2] := nil;
        $a4..$a7: begin
                    regState^[6] := nil;
                    regState^[7] := nil;
                  end;
        $b8..$bf: if (not prfx66) {$ifdef amd64} and (imLen = 8) {$endif} then
                    regState^[opcode and $7] := code;
        $c8, $c9: regState^[5] := nil;
        {$ifndef amd64}
          $c7:      if (not regPtr) and (not prfx66) then
                      regState^[reg] := code;
        {$endif}
        $df:      if modRm = $e0 then
                    regState^[0] := nil;
        $e0..$e2: regState^[1] := nil;
        $f7:      if multi >= 4 then
                    regState^[2] := nil;
        $ff:      if (multi <= 1) and (not regPtr) then
                    regState^[reg] := nil;
      end;
  end;

var c1 : dword;
begin
  // first of all let's initialize the variables
  ZeroMemory(@result, sizeOf(TCodeInfo));
  result.This := code;
  if code <> nil then begin
    opcode := 0;
    try
      // first let's initialize the prefix variables
      prfxSeg := 0;
      prfx66 := false;
      prfx67 := false;
      prfxF0 := false;
      prfxF2 := false;
      prfxF3 := false;
      {$ifdef amd64}
        prfxRex := 0;
      {$endif}
      // typically we are working with dwords
      dw := 4;
      // now we strip off all prefixes, so we end up with the real opcode
      repeat
        opcode := byte(code^);
        inc(dword(code));
      until not CheckPrefix;
      if opcode = $0f then begin
        // we have a two byte opcode ($0f $xx)
        opcode   := byte(code^);
        flgs     := COpcodeFlags0f[opcode];
        labelIdx := COpcodeLabelIndex0f[opcode];
        opcode   := opcode + $0f00;
        inc(dword(code));
      end else begin
        // this is the usual one byte opcode
        flgs     := COpcodeFlags[opcode];
        labelIdx := COpcodeLabelIndex[opcode];
      end;
      if flgs and fMod <> 0 then begin
        // this instruction has a modrm byte, so let's parse it
        ParseModRm;
        // this is one of the few opcodes, which differ quite much,
        // depending on the modrm opcode extension
        // so have to get the real flags from an additional table
        if flgs and fMod = fModOpc then
          for c1 := 0 to high(COpcodeFlagsEx) do
            if COpcodeFlagsEx[c1].opcode = opcode then begin
              if regPtr then
                   flgs := COpcodeFlagsEx[c1].flags[multi]
              else flgs := COpcodeFlagsEx[c1].flags[multi + 8];
              break;
            end;
      end;
      // how long (if available at all) is the immediate data for this opcode?
      imLen := ParseImmediateData;
      // is this opcode/modrm combination valid?
      if IsValidOpcode then begin
        // it is valid
        result.IsValid := true;
        // is this a jmp or call instruction?
        CheckTarget;
        if regState <> nil then
          // and here we keep track on which value the registers have
          CheckRegState;
      end;
      // skip the immediate data
      inc(dword(code), imLen);
    except result.IsValid := false end;
    result.Opcode := opcode;
  end;
  result.Next := code;
  if (result.Jmp or result.Call) and (result.Target = result.Next) then begin
    result.Jmp         := false;
    result.Call        := false;
    result.Target      := nil;
    result.PTarget     := nil;
    result.PPTarget    := nil;
    result.TargetSize  := 0;
    result.Enlargeable := false;
  end;
end;

function CodeToHex(code: pointer; fixlen: boolean = true) : string;
begin
  if fixlen then result := IntToHexEx(dword(code), 8)
  else           result := IntToHexEx(dword(code), 1);
  {$ifdef cstyle}
    DeleteR(result, 1);
  {$else}
    Delete(result, 1, 1);
  {$endif}
end;

function FindProcName(module: dword; proc: pointer) : string;
begin
  result := GetImageProcName(module, proc, true);
  if (result = '') and (@GetProcNameFromMapFile <> nil) then
    result := GetProcNameFromMapFile(proc);
end;

function ParseCode(code: pointer; var disAsm: string;
                   regState: TPRegState; useRegState: boolean) : TCodeInfo; overload;
// calls the raw "ParseCode" and adds a disassemble string
var prfxSeg   : byte;     // 26, 2e, 36, 3e, 64..65 segment override prefix
    prfx66    : boolean;  // 66 - operand size prefix
    prfx67    : boolean;  // 67 - address size prefix
    prfxF0    : boolean;  // f0 - lock prefix
    prfxF2    : boolean;  // f2 - repne (or sse2 special size) prefix
    prfxF3    : boolean;  // f3 - rep   (or sse2 special size) prefix
    {$ifdef amd64}
      prfxRex   : byte;     // 40..4f - REX prefix
    {$endif}
    opcode    : word;     // instruction opcode, one or two bytes
    flgs      : dword;    // flags from one of the const flag tables
    labelIdx  : integer;  // label index
    modRm     : byte;     // modrm byte
    sib       : byte;     // sib byte
    regPtr    : boolean;  // do the modrm reg/mem bits address a register?
    reg       : integer;  // modrm reg/mem bits
    multi     : integer;  // modrm multi purpose bits
    regScale  : integer;  // sib scale register
    scale     : integer;  // sib scale factor
    dispSize  : integer;  // size of displacement data
    dispp     : pointer;  // at which address is the displacement data stored?
    dispi     : integer;  // displacement data in integer form
    dispc     : dword;    // displacement data in dword   form
    imLen     : integer;  // size of immediate data
    {$ifdef amd64}        // immediate value (in integer form, if available)
      imVal     : int64;
    {$else}
      imVal     : integer;
    {$endif}
    dw        : integer;  // 4 or 2, depending on the operand size prefix

  function St(reg: integer = 0) : string;
  // return the "reg" floating point register as a string
  begin
    result := 'st';
    if reg <> 0 then
      result := result + '(' + IntToStrEx(reg) + ')';
  end;

  {$ifdef amd64}
    function DisAsmModRm(next: pointer) : string;
  {$else}
    function DisAsmModRm : string;
  {$endif}
  // compose the modrm byte (plus sib byte, if available) into a string

    function CalcMSize : integer;
    // how big is the register/memory, the modrm byte refers to?
    begin
      if prfx66 and ((flgs and f66 = f66M) or (flgs and f66 = f66RM)) then begin
        if (flgs and fMod <> 0) and ((flgs and fReg > fReg32) or (flgs and fMod > fMod32)) then
          // 66 prefix set for sse2 instructions means -> oword (16 bytes)
          result := 16
        else
          // 66 prefix set for other instructions means -> word (2 bytes)
          result := 2;
      end else
        // 66 prefix is not set, or doesn't have any effect this time
        case flgs and fMod of
          fMod8   : result := 1;   // byte  ( 1 byte )
          fMod16  : result := 2;   // word  ( 2 bytes)
          fMod32  : {$ifdef amd64}
                      if ((prfxRex and $8 <> 0) and (opcode <> $63)) or
                         (opcode = $8f) or ((opcode = $ff) and (multi in [2, 4, 6])) or
                         ((opcode >= $0f20) and (opcode <= $0f23)) then
                        result := 5
                      else
                    {$endif}
                      result := 4;   // dword ( 4 bytes)
          fMod64  : result := 8;   // qword ( 8 bytes)
          fMod80  : result := 10;  // real  (10 bytes)
          else      result := 16;  // oword (16 bytes)
        end;
    end;

  var rs, ms : integer;  // register/modrm size
  begin
    result := '';
    if regPtr then begin
      // this modrm byte references memory
      // now let's begin to set up the modrm result string
      // a modrm memory location is always printed in "[]" brackets
      result := '[';
      {$ifdef amd64}
        if prfx67 then rs := 4
        else           rs := 5;
      {$else}
        if prfx67 then rs := 2
        else           rs := 4;
      {$endif}
      if reg <> -1 then
        // address register * 1
        result := result + CRegLabels[rs, reg];
      if scale <> 0 then begin
        // address register * scale
        result := result + '+' + CRegLabels[rs, regScale];
        if scale > 1 then
          result := result + '*' + IntToStrEx(scale);
      end;
      if Length(result) > 1 then begin
        // we do have address registers
        // so print the displacement data (if available) in integer form
        if dispi <> 0 then
          if dispi > 0 then begin
            if dispi >= 10 then
                 result := result + '+' + IntToHexEx(dispi)
            else result := result + '+' + IntToStrEx(dispi);
          end else
            if dispi <= -10 then
                 result := result + '-' + IntToHexEx(-dispi)
            else result := result + '-' + IntToStrEx(-dispi);
      end else begin
        // we don't have any address registers, just our displacement data
        // so print the displacement data in dword form
        // if no displacement data is available (strange), print out "0"
        {$ifdef amd64}
          if sib = 0 then
            dispc := dword(next) + dispc;
        {$endif}
        if dispc < 10 then
             result := result + IntToStrEx(dispc)
        else result := result + IntToHexEx(dispc);
      end;
      result := result + ']';
      if result[2] = '+' then
        // just in case our string begins with "[+", remove that ugly "+"
        Delete(result, 2, 1);
      // add segment override prefix, if available
      if prfxSeg <> 0 then
        result := CRegLabels[3, prfxSeg - 1] + ':' + result;
      if flgs and fPtr <> 0 then begin
        // the flags tell us to add a "xxx ptr" in front of our modrm string
        result := ' ptr ' + result;
        case CalcMSize of
          1  : result :=  'byte' + result;
          2  : result :=  'word' + result;
          4  : result := 'dword' + result;
          {$ifdef amd64}
            5  : result := 'qword' + result;
          {$endif}
          8  : result := 'qword' + result;
          10 : result := 'tbyte' + result;
          16 : result := 'oword' + result;
        end;
      end;
    end else
      // the modrm byte doesn't refer to memory
      // it addresses a pure register, so print out the register
      if (opcode < $d8) or (opcode > $df) then begin
        // here we have the usual case, namely non floating point registers
        ms := CalcMSize;
        case ms of
          1..5 : result := CRegLabels[ms, reg];
          8    : result := 'mm' + IntToStrEx(reg);
          16   : result := 'xmm' + IntToStrEx(reg);
        end;
      end else
        // print out the floating pointer register
        result := St(reg);
  end;

  function GetLabel(next: pointer) : string;
  // compose the instruction label
  var i1 : integer;
      s1 : string;
  begin
    result := '';
    if labelIdx > 0 then begin
      // we do have a valid label index, so let's get the indexed string
      s1 := SubStr(COpcodeLabels, labelIdx, #0);
      // replace some placeholders
      ReplaceStr(s1, '%cc',  SubStr(Ccc, opcode and $F + 1));
      ReplaceStr(s1, '%seg', CRegLabels[3, (opcode shr 3) and $7]);
      // pick the correct sub string for the given prefixes (if available)
      if      prfx66 then result := SubStr(s1, 2, '/')
      else if prfxF2 then result := SubStr(s1, 3, '/')
      else if prfxF3 then result := SubStr(s1, 4, '/');
      if result = '' then
        result := SubStr(s1, 1, '/');
      // pick the sub string for the modrm multi purpose value (if available)
      i1 := SubStrCount(result);
      if i1 > 1 then
        if (i1 > 8) and (not regPtr) then begin
          result := SubStr(result, 8 + multi + 1);
          if PosStr('-', result) > 0 then
            result := SubStr(result, reg + 1, '-');
        end else
          result := SubStr(result, multi + 1);
      // does the label depend on whether the modrm byte addresses memory?
      if PosStr(':', result) > 0 then
        if regPtr then
             result := SubStr(result, 2, ':')
        else result := SubStr(result, 1, ':');
      // a lot of sse2 labels need to be adjusted according to the prefixes
      if prfx66 or prfxF2 then
           ReplaceStr(result, 'S', 'd')
      else ReplaceStr(result, 'S', 's');
      if prfxF2 or prfxF3 then
           ReplaceStr(result, 'P', 's')
      else ReplaceStr(result, 'P', 'p');
      // add the leading "f" for floating point instructions
      if (opcode >= $d8) and (opcode <= $df) then
        result := 'f' + result;
    end else
      if opcode = $0f0f then
        // this is a 3dnow instruction, let's search for the label
        for i1 := 1 to Length(C3dNowLabels) do
          if (C3dNowLabels[i1] = #0) and (byte(C3dNowLabels[i1 + 1]) = byte(pointer(dword(next) - 1)^)) then begin
            result := pchar(@C3dNowLabels[i1 + 2]);
            break;
          end;
  end;

  function RegStr(len, reg: integer) : string;
  // compose the register string
  begin
    if (opcode < $d8) or (opcode > $df) then begin
      // this is a non floating point register
      if prfx66 and ((flgs and f66 = f66R) or (flgs and f66 = f66RM)) then begin
        if (flgs and fMod <> 0) and ((flgs and fReg > fReg32) or (flgs and fMod > fMod32)) then
          // 66 prefix set for sse2 instructions means -> oword (16 bytes)
          len := 16
        else
          // 66 prefix set for other instructions means -> word (2 bytes)
          len := 2;
      end {$ifdef amd64} else
        if (len = 4) and ((prfxRex and $8 <> 0) or (opcode in [$50..$5f])) then
          len := 5{$endif};
      case len of
        1..2, 4..6 : result := CRegLabels[len, reg];
        8          : result := 'mm' + IntToStrEx(reg);
        16         : result := 'xmm' + IntToStrEx(reg);
      end;
    end else
      // return the floating point register
      result := St(reg);
  end;

  procedure IxToDw(out ims: string);
  // return the immediate data as a string in dword form
  var ic, ic2 : dword;
  begin
    ims := '';
    // 3dnow instructions' ($0f0f) immediate data is hidden
    // same with aam/aad, if the immediate data is the default value of $0a
    if (opcode <> $0f0f) and
       (((opcode <> $d4) and (opcode <> $d5)) or (byte(pointer(dword(code) - 1)^) <> $0a)) then begin
      // in all other cases we show the immediate data
      ic2 := 0;
      case imLen of
        1 :  if opcode = $6a then begin
               // byte immediate data sign extended
               ic := dword(shortInt(code^));
               if prfx66 then
                 ic := word(ic);
             end else
               // byte immediate data unsigned
               ic := byte(code^);
        2 :  // word immediate data unsigned
             ic := word(code^);
        3 :  begin
               // "word, byte" immediate data unsigned
               ic  := word(code^);
               ic2 := byte(pointer(dword(code) + 2)^);
             end;
        4 :  if (opcode = $9a) or (opcode = $ea) then begin
               // "word:word" immediate data unsigned
               ic  := word(code^);
               ic2 := word(pointer(dword(code) + 2)^);
             end else
               // dword immediate data unsigned
               ic := dword(code^);
        else begin
               // "word:dword" immediate data unsigned
               ic  := dword(code^);
               ic2 :=  word(pointer(dword(code) + 4)^);
             end;
      end;
      if (ic2 = 0) {$ifdef amd64} and (imLen <> 8) {$endif} then begin
        // we have the usual immediate form, just one value
        if ic < 10 then
             ims := IntToStrEx(ic)
        else ims := IntToHexEx(ic);
      end else
        // strange form, either "iw, ib" or "iw:iw" or "iw:id"
        case imLen of
          3 :  ims := IntToHexEx(ic ) + ', ' + IntToHexEx(ic2);
          {$ifdef amd64}
            8 :  ims := IntToHexEx(int64(code^));
          {$endif}
          else ims := IntToHexEx(ic2) + ':'  + IntToHexEx(ic );
        end;
      // we have a memory address without having a modrm byte
      // this only happens with the opcodes a0..a3
      if (flgs and fPtr <> 0) and (flgs and fMod = 0) then begin
        ims := '[' + ims + ']';
        // add segment override prefix, if available
        if prfxSeg <> 0 then
          ims := CRegLabels[3, prfxSeg - 1] + ':' + ims;
      end;
    end else
      ims := '';
  end;

  procedure IxToInt(out ims: string);
  // return the immediate data as a string in integer form
  begin
    // first of all lets print out the relative immediate value
    if (imVal > -10) and (imVal < 10) then begin
      if      imVal < 0             then ims := '-' + IntToStrEx(-int64(imVal))
      else if flgs and fJmpRel <> 0 then ims := '+' + IntToStrEx( imVal)
      else                               ims :=       IntToStrEx( imVal);
    end else
      if      imVal < 0             then ims := '-' + IntToHexEx(-int64(imVal))
      else if flgs and fJmpRel <> 0 then ims := '+' + IntToHexEx( imVal)
      else                               ims :=       IntToHexEx( imVal);
    if result.RelTarget then
      // this is a relative call or jmp, let's add the absolute target
      ims := ims + ' (' + IntToHexEx(dword(result.Target)) + ')';
  end;

  function CheckFunctionName(target: pointer) : boolean;
  // find out the name of the target, if available/possible
  var nh : PImageNtHeaders;
      mh : dword;
      mn : string;
      ci : TCodeInfo;
      s1 : string;
  begin
    result := false;
    s1 := '';
    // to which module does the target belong?
    if FindModule(target, mh, mn) then begin
      // try to find the target name
      s1 := FindProcName(mh, target);
      if s1 = '' then begin
        // no name found, maybe this is a static linking?
        nh := GetImageNtHeaders(mh);
        if (nh <> nil) and (dword(target) >= mh) and
           (dword(target) <= mh + GetSizeOfImage(nh)) then begin
          // at least the target is inside of the code area of the module
          ci := ParseCode(target);
          if (ci.Target <> nil) and FindModule(ci.Target, mh, mn) then
            // and the target is itself a jmp or call again
            // let's see whether we can find the name of the target's target
            s1 := FindProcName(mh, ci.Target);
        end;
      end;
      if s1 <> '' then begin
        // the target name was found, let's add the name of the module
        if (mh <> HInstance) and (PosStr('(', s1) = 0) then begin
          // but only if the module is not me
          Delete(mn, 1, PosStr('\', mn, maxInt, 1));
          s1 := s1 + ' (' + mn + ')';
        end;
        // finally let's add the function name to the output string
        disAsm := FillStr(disAsm, -40) + '  ; ' + s1;
        result := true;
      end;
    end;
  end;

  procedure CheckStringData(data: dword; isPtr: boolean);
  // does this instruction reference a string constant?
  var mh : dword;
      s1 : string;
      nh : PImageNtHeaders;
      pc : pchar;
      i1, i2, i3, i4, i5 : integer;
  begin
    if FindModule(code, mh, s1) then begin
      nh := GetImageNtHeaders(mh);
      if nh <> nil then
        if (data >= mh) and (data <= mh + GetSizeOfImage(nh) - 100) then begin
          if isPtr and (TPCardinal(data)^ > mh) and
             (TPCardinal(data)^ <= mh + GetSizeOfImage(nh) - 100) then
            data := TPCardinal(data)^;
          if not CheckFunctionName(pointer(data)) then begin
            pc := pointer(data);
            i2 := 0;
            i3 := 0;
            i4 := 0;
            i5 := 0;
            for i1 := 1 to 100 do begin
              if      (pc^ = #0) or (pc^ in [#10, #12])          then break
              else if pc^ in ['A'..'Z', 'a'..'z', '0'..'9', ' '] then inc(i2)
              else if pc^ in [':', '\', '.', ',']                then inc(i3)
              else if pc^ in [#33..#93]                          then inc(i4)
              else if byte(pc^) < 32                             then exit
              else                                                    inc(i5);
              inc(pc);
            end;
            if (i1 > 4) and
               (i2 * 2 > i3 * 5) and (i2 + (i3 div 2) > i4 * 8) and
               (i2 + (i3 div 2) + (i4 div 4) > i5 * 10) then begin
              SetString(s1, pchar(data), i1 - 1);
              {$ifdef cstyle}
                disAsm := FillStr(disAsm, -40) + '  ; "' + s1 + '"';
              {$else}
                disAsm := FillStr(disAsm, -40) + '  ; ''' + s1 + '''';
              {$endif}
            end;
          end;
        end;
    end;
  end;

var ms, rs, ims    : string;
    s2, s3, s4, s5 : string;
    c1             : dword;
begin
  disAsm := '';
  result := ParseCode(code,
                      prfxSeg, prfx66, prfx67, prfxF0, prfxF2, prfxF3, {$ifdef amd64}prfxRex,{$endif}
                      opcode, flgs, labelIdx,
                      modRm, sib, regPtr, reg, multi, regScale, scale,
                      dispSize, dispp, dispi, dispc, imLen, imVal, dw,
                      regState, useRegState, 0);
  if result.This <> result.Next then begin
    // is this opcode/modrm combination valid?
    if result.IsValid then begin
      // it is, first of all let's print out the code address
      disAsm := CodeToHex(code) + '   ';
      // then we check the prefixes
      if prfxF0 then
        disAsm := disAsm + 'lock ';
      // f2/f3 are only "rep(ne)" in one byte opcodes
      // in two byte opcodes they're used as special size flags for sse2
      if opcode < $ff then begin
        if prfxF2 then
          disAsm := disAsm + 'repne ';
        if prfxF3 then
          disAsm := disAsm + 'rep ';
      end;
      // now we add the instruction label
      disAsm := disAsm + GetLabel(result.Next);
      // finally let's look at all the instruction parameters
      if flgs and fMod <> 0 then begin
        // we do have a modrm byte
        // first check for some special cases
        if (opcode > $ff) and (prfxF2 or prfxF3) then
          // we seem to have a sse2 instruction with some special prefixes
          if byte(opcode) in [$2a, $2c, $2d] then begin
            // for these instructions change the mod64 or reg64 flags to 32
            if flgs and fMod = fMod64 then
                 flgs := (flgs and (not fMod)) + fMod32
            else flgs := (flgs and (not fReg)) + fReg32;
          end else
            if byte(opcode) in [$6f, $70, $7e..$7f] then begin
              // for these instructions set both the mod and reg flags to 128
              flgs := (flgs and (not fMod)) + fMod128;
              flgs := (flgs and (not fReg)) + fReg128;
            end else
              if opcode = $0fd6 then
                // finally for this instruction set either mod or reg to 128
                if prfxF3 then
                     flgs := (flgs and (not fMod)) + fMod128
                else flgs := (flgs and (not fReg)) + fReg128;
        // now we compose the register string, if a register is available
        // we have a modrm byte, so the register information is stored there
        case flgs and FReg of
          fReg8   : {$ifdef amd64}
                      if (prfxRex <> 0) and (multi < 8) then
                        rs := RegStr(6, multi)                   // byte register amd64 special mode
                      else
                    {$endif}
                      rs := RegStr(1, multi);                    // byte register
          fReg16  : rs := RegStr(2, multi);                      // word register
          fRegxx  : if opcode > $ff then begin                   // segment/cr/dr register
                      if odd(opcode) then
                           rs := 'dr' + IntToStrEx(multi)
                      else rs := 'cr' + IntToStrEx(multi);
                    end else
                      rs := CRegLabels[3, multi];
          fReg32  : rs := RegStr(4, multi);                      // (d)word register
          fReg64  : rs := RegStr(8, multi);                      // qword register
          fRegSt  : rs := St;                                    // st floating point register
          fReg128 : rs := RegStr(16, multi);                     // oword register
          else      rs := '';
        end;
        // compose the modrm byte into a string
        ms := DisAsmModRm{$ifdef amd64}(result.Next){$endif};
      end else begin
        // we have no modrm byte
        // we compose the register string, if a register is available
        // check the flags for register information
        ms := '';
        case flgs and FReg of
          fRegAl   : rs := RegStr(1, 0);                         // al register
          fRegEax  : rs := RegStr(4, 0);                         // (e)ax register
          fRegO8   : rs := RegStr(1, opcode and $7);             // byte register depending on opcode
          fRegO32  : {$ifdef amd64}                              // (d)word register depending on opcode
                       if (prfxRex and $1 <> 0) and (opcode >= $b8) and (opcode <= $bf) then
                         rs := RegStr(4, opcode and $7 + 8)
                       else
                     {$endif}
                       rs := RegStr(4, opcode and $7);
          fRegEaxO : begin                                       // fRegEax + fRegO32
                       rs := RegStr(4, 0);
                       ms := RegStr(4, opcode and $7);
                     end;
          fRegDxA  : begin                                       // dx register + (e)ax/al register
                       if odd(opcode) then rs := RegStr(4, 0)
                       else                rs := RegStr(1, 0);
                       ms := 'dx';
                     end;
          else       rs := '';
        end;
      end;
      // prepare code pointer for getting immediate data
      dword(code) := dword(result.Next) - dword(imLen);
      // now let's compose the immediate data string
      if imLen > 0 then
        if result.RelTarget or (opcode in [$69, $6b, $80..$83]) then
             IxToInt(ims)
        else IxToDw (ims);
      // now we have 3 strings: register (rs), modrm (ms) and immediate (ims)
      // let's sort out empty strings, the filled strings are stored into s2-s4
      if rs <> '' then begin
        s2 := rs;
        if ms <> '' then begin
          s3 := ms;
          s4 := ims;
        end else begin
          s3 := ims;
          s4 := '';
        end;
      end else begin
        if ms <> '' then begin
          s2 := ms;
          s3 := ims;
        end else begin
          s2 := ims;
          s3 := '';
        end;
        s4 := '';
      end;
      // do we have any parameters at all?
      if s2 <> '' then begin
        // yes, we have, so let's prepare the disassembler string for that
        disAsm := FillStr(disAsm, -19);
        if disAsm[Length(disAsm)] <> ' ' then
          disAsm := disAsm + ' ';
        // if the flags tell us to swap the order of the parameters, we do so
        if flgs and fOrder <> 0 then begin
          s5 := s2;
          s2 := s3;
          s3 := s5;
        end;
        // now let's add all the available parameters
        disAsm := disAsm + s2;
        if s3 <> '' then begin
          disAsm := disAsm + ', ' + s3;
          if s4 <> '' then
            disAsm := disAsm + ', ' + s4;
        end;
      end;
      // the following special cases didn't fit into the flags logic
      // so we handle them here manually
      if (opcode = $d0) or (opcode = $d1) then
        disAsm := disAsm + ', 1';
      if (opcode = $d2) or (opcode = $d3) or (opcode = $0fa5) or (opcode = $0fad) then
        disAsm := disAsm + ', cl';
      // if this instruction is call/jmp, we try to find the target name
      if result.Target <> nil then
        CheckFunctionName(result.Target)
      else begin
        // does this instruction reference a string constant?
        if (flgs and fMod <> 0) and (dispSize = 4) then
          CheckStringData(dispc, true);
        if imLen = 4 then
          CheckStringData(dword(imVal), flgs and fPtr <> 0);
      end;
    end else begin
      // this opcode/modrm combination is invalid, print the data in "db"s
      for c1 := dword(result.This) to dword(code) + dword(imLen) - 1 do
        disAsm := disAsm + #$d#$a + CodeToHex(pointer(c1)) + '   ' +
                  'db ' + IntToHexEx(dword(byte(pointer(c1)^)), 2);
      Delete(disAsm, 1, 2);
    end;
  end;
end;

function ParseCode(code: pointer; regState: TPRegState; useRegState: boolean; tryRead_: dword) : TCodeInfo; overload;
var prfxSeg                                : byte;
    prfx66, prfx67, prfxF0, prfxF2, prfxF3 : boolean;
    {$ifdef amd64}
      prfxRex                                : byte;
    {$endif}
    opcode                                 : word;
    flgs                                   : dword;
    labelIdx                               : integer;
    modRm, sib                             : byte;
    regPtr                                 : boolean;
    reg, multi, regScale, scale            : integer;
    dispSize                               : integer;
    dispp                                  : pointer;
    dispi                                  : integer;
    dispc                                  : dword;
    imLen                                  : integer;
    {$ifdef amd64}
      imVal                                  : int64;
    {$else}
      imVal                                  : integer;
    {$endif}
    dw                                     : integer;
begin
  result := ParseCode(code,
                      prfxSeg, prfx66, prfx67, prfxF0, prfxF2, prfxF3, {$ifdef amd64}prfxRex,{$endif}
                      opcode, flgs, labelIdx,
                      modRm, sib, regPtr, reg, multi, regScale, scale,
                      dispSize, dispp, dispi, dispc, imLen, imVal, dw,
                      regState, useRegState, tryRead_);
end;

function ParseCode(code: pointer) : TCodeInfo; overload;
begin
  result := ParseCode(code, nil, false, 0);
end;

function ParseCode_(code: pointer; tryRead_: dword) : TCodeInfo;
begin
  result := ParseCode(code, nil, false, tryRead_);
end;

function ParseCode(code: pointer; var disAsm: string) : TCodeInfo; overload;
begin
  result := ParseCode(code, disAsm, nil, false);
end;

function ParseFunction_(func                    : pointer;
                        tryRead_                : dword;
                        HandleAnyExceptionAddr  : pointer;
                        HandleOnExceptionAddr   : pointer;
                        HandleAutoExceptionAddr : pointer;
                        HandleFinallyAddr       : pointer;
                        Halt0Addr               : pointer) : TFunctionInfo;
const CENEWHDR = $003C;  // offset of new EXE header
      CEMAGIC  = $5A4D;  // old EXE magic id:  'MZ'
      CPEMAGIC = $4550;  // NT portable executable
var cac : integer;   // counter for code areas
    cca : integer;   // current code area
    mcb : cardinal;  // module code begin
    mce : cardinal;  // module code end
    mdb : cardinal;  // module data begin
    mde : cardinal;  // module data end
    rs  : TRegState;

  procedure AddCodeArea(newAreaBegin, newCaller: pointer);
  var i1, i2 : integer;
      b1     : boolean;
      nae    : pointer;
  begin
    nae := nil;
    with result do begin
      b1 := true;
      for i1 := 0 to cac - 1 do
        with CodeAreas[i1] do
          if newAreaBegin = AreaBegin then begin
            if (calledFrom = nil) or
               ( (dword(newCaller) > dword(calledFrom)) and
                 (dword(newCaller) < dword(AreaBegin ))     ) then
              calledFrom := newCaller;
            for i2 := 0 to high(Registers) do
              if rs[i2] <> Registers[i2] then
                Registers[i2] := nil;
            b1 := false;
            break;
          end else
            if (dword(newAreaBegin) >  dword(AreaBegin)) and
               (dword(newAreaBegin) <= dword(AreaEnd  )) then begin
              nae := AreaEnd;
              dword(AreaEnd) := dword(newAreaBegin) - 1;
              for i2 := 0 to high(Registers) do
                if rs[i2] <> Registers[i2] then
                  rs[i2] := nil;
              if i1 = cca then
                cca := cac;
              break;
            end;
      if b1 then begin
        if cac = Length(CodeAreas) then
          if CodeAreas = nil then
               SetLength(CodeAreas, 8)
          else SetLength(CodeAreas, Length(CodeAreas) * 2);
        inc(cac);
        with CodeAreas[cac - 1] do begin
          AreaBegin     := newAreaBegin;
          AreaEnd       := nae;
          CaseBlock     := false;
          OnExceptBlock := false;
          CalledFrom    := newCaller;
          Move(rs, Registers, 32);
        end;
      end;
    end;
  end;

  procedure AddSpecialBlock(newAreaBegin: pointer; areaLen: dword; isCaseBlock, isOnExceptBlock: boolean);
  begin
    with result do begin
      if cac = Length(CodeAreas) then
        if CodeAreas = nil then
             SetLength(CodeAreas, 8)
        else SetLength(CodeAreas, Length(CodeAreas) * 2);
      inc(cac);
      with CodeAreas[cac - 1] do begin
        AreaBegin     := newAreaBegin;
        AreaEnd       := pointer(dword(newAreaBegin) + areaLen - 1);
        CaseBlock     := isCaseBlock;
        OnExceptBlock := isOnExceptBlock;
        CalledFrom    := nil;
        ZeroMemory(@Registers, 32);
      end;
    end;
  end;

  procedure CheckAddTarget(var ci: TCodeInfo);
  var b1  : boolean;
      i1  : integer;
      ci2 : TCodeInfo;
      by1 : byte;
      c1  : dword;
      s1  : string;
  begin
    if ci.Call or ci.Jmp then
      with result do
        if (ci.PTarget <> nil) or (ci.PPTarget <> nil) then begin
          b1 := false;
          if ci.Target = HandleAnyExceptionAddr then begin
            // we have a Delphi try..except end block here
            // "b1" makes sure that "jmp @HandleAnyException" is treated as a "call"
            b1 := true;
            // furthermore we add the code after the "jmp @HandleAnyException"
            // as a new code area, cause @HandleAnyException will end up there
            AddCodeArea(ci.Next, nil);
          end else
            if ci.Target = HandleFinallyAddr then begin
              // we have a Delphi try..finally end block here
              // "b1" makes sure that "jmp @HandleFinally" is treated as a "call"
              b1 := true;
              // furthermore we add the code after the "jmp @HandleFinally"
              // as a new code area, cause @HandleFinally will end up there
              AddCodeArea(ci.Next, nil);
              // the code after @HandleFinally is a "jmp" to the finally block
              // directly before the finally block there is a "push dword"
              // this push is the address of the code after the finally block
              // we try to find this push and add it as another code area
              ci2 := ParseCode(ci.Next);
              if ci2.Jmp and                                              // we found the "jmp" after @HandleFinally
                 (dword(ci2.Target) > dword(func)) and                    // the target is inside of our function
                 (dword(ci2.Target) < dword(ci.This)) and                 // but before the @HandleFinally call
                 (TPByte(dword(ci2.Target) - 5)^ = $68) and               // before the target there is a "push"
                 (TPCardinal(dword(ci2.Target) - 4)^ > dword(func)) then  // the push target is inside of our function
                // we found the push, now we add the code area
                AddCodeArea(TPPointer(dword(ci2.Target) - 4)^, nil);
            end else
              if ci.Target = HandleOnExceptionAddr then begin
                // we have a Delphi try..except end block here
                // the except block has branches for different exception classes
                // "b1" makes sure that "jmp @HandleOnException" is treated as a "call"
                b1 := true;
                // now we identify the branch information block
                AddSpecialBlock(ci.Next, 4 + TPCardinal(ci.Next)^ * 8, false, true);
                // finally we add each branch as a new code area
                for c1 := 1 to TPCardinal(ci.Next)^ do
                  AddCodeArea(TPPointer(dword(ci.Next) + 8 * c1)^, nil);
              end else
                if ci.Target = HandleAutoExceptionAddr then begin
                  // we have a safecall exception block here
                  // "b1" makes sure that "jmp @HandleAutoException" is treated as a "call"
                  b1 := true;
                end else
                  if (ci.Target = BcbInitExceptBlockLDTC) and (ci.Target <> nil) and
                     (dword(CodeAreas[cca].AreaBegin) < dword(ci.This)) then begin
                    // this is a BCB try..whatever statement
                    // somewhere before the call to "__InitExceptBlockLDTC"
                    // there's a "mov eax, $xxxxxxxx" call
                    c1 := 0;
                    ci2 := ParseCode(CodeAreas[cca].AreaBegin);
                    while ci2.IsValid and (ci2.This <> ci.This) do begin
                      if ci2.Opcode = $b8 then
                        // found a "mov eax", let's store the $xxxxxxxx
                        // there might be multiple such "mov"s
                        // we're interested in the last one only
                        // so we don't leave the loop just yet
                        c1 := TPCardinal(dword(ci2.This) + 1)^;
                      ci2 := ParseCode(ci2.Next);
                    end;
                    if c1 <> 0 then begin
                      inc(c1, 10);
                      case TPWord(c1)^ of
                        0: AddCodeArea(TPPointer(c1 + 2)^, nil);      // try/finally ("C")
                        1: AddCodeArea(TPPointer(c1 + 6)^, nil);      // try/except(expr )  ("C")  XB_EXCEXP
                        2: AddCodeArea(TPPointer(c1 + 6)^, nil);      // try/except(const)  ("C")  XB_EXCCNS
                        3: begin                                      // try (C++)
                             c1 := TPCardinal(c1 + 2)^ + 8;
                             while TPPointer(c1)^ <> nil do begin
                               AddCodeArea(TPPointer(c1)^, nil);
                               inc(c1, 5 * 4);
                             end;
                           end;
                      end;
                    end;
                  end;
          if (ci.TargetSize = 4) and
             ( ci.Call or (cardinal(ci.Target) < mcb) or (cardinal(ci.Target) > mce) or b1 ) then begin
            if (ci.Target <> nil) and TryRead(ci.Target, @by1, 1, tryRead_) and (by1 in [$e9, $eb, $ff]) then begin
              // statically linked APIs are normally realized by a "call" to a "jmp"
              // we want to have the *real* target, so we take the "jmp" target
              ci2 := ParseCode(ci.Target);
              if ci2.IsValid and (ci2.Target <> nil) and
                 ((not FindModule(ci.Target, c1, s1)) or (GetImageProcName(c1, ci.Target, false) = '')) then
                ci.Target := ci2.Target;
            end;
            b1 := true;
            for i1 := 0 to high(FarCalls) do
              if FarCalls[i1].CodeAddr2 = ci.Next then begin
                b1 := false;
                break;
              end;
            if b1 then begin
              SetLength(FarCalls, Length(FarCalls) + 1);
              with FarCalls[high(FarCalls)] do begin
                Call       := ci.Call;
                CodeAddr1  := ci.This;
                CodeAddr2  := ci.Next;
                Target     := ci.Target;
                RelTarget  := ci.RelTarget;
                PTarget    := ci.PTarget;
                PPTarget   := ci.PPTarget;
                if PPTarget <> nil then
                  inc(Copy.BufferLen, 4);
              end;
            end;
          end else
            AddCodeArea(ci.Target, ci.This);
          for i1 := 0 to high(UnknownTargets) do
            if UnknownTargets[i1].CodeAddr1 = ci.This then begin
              UnknownTargets[i1] := UnknownTargets[high(UnknownTargets)];
              SetLength(UnknownTargets, high(UnknownTargets));
              break;
            end;
        end else begin
          i1 := Length(UnknownTargets);
          SetLength(UnknownTargets, i1 + 1);
          UnknownTargets[i1].Call      := ci.Call;
          UnknownTargets[i1].CodeAddr1 := ci.This;
          UnknownTargets[i1].CodeAddr2 := ci.Next;
        end;
  end;

  procedure ParseCodeArea(var ci: TCodeInfo);
  var i1   : integer;
      cc   : pointer;
      cmp  : record
               switches  : byte;
               reg       : byte;
               jumpFound : boolean;
             end;
      b1   : boolean;
      stp  : dword;
      rs2  : TRegState;
      push : dword;
  begin
    push := 0;
    cmp.switches := 0;
    with result do begin
      cc := CodeAreas[cca].AreaBegin;
      Move(CodeAreas[cca].Registers, rs, 32);
      stp := mce;
      for i1 := 0 to high(CodeAreas) do
        if (dword(CodeAreas[i1].AreaBegin) > dword(CodeAreas[cca].AreaBegin)) and
           (dword(CodeAreas[i1].AreaBegin) < stp) then
          stp := dword(CodeAreas[i1].AreaBegin);
      while true do begin
        rs2 := rs;
        ci := ParseCode(cc, @rs, false, tryRead_);
        if not ci.IsValid then
          break;
        cardinal(CodeAreas[cca].AreaEnd) := cardinal(ci.Next) - 1;
        if ci.Opcode in [$c2..$c3, $ca..$cb, $cf] then  // ret/iret
          break;
        if (ci.Opcode = $68) and (dword(ci.Next) - dword(ci.This) = 5) and (TPByte(ci.Next)^ = $64) then
          // this is a "push dword" instruction, followed by a "fs:" prefix
          // we store it because it can be part of a try..except/finally block
          push := TPCardinal(dword(ci.This) + 1)^
        else
          if push <> 0 then begin
            if (ci.Opcode = $ff) and
               ( ( (ci.ModRm and $f8 = $30) and                    // (1) push dword ptr fs:[register]
                   (dword(ci.Next) - dword(ci.This) = 3) and       //     instruction = 3 bytes
                   (rs2[ci.ModRm and $7] = nil)              ) or  //     register = 0
                 ( (ci.ModRm = $35) and                            // (2) push dword ptr fs:[dword]
                   (dword(ci.Next) - dword(ci.This) = 7) and       //     instruction = 7 bytes
                   (TPCardinal(dword(ci.This) + 3)^ = 0)     )     //     dword = 0
               ) then
              // some exception handler is being installed
              // we add this pointer to this handler to our list of code areas
              AddCodeArea(pointer(push), nil);
            push := 0;
          end;
        if cmp.switches = 0 then begin
          if (ci.Opcode = $83) and (ci.ModRm in [$f8..$ff]) then begin
            // we have found a "cmp reg, byteValue"
            // this *may* be the beginning of a "case" statement
            cmp.switches  := TPByte(dword(cc) + 2)^;
            cmp.reg       := ci.ModRm and $7;
            cmp.jumpFound := false;
          end;
        end else
          if not cmp.jumpFound then begin
            if (ci.Opcode in [$77, $7f]) or (ci.Opcode = $0f87) or (ci.Opcode = $0f8f) then begin
              // this may still be a "case" statement with ja/jg
              cmp.jumpFound := true;
              inc(cmp.switches);
            end else
              if (ci.Opcode in [$73, $7d]) or (ci.Opcode = $0f83) or (ci.Opcode = $0f8d) then
                // this may still be a "case" statement with jae/jge
                cmp.jumpFound := true
              else
                cmp.switches := 0;
          end else
            if (ci.Opcode = $ff) and (ci.ModRm = $24) and
               (TPByte(dword(cc) + 2)^ and $c7 = $85) and
               ((TPByte(dword(cc) + 2)^ shr 3) and $7 = cmp.reg) and
               (TPPointer(dword(cc) + 3)^ = ci.Next) then begin
              // it *is* a case statement!
              // so let's fill the code areas for the case branches
              for i1 := 0 to cmp.switches - 1 do
                AddCodeArea(TPAPointer(ci.Next)^[i1], cc);
              // now let's add a data area for the case jump pointers
              AddSpecialBlock(ci.Next, cmp.switches * 4, true, false);
              break;
            end else
              cmp.switches := 0;
        b1 := (ci.Target <> nil) and (ci.Target = Halt0Addr);
        CheckAddTarget(ci);
        if (dword(CodeAreas[cac - 1].AreaBegin) > dword(CodeAreas[cca].AreaBegin)) and
           (dword(CodeAreas[cac - 1].AreaBegin) < stp) then
          stp := dword(CodeAreas[cac - 1].AreaBegin);
        if b1 then  // Halt?
          break;
        if ci.Jmp and ( (ci.Opcode in [$e9..$eb]) or
                        ((ci.Opcode = $ff) and (ci.ModRm and $30 = $20)) ) then // jmp?
          break;
        cc := ci.Next;
        b1 := false;
        for i1 := 0 to high(rs) do
          if rs[i1] <> rs2[i1] then begin
            b1 := true;
            break;
          end;
        if b1 or (dword(cc) >= stp) then begin
          AddCodeArea(cc, nil);
          break;
        end;
      end;
      if dword(cc) > stp then
        ci.IsValid := false;
    end;
  end;

  procedure CalcCodeBegin(var ce: dword);
  var i1 : integer;
  begin
    with result do begin
      CodeBegin := pointer($FFFFFFFF);
      ce := 0;
      for i1 := 0 to cac - 1 do begin
        if cardinal(CodeAreas[i1].AreaBegin) < cardinal(CodeBegin) then
          CodeBegin := CodeAreas[i1].AreaBegin;
        if cardinal(CodeAreas[i1].AreaEnd) > ce then
          pointer(ce) := CodeAreas[i1].AreaEnd;
      end;
      CodeLen := ce - cardinal(CodeBegin) + 1;
    end;
  end;

  procedure FindCodeArea;
  var i1 : integer;
  begin
    with result do
      for i1 := 0 to cac - 1 do
        if CodeAreas[i1].AreaBegin = CodeBegin then begin
          dword(CodeBegin) := dword(CodeAreas[i1].AreaEnd) + 1;
          FindCodeArea;
          break;
        end;
  end;

var ci         : TCodeInfo;
    ce         : cardinal;  // code end
    i1, i2, i3 : integer;
    mbi        : TMemoryBasicInformation;
    ih         : PImageNtHeaders;
    sh         : PImageSectionHeader;
    b1         : boolean;
begin
  if HandleAnyExceptionAddr  = nil then HandleAnyExceptionAddr  := GetHandleAnyExceptionAddr;
  if HandleOnExceptionAddr   = nil then HandleOnExceptionAddr   := GetHandleOnExceptionAddr;
  if HandleAutoExceptionAddr = nil then HandleAutoExceptionAddr := GetHandleAutoExceptionAddr;
  if HandleFinallyAddr       = nil then HandleFinallyAddr       := GetHandleFinallyAddr;
  if Halt0Addr               = nil then Halt0Addr               := GetHalt0Addr;
  Finalize(result);
  ZeroMemory(@result, sizeOf(TFunctionInfo));
  with result do
    if (VirtualQuery(func, mbi, sizeOf(mbi)) = sizeOf(mbi)) and (mbi.State = MEM_COMMIT) then begin
      ih := GetImageNtHeaders(dword(mbi.AllocationBase));
      if ih <> nil then begin
        if ih^.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC then
             dword(sh) := dword(@ih^.OptionalHeader) + sizeOf(TImageOptionalHeader64)
        else dword(sh) := dword(@ih^.OptionalHeader) + sizeOf(TImageOptionalHeader  );
        if sh^.Characteristics and IMAGE_SCN_CNT_CODE <> 0 then begin
          mcb := dword(mbi.AllocationBase) + sh^.VirtualAddress;
          mce := mcb + sh^.Misc.VirtualSize - 1;
          inc(sh);
          if sh^.Characteristics and IMAGE_SCN_CNT_CODE <> 0 then
            mce := dword(mbi.AllocationBase) + sh^.VirtualAddress + sh^.Misc.VirtualSize - 1;
        end else
          if ih^.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC then begin
            mcb := dword(mbi.AllocationBase) + PImageOptionalHeader64(@ih^.OptionalHeader).BaseOfCode;
            mce := mcb + PImageOptionalHeader64(@ih^.OptionalHeader).SizeOfCode;
          end else begin
            mcb := dword(mbi.AllocationBase) + ih^.OptionalHeader.BaseOfCode;
            mce := mcb + ih^.OptionalHeader.SizeOfCode;
          end;
        if ih^.OptionalHeader.Magic <> IMAGE_NT_OPTIONAL_HDR64_MAGIC then begin
          mdb := dword(mbi.AllocationBase) + ih^.OptionalHeader.BaseOfData;
          mde := mdb + ih^.OptionalHeader.SizeOfUninitializedData + ih^.OptionalHeader.SizeOfInitializedData - 1;
          if mcb > mdb then mcb := mdb;
          if mce < mde then mce := mde;
        end;
      end else begin
        mcb := dword(mbi.BaseAddress);
        mce := mcb + mbi.RegionSize;
      end;
      EntryPoint    := func;
      Interceptable := false;
      Copy.IsValid  := true;
      cac := 0;
      ZeroMemory(@rs, 32);
      AddCodeArea(EntryPoint, nil);
      while true do begin
        cca := -1;
        for i1 := 0 to cac - 1 do
          if CodeAreas[i1].AreaEnd = nil then begin
            cca := i1;
            break;
          end;
        if cca = -1 then
          for i1 := high(UnknownTargets) downto 0 do begin
            b1 := false;
            for i2 := 0 to cac - 1 do
              if (dword(UnknownTargets[i1].CodeAddr1) >= dword(CodeAreas[i2].AreaBegin)) and
                 (dword(UnknownTargets[i1].CodeAddr2) <= dword(CodeAreas[i2].AreaEnd  )) then begin
                ci := ParseCode(UnknownTargets[i1].CodeAddr1, @CodeAreas[i2].Registers, true, tryRead_);
                if ci.Target <> nil then begin
                  CheckAddTarget(ci);
                  if CodeAreas[cac - 1].AreaEnd = nil then begin
                    cca := cac - 1;
                    b1 := true;
                  end;
                end;
                break;
              end;
            if b1 then
              break;
          end;
        if cca = -1 then begin
          b1 := false;
          for i1 := 0 to high(UnknownTargets) do
            if not UnknownTargets[i1].Call then begin
              b1 := true;
              break;
            end;
          if b1 then begin
            CalcCodeBegin(ce);
            FindCodeArea;
            if (dword(CodeBegin) - 1 <> ce) and (ce - dword(CodeBegin) < $400) then begin
              // some bytes in the middle of our function are not disassembled yet
              // plus there are jump instructions to unknown targets in the code
              // so we guess that these not yet disassembled parts are code, too
              cca := cac;
              ZeroMemory(@rs, 32);
              AddCodeArea(CodeBegin, nil);
              ParseCodeArea(ci);
              if not ci.IsValid then begin
                // oooops, we guessed wrong, let's pretend we didn't even try...
                cac := cca;
                ci.IsValid := true;
                break;
              end;
            end else
              break;
          end else
            break;
        end else begin
          ParseCodeArea(ci);
          if not ci.IsValid then
            break;
        end;
      end;
      SetLength(CodeAreas, cac);
      if not ci.IsValid then begin
        IsValid       := false;
        LastErrorAddr := ci.Next;
        LastErrorNo   := CErrorNo_InvalidCode;
        LastErrorStr  := CErrorStr_InvalidCode;
      end else begin
        IsValid := true;
        CalcCodeBegin(ce);
        inc(Copy.BufferLen, CodeLen + 4);
        i1 := 0;
        i2 := 0;
        repeat
          b1 := true;
          if CodeAreas[i1].CaseBlock or CodeAreas[i1].OnExceptBlock or (CodeAreas[i1].CalledFrom <> nil) then
            break;
          inc(i2, dword(CodeAreas[i1].AreaEnd) - dword(CodeAreas[i1].AreaBegin) + 1);
          for i3 := 1 to high(CodeAreas) do
            if dword(CodeAreas[i3].AreaBegin) = dword(CodeAreas[i1].AreaEnd) + 1 then begin
              i1 := i3;
              b1 := false;
              break;
            end;
        until b1;
        if i2 >= 6 then begin
          Interceptable := true;
          ci.Next := EntryPoint;
          repeat
            ci := ParseCode(ci.Next);
            if (  ci.Call or ci.Jmp ) and
               ( ((ci.PTarget = nil) and (ci.PPTarget = nil)) or
                 ((not ci.Enlargeable) and (ci.TargetSize < 4))  ) then begin
              Interceptable := false;
              break;
            end;
          until cardinal(ci.Next) - cardinal(EntryPoint) >= 6;
        end;
      end;
    end else begin
      IsValid       := false;
      LastErrorAddr := func;
      LastErrorNo   := ERROR_INVALID_PARAMETER;
      LastErrorStr  := ErrorCodeToStr(LastErrorNo);
    end;
end;

function ParseFunction(func: pointer) : TFunctionInfo; overload;
begin
  result := ParseFunction_(func, 0, nil, nil, nil, nil, nil);
end;

function ParseFunctionEx(func: pointer; var disAsm: string; exceptAddr: pointer;
                         maxLines: integer; autoDelimiters: boolean) : TFunctionInfo;
var len    : integer;
    lines  : integer;
    before : boolean;

  procedure FindCodeArea(var ca: integer);
  var min, cur : dword;
      i1       : integer;
  begin
    if ca = -1 then min := 0
    else            min := dword(result.CodeAreas[ca].AreaEnd) + 1;
    cur := maxCard;
    ca  := -1;
    for i1 := 0 to high(result.CodeAreas) do
      if (dword(result.CodeAreas[i1].AreaBegin) >= min) and
         (dword(result.CodeAreas[i1].AreaBegin) <  cur) then begin
        cur := dword(result.CodeAreas[i1].AreaBegin);
        ca  := i1;
      end;
  end;

var cai       : array of integer;
    name      : string;
    lineNoLen : integer;

  procedure DoItAll(justCount: boolean; var first: integer);
  var lineNo           : integer;
      minAddr, maxAddr : pointer;

    procedure AddLine(code: pointer; line: string = ''; addCodePos: boolean = true; addLineNo: boolean = true);
    var i1, i2 : integer;
    begin
      if (not justCount) and (lines >= first) then begin
        if addCodePos then begin
          if line <> '' then
            line := ' ' + line;
          line := CodeToHex(code) + line;
        end else
          if code = exceptAddr then
            line[10] := '>';//'»';
        if lineNoLen > 0 then begin
          i1 := lineNo;
          if addLineNo then
            GetLineNumber(code, lineNo, minAddr, maxAddr);
          if i1 <> lineNo then begin
            if Length(line) < 10 then
                 line := line + ' ' + IntToStrEx(lineNo, lineNoLen)
            else Insert(IntToStrEx(lineNo, lineNoLen) + ' ', line, 10);
          end else
            if Length(line) >= 10 then
              Insert(FillStr('', lineNoLen + 1), line, 10);
        end;
        line := line + #$d#$a;
        while len + Length(line) > Length(disAsm) do
          if disAsm = '' then
               SetLength(disAsm, 200)
          else SetLength(disAsm, (len + Length(line)) * 2);
        Move(line[1], disAsm[len + 1], Length(line));
        inc(len, Length(line));
      end;
      if maxLines > 0 then begin
        inc(lines);
        if (dword(exceptAddr) <= dword(code)) and before then begin
          if lines > maxLines * 12 div 10 then begin
            if justCount then begin
              first := lines - maxLines - 2;
              if first < 0 then
                first := 0;
            end else begin
              first := 0;
              i2 := len;
              for i1 := 0 to maxLines do
                i2 := PosStr(#$d#$a, disAsm, i2 - 2, 1);
              if i2 > 0 then begin
                Delete(disAsm, 1, i2 + 1);
                dec(len, i2 + 1);
                disAsm := '[...]' + #$d#$a + disAsm;
                inc(len, 7);
              end;
            end;
          end;
          lines := 0;
          before := false;
        end;
      end;
    end;

  var b1, b2     : boolean;
      i1, i2, i3 : integer;
      s1         : string;
      ci         : TCodeInfo;
      rs         : TRegState;
      clss       : TClass;
      lastCi     : pointer;
  begin
    lineNo := 0;
    minAddr := nil;
    maxAddr := nil;
    lines := 0;
    before := true;
    b1 := false;
    b2 := false;
    lastCi := nil;
    ci.IsValid := false;
    for i1 := 0 to high(cai) do
      with result.CodeAreas[cai[i1]] do begin
        if (AreaBegin = func) or (autoDelimiters and (CalledFrom <> nil)) then begin
          if b1 then
            AddLine(lastCi);
          if (not justCount) and (lines >= first) then begin
            if AreaBegin = func then
                 s1 := name
            else s1 := 'loc_' + CodeToHex(AreaBegin, false);
            s1 := s1 + ':';
            if AreaBegin = func then
              s1 := FillStr(s1, -31) + '  ; function entry point';
            AddLine(AreaBegin, s1, true, false);
          end else
            AddLine(AreaBegin, '');
        end;
        if CaseBlock then begin
          if autoDelimiters then begin
            if b1 then
              AddLine(lastCi);
            if b2 then begin
              AddLine(ci.This, '; ---------------------------------------------------------');
              AddLine(ci.This);
            end;
          end;
          for i2 := 0 to (dword(AreaEnd) + 1 - dword(AreaBegin)) div 4 - 1 do begin
            if (not justCount) and (lines >= first) then begin
              s1 := '  dd loc_' + CodeToHex(TPAPointer(AreaBegin)^[i2], false);
              if i2 = 0 then
                s1 := FillStr(s1, -31) + '  ; case jump table';
              AddLine(pointer(dword(AreaBegin) + dword(i2) * 4), s1);
            end else
              AddLine(pointer(dword(AreaBegin) + dword(i2) * 4), '');
            if (not before) and (justCount or (lines >= maxLines)) then
              break;
          end;
          if autoDelimiters and (before or (lines < maxLines)) then begin
            AddLine(pointer(dword(AreaEnd) + 1));
            AddLine(pointer(dword(AreaEnd) + 1), '; ---------------------------------------------------------');
            AddLine(pointer(dword(AreaEnd) + 1));
          end;
          b1 := false;
          b2 := false;
        end else
          if OnExceptBlock then begin
            // this is a Delphi style "exception on E: Exception do ..." block
            i3 := 1;
            if not justCount then
              for i2 := 1 to TPCardinal(AreaBegin)^ do
                if TPAPointer(AreaBegin)^[i2 * 2 - 1] <> nil then begin
                  try
                    clss := TClass(TPAPointer(AreaBegin)^[i2 * 2 - 1]^);
                    if Length(clss.ClassName) > i3 then
                      i3 := Length(clss.ClassName);
                  except end;
                end;
            for i2 := 1 to TPCardinal(AreaBegin)^ do begin
              if (not justCount) and (lines >= first) then begin
                if TPAPointer(AreaBegin)^[i2 * 2 - 1] <> nil then begin
                  try
                    s1 := TClass(TPAPointer(AreaBegin)^[i2 * 2 - 1]^).ClassName;
                  except
                    s1 := 'EUnknown';
                  end;
                  s1 := '  on ' + FillStr(s1, -i3) + ' do';
                end else
                  s1 := '  else' + FillStr('', i3 + 2);
                s1 := s1 + ' loc_' + CodeToHex(TPAPointer(AreaBegin)^[i2 * 2], false);
              end else
                s1 := '';
              AddLine(pointer(dword(AreaBegin) + dword(i2) * 8 - 4), s1);
              if (not before) and (justCount or (lines >= maxLines)) then
                break;
            end;
            if autoDelimiters and (before or (lines < maxLines)) then begin
              AddLine(pointer(dword(AreaEnd) + 1));
              AddLine(pointer(dword(AreaEnd) + 1), '; ---------------------------------------------------------');
              AddLine(pointer(dword(AreaEnd) + 1));
            end;
            b1 := false;
            b2 := false;
          end else begin
            ci.Next := AreaBegin;
            Move(Registers, rs, 32);
            repeat
              b1 := true;
              b2 := true;
              if ci.IsValid then
                lastCi := ci.This
              else
                lastCi := AreaBegin;
              if (not justCount) and (lines >= first) then begin
                ci := ParseCode(ci.Next, s1, @rs, true);
                if ci.RelTarget then
                  for i2 := 0 to high(result.CodeAreas) do
                    if ci.Target = result.CodeAreas[i2].AreaBegin then begin
                      Delete(s1, PosStr(' ', s1, 12), maxInt);
                      s1 := FillStr(s1, -19);
                      if s1[Length(s1)] <> ' ' then
                        s1 := s1 + ' ';
                      if ci.Target = func then
                           s1 := s1 + name
                      else s1 := s1 + 'loc_' + CodeToHex(ci.Target, false);
                      break;
                    end;
                AddLine(ci.This, s1, false);
              end else begin
                ci := ParseCode(ci.Next, @rs, true, 0);
                AddLine(ci.This, '', false);
              end;
              if autoDelimiters and
                 (ci.Jmp or ci.Call or (ci.Opcode in [$c2..$c3, $ca..$cb, $cf])) and
                 ((dword(ci.Next) <= dword(AreaEnd)) or (i1 < high(cai))) then begin
                AddLine(ci.This);
                if ((not (ci.Jmp or ci.Call)) or (ci.Jmp and (ci.Opcode in [$e9..$eb, $ff]))) and
                   ( (ci.Target = nil) or
                     ( (ci.Target <> GetHandleAnyExceptionAddr) and
                       (ci.Target <> GetHandleOnExceptionAddr ) and
                       (ci.Target <> GetHandleFinallyAddr     )     ) ) then begin
                  AddLine(ci.This, '; ---------------------------------------------------------');
                  AddLine(ci.This);
                  b2 := false;
                end; 
                b1 := false;
              end;
            until (dword(ci.Next) > dword(AreaEnd)) or ((not before) and (justCount or (lines >= maxLines)));
          end;
        if (not before) and (lines >= maxLines) and
           ((dword(ci.Next) <= dword(AreaEnd)) or (i1 < high(cai))) then begin
          if not justCount then begin
            SetLength(disAsm, len);
            disAsm := disAsm + '[...]';
            len := len + 7;
          end;
          exit;
        end;
      end;
  end;

var i1, i2 : integer;
    p1     : pointer;
    first  : integer;
    mbi    : TMemoryBasicInformation;
begin
  len := 0;
  result := ParseFunction(func);
  if result.IsValid then begin
    if (VirtualQuery(func, mbi, sizeOf(mbi)) = sizeOf(mbi)) and
       (mbi.State = MEM_COMMIT) and (mbi.AllocationBase <> nil) then 
         name := FindProcName(dword(mbi.AllocationBase), func)
    else name := '';
    if name = '' then
         name := 'sub_' + CodeToHex(func, false)
    else name := 'public ' + name;
    lineNoLen := 0;
    if @GetLineNumber <> nil then begin
      i1 := 0;
      GetLineNumber(pointer(dword(result.EntryPoint) + dword(result.CodeLen) - 1), i1, p1, p1);
      if i1 = 0 then begin
        GetLineNumber(exceptAddr, i1, p1, p1);
        i1 := i1 * 10;
      end;
      if i1 <> 0 then
        lineNoLen := Length(IntToStrEx(i1));
    end;
    SetLength(cai, Length(result.CodeAreas));
    i2 := -1;
    for i1 := 0 to high(cai) do begin
      FindCodeArea(i2);
      if i2 = -1 then begin
        disAsm := 'Internal error in ParseFunction while composing the disassembling string...  :-(';
        exit;
      end;
      cai[i1] := i2;
    end;
    first := 0;
    if maxLines > 0 then
      DoItAll(true, first);
    DoItAll(false, first);
  end;
  SetLength(disAsm, len - 2);
end;

function ParseFunction(func: pointer; var disAsm: string) : TFunctionInfo; overload;
begin
  result := ParseFunctionEx(func, disAsm, nil, 0, true);
end;

// ***************************************************************

var kernel32handle_ : dword;
function kernel32handle : dword;
var s1 : string;
begin
  if kernel32handle_ = 0 then begin
    s1 := DecryptStr(CKernel32);
    if GetVersion and $80000000 = 0 then
         kernel32handle_ := GetModuleHandleW(pointer(AnsiToWideEx(s1)))
    else kernel32handle_ := GetModuleHandleA(pointer(             s1 ));
  end;
  result := kernel32handle_;
end;

function KernelProc(api: string; doubleCheck: boolean = false) : pointer;
begin
  result := GetImageProcAddress(kernel32handle, DecryptStr(api), doubleCheck);
end;

var ntdllhandle_ : dword;
function ntdllhandle : dword;
begin
  if ntdllhandle_ = 0 then
    ntdllhandle_ := GetModuleHandleW(pointer(AnsiToWideEx(DecryptStr(CNtDll))));
  result := ntdllhandle_;
end;

function NtProc(api: string; doubleCheck: boolean = false) : pointer;
var nh : PImageNtHeaders;
begin
  if api = '' then begin
    result := nil;
    nh := GetImageNtHeaders(ntdllhandle);
    if nh <> nil then
      if nh^.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC then
           result := @PImageOptionalHeader64(@nh^.OptionalHeader).AddressOfEntryPoint
      else result := @                        nh^.OptionalHeader .AddressOfEntryPoint;
  end else
    result := GetImageProcAddress(ntdllhandle, DecryptStr(api), doubleCheck);
end;

function GetExportDirectory(code: pointer; out module: cardinal; out pexp: PImageExportDirectory) : boolean;
var mbi   : TMemoryBasicInformation;
    arrCh : array [0..MAX_PATH] of char;
    pinh  : PImageNtHeaders;
begin
  result := false;
  if (VirtualQuery(code, mbi, sizeOf(mbi)) = sizeOf(mbi)) and
     (mbi.State = MEM_COMMIT) and (mbi.AllocationBase <> nil) and
     (GetModuleFileName(cardinal(mbi.AllocationBase), arrCh, MAX_PATH) <> 0) then begin
    module := cardinal(mbi.AllocationBase);
    if TPWord(module)^ = CEMAGIC then begin
      pinh := pointer(module + TPCardinal(module + CENEWHDR)^);
      if pinh^.signature = CPEMAGIC then begin
        pexp   := pointer(module + pinh^.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        result := pexp <> nil;
      end;
    end;
  end;
end;

function SolveW9xDebugMode(code: pointer) : pointer;
var module : cardinal;
    pexp   : PImageExportDirectory;
    i1     : integer;
    c1     : cardinal;
    by1    : byte;
begin
  result := code;
  if {(DebugHook <> 0) and} (code <> nil) and TryRead(code, @by1, 1) and (by1 = $68) and
     (GetVersion and $80000000 <> 0) and (not GetExportDirectory(code, module, pexp)) then begin  // w9x debug mode?
    code := TPPointer(cardinal(code) + 1)^;
    if GetExportDirectory(code, module, pexp) then
      with pexp^ do
        for i1 := 0 to NumberOfFunctions - 1 do begin
          c1 := TPACardinal(module + AddressOfFunctions)^[i1];
          if module + c1 = cardinal(code) then begin
            result := code;
            break;
          end;
        end;
  end;
end;

var FMagic      : cardinal = 0;
    FMagic95    : boolean  = false;
    FMagicReady : boolean  = false;

function Magic : cardinal;

  function Fs(index: cardinal) : cardinal;
  asm
    mov eax, fs:[eax]
  end;

var c1 : dword;
begin
  if not FMagicReady then begin
    FMagicReady := true;
    FMagic := GetCurrentThreadID xor (Fs($18) - $10);
    if (not TryRead(@TPACardinal(GetCurrentThreadID xor FMagic)^[2], @c1, 4)) or
       (c1 <> GetCurrentProcessID xor FMagic) then begin
      FMagic := GetCurrentProcessID xor Fs($30);
      if (not TryRead(@TPACardinal(GetCurrentThreadID xor FMagic)^[14], @c1, 4)) or
         (c1 <> GetCurrentProcessID xor FMagic) then
        FMagic := 0;
    end else
      FMagic95 := true;
  end;
  result := FMagic;
end;

function Magic95 : boolean;
begin
  if not FMagicReady then Magic;
  result := FMagic95;
end;

// ***************************************************************

type
  TTryRead = record
    areaBegin : dword;
    areaEnd   : dword;
    readable  : boolean;
  end;
  TDATryRead = array of TTryRead;
  TPDATryRead = ^TDATryRead;

function StartTryRead : dword;
var tr  : TPDATryRead;
    trc : integer;
    mbi : TMemoryBasicInformation;
    c1  : dword;
    b1  : boolean;
begin
  New(tr);
  SetLength(tr^, 64);
  trc := 0;
  c1 := 0;
  while (c1 < $80000000) and (VirtualQuery(pointer(c1), mbi, sizeOf(mbi)) = sizeOf(mbi)) do begin
    b1 := (mbi.State = MEM_COMMIT) and
          ( (mbi.Protect = PAGE_READONLY) or
            (mbi.Protect = PAGE_READWRITE) or
            (mbi.Protect = PAGE_EXECUTE) or
            (mbi.Protect = PAGE_EXECUTE_READ) or
            (mbi.Protect = PAGE_EXECUTE_READWRITE) );
    if (trc = 0) or (tr^[trc - 1].readable <> b1) then begin
      if trc = Length(tr^) then
        SetLength(tr^, trc * 3 div 2);
      tr^[trc].areaBegin := c1;
      tr^[trc].readable  := b1;
      inc(trc);
    end;
    inc(c1, mbi.RegionSize);
    tr^[trc - 1].areaEnd := c1;
  end;
  SetLength(tr^, trc);
  result := dword(tr);
end;

procedure EndTryRead(tryRead: dword);
begin
  try
    Dispose(TPDATryRead(tryRead));
  except end;
end;

function CheckTryRead(tryRead: dword; mem: pointer; len: integer) : boolean;
var i1, i2, i3 : integer;
    b1         : boolean;
begin
  result := false;
  try
    i3 := length(TPDATryRead(tryRead)^);
    i1 := i3 div 2;
    i2 := (i1 + 2) div 2;
    b1 := false;
    while i2 > 0 do begin
      if dword(mem) < TPDATryRead(tryRead)^[i1].areaBegin then begin
        dec(i1, i2);
        if i1 < 0 then i1 := 0;
      end else if dword(mem) < TPDATryRead(tryRead)^[i1].areaEnd then begin
        result := TPDATryRead(tryRead)^[i1].readable;
        exit;
      end else begin
        inc(i1, i2);
        if i1 >= i3 then i1 := i3 - 1;
      end;
      if b1 then break;
      if i2 = 1 then b1 := true
      else           i2 := (i2 + 1) div 2;
    end;
  except end;
end;

var
  ReadProcessMemory  : function (process: dword; const addr: pointer; buf: pointer; size: dword; var written: dword) : bool stdcall = nil;
  WriteProcessMemory : function (process: dword; const addr: pointer; buf: pointer; size: dword; var written: dword) : bool stdcall = nil;

function TryRead(src, dst: pointer; count: integer; tryRead: dword = 0) : boolean;
var dummy : dword;
begin
  if (tryRead = 0) or CheckTryRead(tryRead, src, count) then begin
    if @ReadProcessMemory = nil then
      ReadProcessMemory  := KernelProc(CReadProcessMemory);
    result := (src <> nil) and ReadProcessMemory(GetCurrentProcess, src, dst, count, dummy) and (integer(dummy) = count);
  end else
    result := false;
end;

function TryWrite(src, dst: pointer; count: integer; tryRead: dword = 0) : boolean;
var dummy : dword;
begin
  if (tryRead = 0) or CheckTryRead(tryRead, dst, count) then begin
    if @WriteProcessMemory = nil then
      WriteProcessMemory := KernelProc(CWriteProcessMemory);
    result := (dst <> nil) and WriteProcessMemory(GetCurrentProcess, dst, src, count, dummy) and (integer(dummy) = count);
  end else
    result := false;
end;

// ***************************************************************

end.
