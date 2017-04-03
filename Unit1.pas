unit Unit1;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, maddisasm, StdCtrls, Buttons, ExtCtrls;

type
  TForm1 = class(TForm)
    Memo1: TMemo;
    LabeledEdit1: TLabeledEdit;
    LabeledEdit2: TLabeledEdit;
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    BitBtn3: TBitBtn;
    OpenDialog1: TOpenDialog;
    BitBtn4: TBitBtn;
    procedure BitBtn1Click(Sender: TObject);
    procedure BitBtn2Click(Sender: TObject);
    procedure BitBtn3Click(Sender: TObject);
    procedure BitBtn4Click(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure LabeledEdit2Change(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
    function GetCode(strFileName: string; strOffset: cardinal): pointer;
    function Disasm(strAsm: pointer): string;
    function fFunc1(): boolean;
  end;

type
   PIMAGE_DOS_HEADER=^IMAGE_DOS_HEADER;
type
   PIMAGE_NT_HEADERS=^IMAGE_NT_HEADERS;
type
   PIMAGE_SECTION_HEADER=^IMAGE_SECTION_HEADER;

var
  PEHead:IMAGE_NT_HEADERS;
  EP: Cardinal;

var
  Form1: TForm1;

implementation

{$R *.dfm}

function TForm1.GetCode(strFileName: string; strOffset: cardinal): pointer;
var
hFile: integer;
read_bytes: cardinal;
EP_code: array[1..64000] of byte;
begin
//открываем файл
hFile:=CreateFileA(pchar(strFileName), GENERIC_READ, FILE_SHARE_READ + FILE_SHARE_WRITE, NIL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
//если файл открыт успешно
if hFile<>-1 then begin
//устанавливаем файловый указатель на начало дизассемблируемого кода
SetFilePointer(hFile,strOffset,NIL,FILE_BEGIN);
//считываем 64000 байт кода
ReadFile(hFile,EP_Code,64000,read_bytes,NIL);
//закрываем файл
CloseHandle(hFile);
//возвращаем pointer на считанный код
result:=@EP_Code;
end else begin
//если не смогли открыть файл - выходим
exit;
end;
end;

function TForm1.Disasm(strAsm: pointer): string;
var
strDisAsm, strdasm: string;
retval: TCodeInfo;
begin
//получим в strDisAsm первую строчку кода, а в retval - структуру, в которой имеется pointer на следующую ассемблерную команду
retval:=madDisAsm.ParseCode(strAsm,strDisAsm);
//в переменной strdasm мы будем хранить весь дизассемблированный листинг
strdasm:=strDisAsm;
//перебераем циклом команды до тех пор пока не встретим ret
while strpos(pchar(strDisAsm),'ret')= nil do begin
//дизассемблируем очередную команду
retval:=madDisAsm.ParseCode(retval.Next,strDisAsm);
//добавляем ее в конец дизассемблированного листинга
strdasm:=strdasm + #13#10 + strDisAsm;
//Application.ProcessMessages;
end;
//возвращаем дизассемблированный код
result:=strdasm;
end;

procedure TForm1.BitBtn1Click(Sender: TObject);
begin
if opendialog1.Execute then
labelededit1.Text := opendialog1.FileName;
end;

procedure TForm1.BitBtn2Click(Sender: TObject);
begin
memo1.Text:=Disasm(GetCode(labelededit1.Text, ep));
end;

function TForm1.fFunc1: boolean;
begin
  ShowMessage('Hello World');
end;

procedure proc2;
begin
  ShowMessage('trololo');
end;

procedure TForm1.BitBtn3Click(Sender: TObject);
type
  TfFunc1 = function(): boolean;
var
  disAsm : string;
  p2: function(): boolean;
begin
  p2 := @TForm1.fFunc1;
//  ParseFunction(@p2, disAsm);
  ParseFunction(@proc2, disAsm);
  memo1.Text:= disAsm;
end;

procedure TForm1.BitBtn4Click(Sender: TObject);
var
  disAsm : string;
begin
ParseCode(GetProcAddress(GetModuleHandle('kernel32.dll'), 'CreateFileA'), disAsm);
memo1.Text:= disAsm;
end;

function GetCodeSectionOffset(FN: String): Cardinal;
var
        DosHead:IMAGE_DOS_HEADER;
        imgsection:IMAGE_SECTION_HEADER;
        i:integer;
        numbers:word;
        buf,EPSection:array[0..512] of char;
        EntryPoint,FileOffset:integer;
        hFile,hFileMapping:cardinal;
        p,a:PBYTE;
begin
  FileOffset := 1024;
  hFile:=CreateFile(pchar(fn),GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ or FILE_SHARE_WRITE,nil,OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,0);
  if (hFile<>INVALID_HANDLE_VALUE) then
	begin
  hFileMapping:=CreateFileMapping(hFile, nil, PAGE_READWRITE, 0, 0, 'mappedfile');
  if hFileMapping<>0 then
  begin
  p:=MapViewOfFile(hFileMapping,FILE_MAP_READ,0,0,0);
  a:=p;
  doshead:=PIMAGE_DOS_HEADER(p)^;
  if p<> nil then
  if doshead.e_magic=IMAGE_DOS_SIGNATURE then
  begin
  p:=pointer(integer(p)+doshead._lfanew);
  pehead:=PIMAGE_NT_HEADERS(p)^;
  if pehead.Signature=IMAGE_NT_SIGNATURE then
  begin
  EntryPoint:=PEHead.OptionalHeader.AddressOfEntryPoint;
     numbers:=PEHead.FileHeader.NumberOfSections;
     p:=pointer(integer(p)+sizeof(IMAGE_NT_HEADERS));
     for i:=1 to numbers do
     begin
     imgsection:=PIMAGE_SECTION_HEADER(p)^;
     lstrcpyn(@buf,@imgsection.name,8);
if (EntryPoint>=imgsection.VirtualAddress)and(EntryPoint<=imgsection.VirtualAddress+imgsection.Misc.VirtualSize) then
begin
EPSection:=buf;
FileOffset:=EntryPoint-imgsection.VirtualAddress+imgsection.PointerToRawData;
end;
 p:=pointer(integer(p)+sizeof(IMAGE_SECTION_HEADER));
end;
//RESULT := FileOffset;
end;
//RESULT := FileOffset;
  end;
  UnMapViewOfFile(a);
  end;
  CloseHandle(hFileMapping);
  CloseHandle(hFile);
  end;
  RESULT := FileOffset;
end;

procedure TForm1.FormCreate(Sender: TObject);
var
  s: string;
begin
labelededit1.Text := extractfilepath(ParamStr(0))+'test.exe';
//адрес точки входа - 1024 (400h). Для простеньких ассемблерных прог
//адрес точки входа часто равен смещению секции кода, которое часто
//равно именно 400h
EP:=GetCodeSectionOffset(labelededit1.Text);
s := inttohex(EP,8);
labelededit2.Text := s;
end;

procedure TForm1.LabeledEdit2Change(Sender: TObject);
begin
ep:=strtoint(LabeledEdit2.Text);
end;

end.
