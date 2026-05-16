library RarWCX;

{$mode objfpc}{$H+}
{$E wcx64}

uses
  Windows, SysUtils, Classes, Unrar, WcxPlugin;

type
  PRarArchive = ^TRarArchive;
  TRarArchive = record
    ArchiveName, Password: UnicodeString;
    Rar: TRarUnpacker;
    Index, OpenMode: Integer;
    ChangeVolProcW: TChangeVolProcW;
    ProcessDataProcW: TProcessDataProcW;
  end;

var
  CryptProcW: TPkCryptProcW = nil;

procedure Log(const S: string);
var
  F: TextFile;
  Buf: array[0..MAX_PATH] of Char;
  FN: string;
begin
  Exit; //no need to log now
  try
    FillChar(Buf, SizeOf(Buf), 0);
    if GetModuleFileName(HInstance, Buf, MAX_PATH) <> 0 then
      FN := ExtractFilePath(StrPas(Buf)) + 'rar_log.txt'
    else
      FN := 'rar_log.txt';
    AssignFile(F, FN);
    if FileExists(FN) then Append(F) else Rewrite(F);
    try
      WriteLn(F, FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', Now), '  ', S);
    finally
      CloseFile(F);
    end;
  except
  end;
end;

function PtrStr(P: Pointer): string;
begin
  if P = nil then Result := 'nil'
  else Result := '$' + IntToHex(PtrUInt(P), SizeOf(Pointer) * 2);
end;

function WideStr(P: PWideChar): string;
begin
  try
    if P = nil then Result := '<nil>' else Result := Copy(string(UnicodeString(P)), 1, 300);
  except
    Result := '<bad PWideChar ' + PtrStr(P) + '>';
  end;
end;

function AnsiStr(P: PAnsiChar): string;
begin
  try
    if P = nil then Result := '<nil>' else Result := Copy(string(AnsiString(P)), 1, 300);
  except
    Result := '<bad PAnsiChar ' + PtrStr(P) + '>';
  end;
end;

procedure CopyAnsi(const S: AnsiString; var Buf; MaxChars: Integer);
var N: Integer;
begin
  FillChar(Buf, MaxChars, 0);
  N := Length(S);
  if N > MaxChars - 1 then N := MaxChars - 1;
  if N > 0 then Move(PAnsiChar(S)^, Buf, N);
end;

procedure CopyWide(const S: UnicodeString; var Buf; MaxChars: Integer);
var N: Integer;
begin
  FillChar(Buf, MaxChars * SizeOf(WideChar), 0);
  N := Length(S);
  if N > MaxChars - 1 then N := MaxChars - 1;
  if N > 0 then Move(PWideChar(S)^, Buf, N * SizeOf(WideChar));
end;

function DosTime(DT: TDateTime): LongInt;
var Y, M, D, H, N, S, MS: Word;
begin
  Result := 0;
  if DT <= 0 then Exit;
  DecodeDate(DT, Y, M, D);
  DecodeTime(DT, H, N, S, MS);
  if Y < 1980 then Y := 1980;
  Result := LongInt(((Y - 1980) shl 25) or (M shl 21) or (D shl 16) or
                    (H shl 11) or (N shl 5) or (S div 2));
end;

function AskPassword(A: PRarArchive; NoUI: Boolean): Boolean;
var
  Buf: array[0..511] of WideChar;
  Mode: Integer;
begin
  Result := False;
  A^.Password := '';
  if not Assigned(CryptProcW) then Exit;
  FillChar(Buf, SizeOf(Buf), 0);
  if NoUI then Mode := PK_CRYPT_LOAD_PASSWORD_NO_UI else Mode := PK_CRYPT_LOAD_PASSWORD;
  if CryptProcW(0, Mode, PWideChar(A^.ArchiveName), @Buf[0], Length(Buf)) = 0 then
  begin
    A^.Password := UnicodeString(PWideChar(@Buf[0]));
    Result := A^.Password <> '';
  end;
  FillChar(Buf, SizeOf(Buf), 0);
end;

function ReopenRar(A: PRarArchive; const Pass: UnicodeString): Boolean;
begin
  FreeAndNil(A^.Rar);
  A^.Rar := TRarUnpacker.Create(String(A^.ArchiveName), String(Pass));
  Result := A^.Rar.Count > 0;
end;

function OpenRar(A: PRarArchive): Boolean;
begin
  Result := ReopenRar(A, '');
  if not Result and (AskPassword(A, True) or AskPassword(A, False)) then
    Result := ReopenRar(A, A^.Password);
end;

function OpenArchiveW(var ArchiveData: tOpenArchiveDataW): THandle; stdcall;
var A: PRarArchive;
begin
  Log('OpenArchiveW name=' + WideStr(ArchiveData.ArcName) + ' mode=' + IntToStr(ArchiveData.OpenMode));
  Result := 0;
  ArchiveData.OpenResult := E_BAD_ARCHIVE;
  New(A);
  FillChar(A^, SizeOf(A^), 0);
  try
    A^.ArchiveName := UnicodeString(ArchiveData.ArcName);
    A^.Index := -1;
    A^.OpenMode := ArchiveData.OpenMode;
    if not FileExists(String(A^.ArchiveName)) then
      ArchiveData.OpenResult := E_EOPEN
    else if OpenRar(A) then
    begin
      ArchiveData.OpenResult := E_SUCCESS;
      Exit(THandle(A));
    end;
    Dispose(A);
  except
    FreeAndNil(A^.Rar);
    Dispose(A);
    ArchiveData.OpenResult := E_BAD_ARCHIVE;
  end;
end;

function ReadHeaderExW(hArcData: THandle; var HeaderData: THeaderDataExW): Integer; stdcall;
var
  A: PRarArchive;
  Name: String;
  UName: UnicodeString;
  Size, TmpSize: Int64;
  DT, TmpDT: TDateTime;
begin
  Log('ReadHeaderExW h=' + IntToStr(hArcData));
  FillChar(HeaderData, SizeOf(HeaderData), 0);
  Result := E_BAD_ARCHIVE;
  A := PRarArchive(hArcData);
  if (A = nil) or (A^.Rar = nil) then Exit;

  Inc(A^.Index);
  if A^.Index >= A^.Rar.Count then Exit(E_END_ARCHIVE);

  Name := A^.Rar.GetName(A^.Index);
  UName := UnicodeString(Name);
  Size := 0;
  DT := 0;

  { TRarUnpacker gives size/date through its iterator, so find matching entry. }
  A^.Rar.Reset;
  while A^.Rar.NextEntry(Name, TmpSize, TmpDT) do
    if A^.Rar.GetName(A^.Index) = Name then
    begin
      Size := TmpSize;
      DT := TmpDT;
      Break;
    end;

  CopyWide(A^.ArchiveName, HeaderData.ArcName, 1024);
  CopyWide(UName, HeaderData.FileName, 1024);
  HeaderData.UnpSize := LongWord(UInt64(Size) and $FFFFFFFF);
  HeaderData.UnpSizeHigh := LongWord(UInt64(Size) shr 32);
  HeaderData.PackSize := HeaderData.UnpSize;
  HeaderData.PackSizeHigh := HeaderData.UnpSizeHigh;
  HeaderData.FileTime := DosTime(DT);
  HeaderData.FileAttr := FILE_ATTRIBUTE_ARCHIVE;
  HeaderData.UnpVer := 29;
  HeaderData.Method := 0;
  Log('Header OK: ' + string(UName));
  Result := E_SUCCESS;
end;

procedure EnsurePassword(A: PRarArchive);
begin
  if (A^.Password = '') and Assigned(CryptProcW) then
    if AskPassword(A, True) or AskPassword(A, False) then
      ReopenRar(A, A^.Password);
end;

function BuildDest(A: PRarArchive; DestPath, DestName: PWideChar): UnicodeString;
var Entry, Base: UnicodeString;
begin
  Result := '';
  if (A^.Index < 0) or (A^.Index >= A^.Rar.Count) then Exit;
  Entry := UnicodeString(A^.Rar.GetName(A^.Index));
  if Entry = '' then Exit;
  if DestName <> nil then Result := UnicodeString(DestName);
  if Result = '' then Result := Entry;
  if DestPath <> nil then Base := UnicodeString(DestPath) else Base := '';
  if (Base <> '') and not ((Result[1] = '\') or ((Length(Result) > 1) and (Result[2] = ':'))) then
    Result := IncludeTrailingPathDelimiter(Base) + Result;
end;

function ProcessFileW(hArcData: THandle; Operation: Integer; DestPath, DestName: PWideChar): Integer; stdcall;
var
  A: PRarArchive;
  OutName, Entry: UnicodeString;
  FS: TFileStream;
begin
  Log('ProcessFileW h=' + IntToStr(hArcData) + ' op=' + IntToStr(Operation) +
      ' path=' + WideStr(DestPath) + ' name=' + WideStr(DestName));
  Result := E_SUCCESS;
  try
    A := PRarArchive(hArcData);
    if (A = nil) or (A^.Rar = nil) then Exit(E_BAD_ARCHIVE);
    if Operation <> PK_EXTRACT then Exit(E_SUCCESS);

    OutName := BuildDest(A, DestPath, DestName);
    if OutName = '' then Exit(E_SUCCESS);

    Entry := UnicodeString(A^.Rar.GetName(A^.Index));
    if (Entry <> '') and (Entry[Length(Entry)] in ['/', '\']) then
    begin
      ForceDirectories(String(OutName));
      Exit(E_SUCCESS);
    end;

    EnsurePassword(A);
    ForceDirectories(ExtractFileDir(String(OutName)));
    FS := TFileStream.Create(String(OutName), fmCreate);
    try
      if not A^.Rar.Extract(A^.Index, FS) then Result := E_BAD_DATA;
    finally
      FS.Free;
    end;
  except
    on E: EOutOfMemory do Result := E_NO_MEMORY;
    on E: EFCreateError do Result := E_ECREATE;
    on E: EFOpenError do Result := E_EOPEN;
    on E: EFilerError do Result := E_EWRITE;
    on E: Exception do Result := E_BAD_DATA;
  end;
end;

function CloseArchive(hArcData: THandle): Integer; stdcall;
var A: PRarArchive;
begin
  Log('CloseArchive h=' + IntToStr(hArcData));
  A := PRarArchive(hArcData);
  if A <> nil then
  begin
    FreeAndNil(A^.Rar);
    Dispose(A);
  end;
  Result := E_SUCCESS;
end;

procedure SetChangeVolProcW(hArcData: THandle; pChangeVolProc1: TChangeVolProcW); stdcall;
var A: PRarArchive;
begin
  Log('SetChangeVolProcW h=' + IntToStr(hArcData) + ' proc=' + PtrStr(Pointer(pChangeVolProc1)));
  A := PRarArchive(hArcData);
  if A <> nil then A^.ChangeVolProcW := pChangeVolProc1;
end;

procedure SetProcessDataProcW(hArcData: THandle; pProcessDataProc: TProcessDataProcW); stdcall;
var A: PRarArchive;
begin
  Log('SetProcessDataProcW h=' + IntToStr(hArcData) + ' proc=' + PtrStr(Pointer(pProcessDataProc)));
  A := PRarArchive(hArcData);
  if A <> nil then A^.ProcessDataProcW := pProcessDataProc;
end;

procedure SetCryptCallbackW(pCryptProc: TPkCryptProcW; CryptoNr, Flags: Integer); stdcall;
begin
  Log('SetCryptCallbackW proc=' + PtrStr(Pointer(pCryptProc)) + ' crypto=' + IntToStr(CryptoNr) + ' flags=' + IntToStr(Flags));
  CryptProcW := pCryptProc;
end;

function GetPackerCaps: Integer; stdcall;
begin
  Log('GetPackerCaps');
  Result := PK_CAPS_BY_CONTENT or PK_CAPS_ENCRYPT;
end;

function IsRarFile(const FN: UnicodeString): Boolean;
const
  Rar4: array[0..6] of Byte = ($52,$61,$72,$21,$1A,$07,$00);
  Rar5: array[0..7] of Byte = ($52,$61,$72,$21,$1A,$07,$01,$00);
var
  FS: TFileStream;
  Sig: array[0..7] of Byte;
begin
  Result := False;
  try
    FS := TFileStream.Create(String(FN), fmOpenRead or fmShareDenyWrite);
    try
      Result := (FS.Read(Sig, SizeOf(Sig)) = SizeOf(Sig)) and
                (CompareMem(@Sig[0], @Rar5[0], 8) or CompareMem(@Sig[0], @Rar4[0], 7));
    finally
      FS.Free;
    end;
  except
  end;
end;

function CanYouHandleThisFileW(FileName: PWideChar): Boolean; stdcall;
begin
  Log('CanYouHandleThisFileW name=' + WideStr(FileName));
  Result := IsRarFile(UnicodeString(FileName));
end;

{ ANSI compatibility exports: keep them because TC may probe classic WCX names. }
function OpenArchive(var ArchiveData: tOpenArchiveData): THandle; stdcall;
var W: tOpenArchiveDataW; N: UnicodeString;
begin
  Log('OpenArchive name=' + AnsiStr(ArchiveData.ArcName));
  FillChar(W, SizeOf(W), 0);
  N := UnicodeString(AnsiString(ArchiveData.ArcName));
  W.ArcName := PWideChar(N);
  W.OpenMode := ArchiveData.OpenMode;
  Result := OpenArchiveW(W);
  ArchiveData.OpenResult := W.OpenResult;
  ArchiveData.CmtSize := W.CmtSize;
  ArchiveData.CmtState := W.CmtState;
end;

function ReadHeaderEx(hArcData: THandle; var HeaderData: THeaderDataEx): Integer; stdcall;
var W: THeaderDataExW;
begin
  Log('ReadHeaderEx h=' + IntToStr(hArcData));
  FillChar(HeaderData, SizeOf(HeaderData), 0);
  Result := ReadHeaderExW(hArcData, W);
  if Result <> E_SUCCESS then Exit;
  CopyAnsi(AnsiString(UnicodeString(PWideChar(@W.ArcName[0]))), HeaderData.ArcName, 1024);
  CopyAnsi(AnsiString(UnicodeString(PWideChar(@W.FileName[0]))), HeaderData.FileName, 1024);
  HeaderData.Flags := W.Flags;
  HeaderData.PackSize := W.PackSize;
  HeaderData.PackSizeHigh := W.PackSizeHigh;
  HeaderData.UnpSize := W.UnpSize;
  HeaderData.UnpSizeHigh := W.UnpSizeHigh;
  HeaderData.HostOS := W.HostOS;
  HeaderData.FileCRC := W.FileCRC;
  HeaderData.FileTime := W.FileTime;
  HeaderData.UnpVer := W.UnpVer;
  HeaderData.Method := W.Method;
  HeaderData.FileAttr := W.FileAttr;
  HeaderData.CmtSize := W.CmtSize;
  HeaderData.CmtState := W.CmtState;
end;

function ReadHeader(hArcData: THandle; var HeaderData: THeaderData): Integer; stdcall;
var Ex: THeaderDataEx;
begin
  Log('ReadHeader h=' + IntToStr(hArcData));
  FillChar(HeaderData, SizeOf(HeaderData), 0);
  Result := ReadHeaderEx(hArcData, Ex);
  if Result <> E_SUCCESS then Exit;
  CopyAnsi(PAnsiChar(@Ex.ArcName[0]), HeaderData.ArcName, 260);
  CopyAnsi(PAnsiChar(@Ex.FileName[0]), HeaderData.FileName, 260);
  HeaderData.Flags := Ex.Flags;
  HeaderData.PackSize := Ex.PackSize;
  HeaderData.UnpSize := Ex.UnpSize;
  HeaderData.HostOS := Ex.HostOS;
  HeaderData.FileCRC := Ex.FileCRC;
  HeaderData.FileTime := Ex.FileTime;
  HeaderData.UnpVer := Ex.UnpVer;
  HeaderData.Method := Ex.Method;
  HeaderData.FileAttr := Ex.FileAttr;
  HeaderData.CmtSize := Ex.CmtSize;
  HeaderData.CmtState := Ex.CmtState;
end;

function ProcessFile(hArcData: THandle; Operation: Integer; DestPath, DestName: PAnsiChar): Integer; stdcall;
var WP, WN: UnicodeString; P1, P2: PWideChar;
begin
  Log('ProcessFile h=' + IntToStr(hArcData) + ' op=' + IntToStr(Operation) +
      ' path=' + AnsiStr(DestPath) + ' name=' + AnsiStr(DestName));
  try
    if Operation <> PK_EXTRACT then Exit(E_SUCCESS);
    P1 := nil; P2 := nil;
    if DestPath <> nil then begin WP := UnicodeString(AnsiString(DestPath)); P1 := PWideChar(WP); end;
    if DestName <> nil then begin WN := UnicodeString(AnsiString(DestName)); P2 := PWideChar(WN); end;
    Result := ProcessFileW(hArcData, Operation, P1, P2);
  except
    Result := E_BAD_DATA;
  end;
end;

procedure SetChangeVolProc(hArcData: THandle; pChangeVolProc1: TChangeVolProc); stdcall;
begin
  Log('SetChangeVolProc h=' + IntToStr(hArcData) + ' proc=' + PtrStr(Pointer(pChangeVolProc1)));
end;

procedure SetProcessDataProc(hArcData: THandle; pProcessDataProc: TProcessDataProc); stdcall;
begin
  Log('SetProcessDataProc h=' + IntToStr(hArcData) + ' proc=' + PtrStr(Pointer(pProcessDataProc)));
end;

procedure SetCryptCallback(pCryptProc: TPkCryptProc; CryptoNr, Flags: Integer); stdcall;
begin
  Log('SetCryptCallback proc=' + PtrStr(Pointer(pCryptProc)) + ' crypto=' + IntToStr(CryptoNr) + ' flags=' + IntToStr(Flags));
end;

function CanYouHandleThisFile(FileName: PAnsiChar): Boolean; stdcall;
begin
  Log('CanYouHandleThisFile name=' + AnsiStr(FileName));
  Result := IsRarFile(UnicodeString(AnsiString(FileName)));
end;

exports
  OpenArchive name 'OpenArchive',
  OpenArchiveW name 'OpenArchiveW',
  ReadHeader name 'ReadHeader',
  ReadHeaderEx name 'ReadHeaderEx',
  ReadHeaderExW name 'ReadHeaderExW',
  ProcessFile name 'ProcessFile',
  ProcessFileW name 'ProcessFileW',
  CloseArchive name 'CloseArchive',
  SetChangeVolProc name 'SetChangeVolProc',
  SetChangeVolProcW name 'SetChangeVolProcW',
  SetProcessDataProc name 'SetProcessDataProc',
  SetProcessDataProcW name 'SetProcessDataProcW',
  SetCryptCallback name 'SetCryptCallback',
  SetCryptCallbackW name 'SetCryptCallbackW',
  GetPackerCaps name 'GetPackerCaps',
  CanYouHandleThisFile name 'CanYouHandleThisFile',
  CanYouHandleThisFileW name 'CanYouHandleThisFileW';

begin
  Log('library initialization');
end.
