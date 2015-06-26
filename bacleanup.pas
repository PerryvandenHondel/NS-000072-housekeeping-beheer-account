{
	Beheer Accounts Cleanup

	
	
	VERSION:
	========
	
	Version		Date		Author		Description
	-------		---------	----------	----------------------------------
	04			2015-01-08	PVDH		Initial version in Pascal



	FLOW:
	=====
	
	Program
		ProgInit()
		ProgRun()
			Step1Export();
				ProcessDomain()
					CreateExportAccount()
					CreateExportDcList()
					CreateExportLastLogon()
		ProgDone()

	
	
	PRCOEDURES AND FUNCTIONS:
	=========================
	
		procedure CreateExportAccount(strFnameAccount: string; strDomainNetbios: string; strBaseOu: string);
		procedure CreateExportDcList(strFnameDcList: string; strRootDn: string);
		procedure CreateExportLastLogon(strFnameLastLogon: string; strRootDse: string; strBaseOu: string);
		procedure ProgDone();
		procedure ProgInit();
		procedure ProgRun();
		procedure Step1Export();
	
}


program BACleanup;



{$MODE OBJFPC} // Do not forget this ever
{$M+}



uses
	DateUtils,
	Process,
	SysUtils,
	StrUtils,
	UTextFile,
	UTextSeparated,
	USupportLibrary;


	
const	
	DAYS_DISABLE 					=	90;		// Disable accounts older then...
	DAYS_DELETE 					=	180;	// Delete accounts older then...
	ADS_UF_ACCOUNTDISABLE			=	2;		// UserAccountControl bit for account disable
	ADS_UF_DONT_EXPIRE_PASSWD 		= 	65536;	// UserAccountControl bit for Password Never Expires
	//SECS_PER_DAY 					= 	86400;	// Number of seconds per day (24 * 60 * 60 = 86400)

	FNAME_EXPORT = 					 	'export.tmp';
	FNAME_ACTION = 						'action.cmd';
	FNAME_DCLIST = 						'export-dc-list.tmp';
	FNAME_ACCOUNT = 					'export-account.tmp';
	FNAME_LASTLOGON = 					'export-last-logon.tmp'; 
	FNAME_CONFIG = 						'bacleanup.conf';
	FNAME_LOG = 						'log.tsv';
	SEPARATOR_EXPORT = 					#9;		// Separator of export file is a TAB, Chr(9) or #9
	
	
var
	//giSecDisable: LongInt;
	//giSecDelete: LongInt;
	giTotalDisable: integer;
	giTotalDelete: integer;
	
	gdtNow: TDateTime;
	//tsvExport: CTextSeparated;	
	//tsvLog: CTextSeparated;
	//txtBatch: CTextFile;
	gsBatchNumber: string; 			// Contains the batch number in format YYYYMMDDHHMMSS
	garrHeader: TStringArray;
	gintSecondsDisable: integer;
	gintSecondsDelete: integer;
	strDn: string;
	dtLatest: TDateTime;


function GetDnsDomainFromDn(sDn: string): string;
{
	Extract the DNS domain name from a DN
	
	CN=Jurgen.Caspers,OU=Normal,OU=Accounts,OU=RBAC,DC=REC,DC=NSINT > rec.nsint
}

var
	p: integer;
	r: string;
begin
	//WriteLn('GetDnsDomainFromDn(): ', sDn);
	p := Pos('DC=', sDn);
	//WriteLn(p);
	r := RightStr(sDn, length(sDn) - p + 1);
	//WriteLn(r);
	
	r := ReplaceText(r, 'DC=', '');
	r := ReplaceText(r, ',', '.');
	
	GetDnsDomainFromDn := r;
end; // of function GetDnsDomainFromDn


function GetRootDseFromDn(sDn: string): string;
{
	Extract the RootDse name from a DN
	
	CN=Jurgen.Caspers,OU=Normal,OU=Accounts,OU=RBAC,DC=REC,DC=NSINT > DC=REC,DC=nsint
}
var
	p: integer;
	r: string;
begin
	//WriteLn('GetRootDseFromDn(): ', sDn);
	p := Pos('DC=', sDn);
	//WriteLn(p);
	r := RightStr(sDn, length(sDn) - p + 1);
	//WriteLn(r);
		
	GetRootDseFromDn := r;
end; // of function GetRootDseFromDn



function IsBeheeraccount(sSam: string): boolean;

type
	TPrefix = array[0..10] of string;

var
	aPrefix: TPrefix;
	x: integer;
	r: boolean;
	
begin
	r := false;

	aPrefix[0] := 'BEH';
	aPrefix[1] := 'NSA';
	aPrefix[2] := 'NSS';
	aPrefix[3] := 'NSI';
	aPrefix[4] := 'KPN';
	aPrefix[5] := 'GTN';
	aPrefix[6] := 'HP';
	aPrefix[7] := 'EDS';
	aPrefix[8] := 'CSC';
	aPrefix[9] := 'ADB';
	aPrefix[10] := 'REC';
	
	for x := 0 to Length(aPrefix) - 1 do
	begin
		//WriteLn(x, ': ', aPrefix[x]);
		if Pos(aPrefix[x] + '_', UpperCase(sSam)) = 1 then
			r := true;
	end;
	IsBeheeraccount := r;
end; // of function IsBeheeraccount



function GetSupportOrg(sSam: string): string;
{
	Returns the support organisation of the beheer account
}

var
	sPrefix: string;
	r: string;
begin
	//WriteLn(Pos('_', sSam));
	
	sPrefix := LeftStr(sSam, Pos('_', sSam) - 1);
	//WriteLn(sPrefix);
	
	case UpperCase(sPrefix) of
		'NSA', 'NSS', 'NSI', 'BEH', 'REC', 'ADB': r := 'NS';
		'KPN', 'GTN': r:= 'KPN';
		'HP', 'EDS': r := 'HP';
		'CSC': r := 'CSC';
	else
		r:= 'UNKNOWN';
	end; // of Case sPrefix of
	GetSupportOrg := r;
end; // of function GetSupportOrg



function IsDisabled(iUac: LongInt): boolean;
	{'
	''	Check the disabled status of an account using the UAC
	''	(User Account Control Value)
	''	
	''	Magic line: If (intUac And ADS_UF_ACCOUNTDISABLE) = ADS_UF_ACCOUNTDISABLE Then DISABLED
	''
	''	Returns
	''		True: 	Account is locked
	''		False:	Account is not locked
	'}
begin;
	if (iUac and ADS_UF_ACCOUNTDISABLE) = ADS_UF_ACCOUNTDISABLE then
		IsDisabled := true
	else
		IsDisabled := false;
end; // of function IsDisabled
	

	
procedure DoCommandDisable(sDn: string; sDesc: string);
var
	sCmd: string;
begin
	// First update the description field Description
	sCmd := 'dsmod.exe user "' + sDn + '" -desc "BA HOUSEKEEPING ' + gsBatchNumber + ', ' + sDesc + '"';
	//txtBatch.WriteToFile(sCmd);

	// Secondly disable the account using DSMOD.EXE to disable the account
	sCmd := 'dsmod.exe user "' + sDn + '" -disabled yes';
	//txtBatch.WriteToFile(sCmd);
	
	// Add a blank line
	//txtBatch.WriteToFile('');
end; // of procedure WriteDisable


procedure DoCommandDelete(sDn: string; sSam: string);
var
	sCmd: string;
begin
	sCmd := 'adfind.exe -b "' + sDn + '" ';
	sCmd := sCmd + '-tdcs -tdcsfmt "%%YYYY%%-%%MM%%-%%DD%% %%HH%%:%%mm%%:%%ss%%" ';
	sCmd := sCmd + '-tdcgt -tdcfmt "%%YYYY%%-%%MM%%-%%DD%% %%HH%%:%%mm%%:%%ss%%" ';
	sCmd := sCmd + '>>userinfo\' + sSam + '.txt';
	//txtBatch.WriteToFile(sCmd);
	
	sCmd := 'dsrm.exe "' + sDn + '" -noprompt';
	//txtBatch.WriteToFile(sCmd);
	
	// Add a blank line
	//txtBatch.WriteToFile('');
end; // of procedure WriteDelete



procedure WriteToLog(sDn: string; sSam: string; dtCalc: TDateTime; sWhichUsed: string; iAgoDays: integer; sAction: string; sMessage: string);

var
	sDomain: string;
	sSupportOrg: string;
begin
	// Get the DNS domain name from a DN
	sDomain := GetDnsDomainFromDn(sDn);
	// Get the Support Organization for an SAM account.
	sSupportOrg := GetSupportOrg(sSam);
	
	//tsvLog.WriteToFile(sDomain + #9 + sSupportOrg + #9 + sSam + #9 + DateTimeToStr(dtCalc) + #9 + sWhichUsed + #9 + IntToStr(iAgoDays) + #9 + sAction + #9 + sMessage);
end; // of procedure WriteToLog



procedure ProcessLine(iLine: integer; sDn: string; sSam: string; sDesc: string; sUac: string; sLastLogon: string; sCreated: string);

var
	dtCalc: TDateTime;
	iAgeDay: LongInt;
	iUac: integer;
	sUseWhich: string;
	sAction: string;
	sActionMsg: string;
	
begin
	WriteLn(iLine, Chr(9), sDn, ' ----------------------------------');
	
	if CompareStr('dn', sDn) = 0 then
		// When a new header line is detected, exit this procedure.
		Exit;
	
	//WriteLn(iLine, '|', sDn, '|', sSam, '|', sDesc, '|', sUac, '|', sLastLogon, '|', sCreated);
	
	
	if IsBeheeraccount(sSam) = false then
	begin
		Writeln(sSam + ' is not an beheeraccount, skipping...');
		Exit;
	end;
	
	if Length(sLastLogon) > 0 then
	begin
		WriteLn('Using last logon to calculate: ' + sLastLogon);
		sUseWhich := 'LAST_LOGON';
		dtCalc := StrToDateTime(sLastLogon);
	end
	else
	begin
		WriteLn('Using creation to calculate: ' + sCreated);
		sUseWhich := 'CREATED';
		dtCalc := StrToDateTime(sCreated);
	end;	
	

	iAgeDay := DaysBetween(gdtNow, dtCalc);
	//iAgeDay := iAgeSec Mod SECS_PER_DAY;
	
	//WriteLn('Secs ago: ', iAgeSec);
	WriteLn('Days no action on account: ', iAgeDay);
	
	if iAgeDay > DAYS_DELETE then
	begin
		WriteLn('This account is not used for more then ', iAgeDay, ' days, action > DELETE');
		DoCommandDelete(sDn, sSam);
		sAction := 'DELETE';
		sActionMsg := 'This account is not used for more then ' + IntToStr(iAgeDay) + ' days';
		WriteToLog(sDn, sSam, dtCalc, sUseWhich, iAgeDay, sAction, sActionMsg);
		Inc(giTotalDelete);
		Exit;
	end;
	
	if iAgeDay > DAYS_DISABLE then
	begin
		WriteLn('This account is not used for more then ', IntToStr(iAgeDay), ' days, action > DISABLE');
		
		iUac := StrToInt(sUac);
		
		if IsDisabled(iUac) = false then
		begin
			WriteLn('Disable account');
			sAction := 'DISABLE';
			sActionMsg := 'This account is not used for more then ' + IntToStr(iAgeDay) + ' days';
			WriteToLog(sDn, sSam, dtCalc, sUseWhich, iAgeDay, sAction, sActionMsg);
			DoCommandDisable(sDn, sDesc);
		end
		else
		begin
			sAction := 'NONE';
			sActionMsg := 'Account is already disabled';
			WriteToLog(sDn, sSam, dtCalc, sUseWhich, iAgeDay, sAction, sActionMsg);
			WriteLn('Account is already disabled');
		end;
		
		Inc(giTotalDisable);
		Exit;
	end;
	
	WriteLn('No action needed');
end;  // of procedure ProcessLine


function DateDiffSec(Date1, Date2: TDateTime): int64;
{
	Calculate the number of seconds between 2 dates.
	
	Result:
		< 0		Date2 is newer then Date1
		> 0		Date1 is newer then Date2
		= 0		Date1 is the same as Date2
}
var
	r: integer;
begin
	r := Trunc(86400.0 * (Date1 - Date2)); // Number of seconds between 2 dates
	WriteLn('DateDiffSec(): Date1=', DateTimeToStr(Date1), ' - Date2=', DateTimeToStr(Date2), ' = ', r);
	DateDiffSec := r;
end; // of function DateDiffSec().


function GetLatestLogonDatePerDc(strFNameLastLogon: string; strHostname: string; strDn: string): TDateTime;

var
	c: string;
	f: TextFile;
	strLine: string;
	p: TProcess;
	r: TDateTime;
	strLastLogonDateTime: string;
begin
	c := 'adfind.exe -h ' + strHostname + ' -b ' + EncloseDoubleQuote(strDn) + ' lastLogon -csv -nocsvq -nodn -nocsvheader -tdcs -tdcsfmt "%YYYY%-%MM%-%DD% %HH%:%mm%:%ss%" >>' + strFNameLastLogon;
	
	WriteLn;
	WriteLn('GetLatestLogonDatePerDc(): ', c);
	p := TProcess.Create(nil);
	p.Executable := 'cmd.exe'; 
	p.Parameters.Add('/c ' + c);
	p.Options := [poWaitOnExit, poUsePipes];
	p.Execute;		// Execute the command.
		
	p.Destroy;
	
	// Set the default return value to 0
	r := 0;
	// Open the text file and read the lines from it.
	AssignFile(f, strFNameLastLogon);
	{I+}
	try
		Reset(f);
		repeat
			ReadLn(f, strLine);
			if Pos('>lastLogon: ', strLine) > 0 then
			begin
				strLastLogonDateTime := RightStr(strLine, 19); // Removed '>lastLogon: '.
				if strLastLogonDateTime = '0000-00-00 00:00:00' then
					// The value retrieved from the DC is a blank, So return 0
					r := 0
				else
					r := StrToDateTime(strLastLogonDateTime);
			end
		until Eof(f);
		CloseFile(f);
	except
		on E: EInOutError do
			WriteLn('File ', strFNameLastLogon, ' handeling error occurred, Details: ', E.ClassName, '/', E.Message);
	end;
	
	WriteLn('GetLatestLogonDatePerDc(): r=', DateTimeToStr(r));
	
	GetLatestLogonDatePerDc := r;
end; // of function GetLatestLogonDatePerDc


function GetLatestLogonDate(strAccountDn: string): TDateTime;
{
	adfind -b "DC=prod,DC=ns,DC=nl" -sc dclist
	
	adfind -h NS00DC012.prod.ns.nl -b CN=Perry.vandenHondel,OU=Accounts,DC=prod,DC=ns,DC=nl lastLogon -tdcs -tdcsfmt "%YYYY%-%MM%-%DD% %HH%:%mm%:%ss%"
}
const
	FNAME_TMP_DCLIST = 			'dclist.tmp';
	FNAME_TMP_LASTLOGON = 		'lastlogon.tmp';
var
	p: TProcess;
	p2: TProcess;
	
	c: string;
	c2: string;
	d: string;
	f: TextFile;
	strFqdn: string;
	strLine: string;
	r: TDateTime;
	strLastLogonDateTime: string;
	dtFromDc: TDateTime; 
	intSeconds: int64;
begin
	r := 0;
	
	WriteLn('GetLatestLogonDate(): ', strAccountDn);
	
	d := GetRootDseFromDn(strAccountDn);
	c := 'adfind.exe -b ' + EncloseDoubleQuote(d) + ' -sc dclist >' + FNAME_TMP_DCLIST;

	WriteLn;
	WriteLn('GetLatestLogonDate(): ', c);
	
	// Setup the process to be executed.
	p := TProcess.Create(nil);
	p.Executable := 'cmd.exe'; 
    p.Parameters.Add('/c ' + c);
	// 1) Wait until the process is finished and 
	// 2) do not show output to the console.
	p.Options := [poWaitOnExit, poUsePipes]; 
	p.Execute;		// Execute the command.
	
	p.Destroy;		// Destroy the process.

	// Delete any existing file before.
	DeleteFile(FNAME_TMP_LASTLOGON);
	
	// Open the text file and read the lines from it.
	AssignFile(f, FNAME_TMP_DCLIST);
	{I+}
	try
		Reset(f);
		repeat
			ReadLn(f, strFqdn);
			WriteLn('Working on: ', strFqdn);
			
			// -csv -nocsvq -nodn -nocsvheader
			c2 := 'adfind.exe -h ' + strFqdn + ' -b ' + EncloseDoubleQuote(strAccountDn) + ' lastLogon -tdcs -tdcsfmt "%YYYY%-%MM%-%DD% %HH%:%mm%:%ss%" >>' + FNAME_TMP_LASTLOGON;
	
			p2 := TProcess.Create(nil);
			p2.Executable := 'cmd.exe'; 
			p2.Parameters.Add('/c ' + c2);
			p2.Options := [poWaitOnExit, poUsePipes];
			p2.Execute;		// Execute the command.
		
			p2.Destroy;
			
			//dtFromDc := GetLatestLogonDatePerDc(FNAME_TMP_LASTLOGON, strFqdn, strAccountDn);
		until Eof(f);
		CloseFile(f);
		
		WriteLn('File ', FNAME_TMP_LASTLOGON, ' created.');
	except
		on E: EInOutError do
			WriteLn('File ', FNAME_TMP_DCLIST, ' handeling error occurred, Details: ', E.ClassName, '/', E.Message);
	end;
	GetLatestLogonDate := r;
end; // of function GetLatestLogonDate


function GetPosOfHeaderItem(searchHeaderItem: string): integer;
{
	Get the position of 'searchHeaderItem' in  the header array 'garrHeader'.
	Returns a integer of the position when found.
	Returns  -1 when no found.
}
var
	x: integer;
	r: integer;
begin
	r := -1;
	for x := 0 to Length(garrHeader) do
	begin
		//WriteLn(Chr(9), x, chr(9), headerArray[x]);
		if searchHeaderItem = garrHeader[x] then
			r := x;
	end;
	GetPosOfHeaderItem := r;
end; // of function CTextSeparated.GetPosOfHeaderItem


procedure PerformAction(strDn: string; strLastLogon: string; strCreated: string; intUserAccountControl: integer);
var
	dtAction: TDateTime;
	dtActionOnTheSecond: TDateTime;
	intActionSecondsAgo: integer;
	intActionDaysAgo: integer;
begin
	WriteLn;
	WriteLn('PerformAction():');
	WriteLn('  DN              : ', strDn);
	WriteLn('  Last logon      : ', strLastLogon);
	WriteLn('  Created         : ', strCreated);
	WriteLn('  UAC             : ', intUserAccountControl);
	
	gintSecondsDisable := DAYS_DISABLE * 24 * 60 * 60;
	gintSecondsDelete := DAYS_DELETE * 24 * 60 * 60;
	
	//WriteLn('gintSecondsDisable=', gintSecondsDisable);
	//WriteLn('gintSecondsDelete=', gintSecondsDelete);
	
	// If the last logon conains no data, is empty.
	// Then use the creation date of the last action of the account.
	if Length(strLastLogon) = 0 then
		dtAction := StrToDateTime(strCreated) // Convert the string with a date time to a number to use in calculations.
	else
		dtAction := StrToDateTime(strLastLogon);
	
	WriteLn('DTACTION=', DateTimeToStr(dtAction));
	
	intActionSecondsAgo := DateDiffSec(Now(), dtAction); // Calculate the number of seconds ago to the dtAction date time.
	intActionDaysAgo := DaysBetween(Now(), dtAction);
	
	WriteLn('intActionSecondsAgo=', intActionSecondsAgo);
	
	if intActionSecondsAgo > gintSecondsDelete then
	begin
		WriteLn('DELETE, the account is not used for ', intActionDaysAgo, ' days, that''s over the threshold of ', DAYS_DELETE, ' days.');
		
		dtActionOnTheSecond := GetLatestLogonDate(strDn);
		WriteLn('dtActionOnTheSecond=', DateTimeToStr(dtActionOnTheSecond));
	end
	else
	begin
		if intActionSecondsAgo > gintSecondsDisable then
		begin
			WriteLn('DISABLE, the account is not used for ', intActionDaysAgo, ' days, that''s over the threshold of ', DAYS_DISABLE, ' days.');
		end;
	end; // of if intActionSecondsAgo > gintSecondsDelete then
end; // of procedure PerformAction().



procedure CreateExportLastLogon(strFnameDcList: string; strFnameLastLogon: string; strBaseOu: string);
{
	Check on each DC found in strFnameDcList of strRootDse the LastLogon value for all accounts found in strBaseOu,
	store in strFnameLastLogon.
}
var
	f: TextFile;
	strLine: string;
	p: TProcess;
	c: AnsiString;
begin
	WriteLn;
	WriteLn(LeftStr('CreateExportLastLogon():' + StringOfChar('-', 80), 80));
	WriteLn('     strFnameDcList : ', strFnameDcList);		// File name of dc list
	WriteLn('  strFnameLastLogon : ', strFnameLastLogon);	// File of last logons
	WriteLn('          strBaseOu : ', strBaseOu);			// OU=accounts,DC=domain,DC=ext
	
	AssignFile(f, strFnameDcList);
	{I+}
	try 
		Reset(f);
		repeat
			ReadLn(f, strLine);
			WriteLn(strLine);
			
			// Export from all DC's of domain strBaseOu the lastLogon date time value.
			
			c := 'adfind.exe ';
			c := c + '-h ' + EncloseDoubleQuote(strLine) + ' ';
			c := c + '-b ' + EncloseDoubleQuote(strBaseOu) + ' ';
			c := c + '-f "' + #38 + '(objectClass=user)(objectCategory=person)" ';
			c := c + 'lastLogon ';
			c := c + '-jtsv -csvnoq ';
			c := c + '-tdcs -tdcsfmt "%YYYY%-%MM%-%DD% %HH%:%mm%:%ss%" ';
			c := c + '>>' + strFnameLastLogon;
			WriteLn(c);
			
			// Setup the process to be executed.
			p := TProcess.Create(nil);
			p.Executable := 'cmd.exe'; 
			p.Parameters.Add('/c ' + c);
			// 1) Wait until the process is finished and 
			// 2) do not show output to the console.
			p.Options := [poWaitOnExit, poUsePipes]; 
			p.Execute;		// Execute the command.
			
		until Eof(f);
		CloseFile(f);
	except
		on E: EInOutError do
			WriteLn('File ', FNAME_CONFIG, ' handeling error occurred, Details: ', E.ClassName, '/', E.Message);
	end;
end; // of procedure CreateExportLastLogon().



procedure CreateExportDcList(strFnameDcList: string; strRootDn: string);
{
	Create a file with all the FQDN's of DC servers of domain specified in strRootDn.
}
var
	p: TProcess;
	c: AnsiString;
begin
	WriteLn;
	WriteLn(LeftStr('CreateExportDcList():' + StringOfChar('-', 80), 80));
	c := 'adfind.exe -b ' + EncloseDoubleQuote(strRootDn) + ' -sc dclist >' + FNAME_DCLIST;

	WriteLn('c=', c);
	
	// Setup the process to be executed.
	p := TProcess.Create(nil);
	p.Executable := 'cmd.exe'; 
    p.Parameters.Add('/c ' + c);
	// 1) Wait until the process is finished and 
	// 2) do not show output to the console.
	p.Options := [poWaitOnExit, poUsePipes]; 
	p.Execute;		// Execute the command.
end; // of procedure CreateExportDcList();



procedure CreateExportAccount(strFnameAccount: string; strDomainNetbios: string; strBaseOu: string);
{
	Create a TSV with the account values in strFnameAccount of domain strDomainNetbios, started from strBaseOu.
}
var
	p: TProcess;
	c: AnsiString;
begin
	WriteLn;
	WriteLn(LeftStr('CreateExportAccount():' + StringOfChar('-', 80), 80));
	
	// adfind.exe -b %%c,%%a -binenc -f "&(objectClass=user)(objectCategory=person)" sAMAccountName displayName givenName sn cn title description homeDirectory profilePath userAccountControl lastLogontimeStamp pwdLastSet whenCreated -jtsv -tdcs -tdcgt -tdcfmt "%%YYYY%%-%%MM%%-%%DD%% %%HH%%:%%mm%%:%%ss%%" -tdcsfmt "%%YYYY%%-%%MM%%-%%DD%% %%HH%%:%%mm%%:%%ss%%" >>%LOGPATH%

	c := 'adfind.exe -b ' + EncloseDoubleQuote(strBaseOu) + ' ';
	c := c + '-f "' + #38 + '(objectClass=user)(objectCategory=person)" ';
	c := c + 'sAMAccountName description userAccountControl userPrincipalName lastLogontimeStamp whenCreated ';
	c := c + '-jtsv -csvnoq ';
	c := c + '-tdcgt -tdcfmt "%YYYY%-%MM%-%DD% %HH%:%mm%:%ss%" ';
	c := c + '-tdcs -tdcsfmt "%YYYY%-%MM%-%DD% %HH%:%mm%:%ss%" ';
	c := c + '>>' + strFnameAccount;

	WriteLn(c);
	
	p := TProcess.Create(nil);
	p.Executable := 'cmd.exe'; 
    p.Parameters.Add('/c ' + c);
	// 1) Wait until the process is finished and 
	// 2) do not show output to the console.
	p.Options := [poWaitOnExit, poUsePipes]; 
	p.Execute;		// Execute the command.
	
	p.Destroy;		// Destroy the process.
end; // of procedure CreateExportAccount().



procedure ProcessDomain(strFnameAccount: string; strRootDn: string; strBaseOu: string; strDomainNetbios: string);
begin
	WriteLn;
	WriteLn(LeftStr('ProcessDomain():' + StringOfChar('-', 80), 80));
	WriteLn('   strFnameAccount : ', strFnameAccount);		// File name of accounts
	WriteLn('        strRootDse : ', strRootDn);			// DC=domain,DC=ext
	WriteLn('         strBaseOu : ', strBaseOu);			// OU=accounts,DC=domain,DC=ext
	WriteLn('  strDomainNetbios : ', strDomainNetbios);		// DOMAINNAME
	
	CreateExportAccount(FNAME_ACCOUNT, strDomainNetbios, strBaseOu);
	CreateExportDcList(FNAME_DCLIST, strRootDn);
	CreateExportLastLogon(FNAME_DCLIST, FNAME_LASTLOGON, strBaseOu);
	
end; // of procedure ProcessDomain()



procedure Step1Export();
var
	f: TextFile;
	strLine: string;
	arrLine: TStringArray;
begin
	WriteLn;
	WriteLn(LeftStr('Step1Export():' + StringOfChar('-', 80), 80));
	
	AssignFile(f, FNAME_CONFIG);
	{I+}
	try 
		Reset(f);
		repeat
			// Process  every line in the .conf file.
			ReadLn(f, strLine);
			WriteLn(strLine);
			
			arrLine := SplitString(strLine, '|');
			ProcessDomain(FNAME_ACCOUNT, arrLine[0], arrLine[1] + ',' + arrLine[0], arrLine[2]);
		until Eof(f);
		CloseFile(f);
	except
		on E: EInOutError do
			WriteLn('File ', FNAME_CONFIG, ' handeling error occurred, Details: ', E.ClassName, '/', E.Message);
	end;
end; // of procedure Step1Export().


procedure ProgTest();
begin
	//WriteLn(GetLatestLogonDate('CN=HP_Ian.Webermann,OU=HP,OU=Beheer,DC=prod,DC=ns,DC=nl'));
	strDn := 'CN=Perry.vandenHondel,OU=Accounts,DC=prod,DC=ns,DC=nl';
	dtLatest := GetLatestLogonDate(strDn);
	WriteLn(' *** Latest logon date time for:', strDn, ': ', DateTimeToStr(dtLatest));
end; // of procedure ProgTest()



procedure ProgInit();
var
	sFolderBatch: string;
begin
	gdtNow := Now();
	
	WriteLn('Now: ' + DateTimeToStr(gdtNow));
	
	gsBatchNumber := GetDateFs(false); // + GetTimeFs();
end; // of procedure ProgInit()



procedure ProgRun();
begin
	WriteLn;
	WriteLn(LeftStr('ProgRun():' + StringOfChar('-', 80), 80));
	
	// Delete any previous export file.
	DeleteFile(FNAME_ACCOUNT);
	DeleteFile(FNAME_LASTLOGON);
	
	Step1Export();
	
	WriteLn('Program completed!');
end; // of procedure ProgRun()



procedure ProgDone();
begin
end; // of procedure ProgDone()
	


begin
	ProgInit();
	ProgRun();
	ProgDone();
end. // of program BACleanup