{
	Beheer Accounts Cleanup

	Version		Date		Author		Description
	-------		---------	----------	----------------------------------
	04			2015-01-08	PVDH		Initial version in Pascal
	
}


program BACleanup;



{$MODE OBJFPC} // Do not forget this ever
{$M+}



uses
	DateUtils,
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


	
var
	//giSecDisable: LongInt;
	//giSecDelete: LongInt;
	giTotalDisable: integer;
	giTotalDelete: integer;
	
	gdtNow: TDateTime;
	tsvExport: CTextSeparated;	
	tsvLog: CTextSeparated;
	txtBatch: CTextFile;
	gsBatchNumber: string; 			// Contains the batch number in format YYYYMMDDHHMMSS



function GetDomainFromDn(sDn: string): string;
{
	Extract the DNS domain name from a DN
	
	CN=Jurgen.Caspers,OU=Normal,OU=Accounts,OU=RBAC,DC=REC,DC=NSINT > rec.nsint
}

var
	p: integer;
	r: string;
begin
	//WriteLn('GetDomainFromDn(): ', sDn);
	p := Pos('DC=', sDn);
	//WriteLn(p);
	r := RightStr(sDn, length(sDn) - p + 1);
	//WriteLn(r);
	
	r := ReplaceText(r, 'DC=', '');
	r := ReplaceText(r, ',', '.');
	
	GetDomainFromDn := r;
end; // of function GetDomainFromDn



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
	txtBatch.WriteToFile(sCmd);

	// Secondly disable the account using DSMOD.EXE to disable the account
	sCmd := 'dsmod.exe user "' + sDn + '" -disabled yes';
	txtBatch.WriteToFile(sCmd);
	
	// Add a blank line
	txtBatch.WriteToFile('');
end; // of procedure WriteDisable


procedure DoCommandDelete(sDn: string; sSam: string);
var
	sCmd: string;
begin
	sCmd := 'adfind.exe -b "' + sDn + '" ';
	sCmd := sCmd + '-tdcs -tdcsfmt "%%YYYY%%-%%MM%%-%%DD%% %%HH%%:%%mm%%:%%ss%%" ';
	sCmd := sCmd + '-tdcgt -tdcfmt "%%YYYY%%-%%MM%%-%%DD%% %%HH%%:%%mm%%:%%ss%%" ';
	sCmd := sCmd + '>>userinfo\' + sSam + '.txt';
	txtBatch.WriteToFile(sCmd);
	
	sCmd := 'dsrm.exe "' + sDn + '" -noprompt';
	txtBatch.WriteToFile(sCmd);
	
	// Add a blank line
	txtBatch.WriteToFile('');
end; // of procedure WriteDelete



procedure WriteToLog(sDn: string; sSam: string; dtCalc: TDateTime; sWhichUsed: string; iAgoDays: integer; sAction: string; sMessage: string);

var
	sDomain: string;
	sSupportOrg: string;
begin
	// Get the DNS domain name from a DN
	sDomain := GetDomainFromDn(sDn);
	// Get the Support Organization for an SAM account.
	sSupportOrg := GetSupportOrg(sSam);
	
	tsvLog.WriteToFile(sDomain + #9 + sSupportOrg + #9 + sSam + #9 + DateTimeToStr(dtCalc) + #9 + sWhichUsed + #9 + IntToStr(iAgoDays) + #9 + sAction + #9 + sMessage);
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

	

procedure ProgInit();

var
	sFolderBatch: string;
	
begin
	gdtNow := Now();
	
	WriteLn('Now: ' + DateTimeToStr(gdtNow));
	
	gsBatchNumber := GetDateFs(false); // + GetTimeFs();
	
	sFolderBatch := GetCurrentDir() + '\' + gsBatchNumber + '\';
	WriteLn('Making folder: ', sFolderBatch);
	MakeFolderTree(sFolderBatch);
	
	WriteLn('Batch output in folder: ' + sFolderBatch);
	
	giTotalDisable := 0;
	giTotalDelete := 0;
	
	WriteLn('Trying to open export.tsv');
	tsvExport := CTextSeparated.Create('export.tsv');
    tsvExport.OpenFileRead();
	tsvExport.SetSeparator(Chr(9)); // Tab char as separator
	WriteLn('Open file: ', tsvExport.GetPath(), ' status = ', BoolToStr(tsvExport.GetStatus, 'OPEN', 'CLOSED'));
	tsvExport.ReadHeader();
	
	WriteLn('Trying to open log.tsv');
	// Open the output file.
	tsvLog := CTextSeparated.Create(sFolderBatch + 'log.tsv');
	tsvLog.OpenFileWrite();
	// Write the header for the output file.
	tsvLog.WriteToFile('Domain'+Chr(9)+'SupportOrg'+Chr(9)+'Account'+Chr(9)+'CalcDateTime'+Chr(9)+'UsingDateTime'+Chr(9)+'DaysAgo'+Chr(9)+'Action'+Chr(9)+'Message');
	
	WriteLn('Trying to open action.cmd');
	// Open the batch file.
	txtBatch := CTextFile.Create(sFolderBatch + 'action.cmd.txt');
    txtBatch.OpenFileWrite();
    txtBatch.WriteToFile('@echo off');
    txtBatch.WriteToFile('::');
    txtBatch.WriteToFile(':: Batch file with command to execute to clean-up beheeraccounts');
    txtBatch.WriteToFile('::');
	txtBatch.WriteToFile('');
	txtBatch.WriteToFile('if not exist userinfo md userinfo');
	txtBatch.WriteToFile('');
	
	WriteLn('WE ARE HERE!');
end; // of procedure ProgInit()



procedure ProgRun();
begin
	repeat
		WriteLn('LINE:');
		tsvExport.ReadLine();
{
		ProcessLine(tsvExport.GetCurrentLine(), tsvExport.GetValue('dn'), tsvExport.GetValue('sAMAccountName'), 
			tsvExport.GetValue('description'), tsvExport.GetValue('userAccountControl'), tsvExport.GetValue('lastLogontimeStamp'), 
			tsvExport.GetValue('whenCreated'));
		
		WriteLn;
} 
		WriteLn(tsvExport.GetCurrentLine(), Chr(9), 'dn=', tsvExport.GetValue('dn')); 
		WriteLn(tsvExport.GetCurrentLine(), Chr(9))
    until tsvExport.GetEof();
end; // of procedure ProgRun()



procedure ProgDone();
var
	nTotal: LongInt;
	nPercentDisable: Double;
	nPercentDelete: Double;
begin
    // Close the batch file.
	txtBatch.CloseFile();
	
	// Close the log file.
	tsvLog.CloseFile();

	// Close the export file.
	tsvExport.CloseFile();

	nTotal := tsvExport.GetCurrentLine();
	nPercentDisable := (giTotalDisable / nTotal) * 100;
	nPercentDelete := (giTotalDelete / nTotal) * 100;
	
	WriteLn;
	WriteLn('STATISTICS:');
	WriteLn(' Batch          : ', gsBatchNumber);
	WriteLn(' Total accounts : ', nTotal:5);
	WriteLn(' Disabled       : ', giTotalDisable:5, ' (', nPercentDisable:3:2, '%)');
	WriteLn(' Deleted        : ', giTotalDelete:5, ' (', nPercentDelete:3:2, '%)');
end; // of procedure ProgDone()
	
	

begin
	ProgInit();
	ProgRun();
	{WriteLn(GetSupportOrg('CSC_Ronald.Blies'));
	WriteLn(GetSupportOrg('GTN_Ronald.Blies'));
	WriteLn(GetSupportOrg('KPN_Ronald.Blies'));
	WriteLn(GetSupportOrg('NSA_Ronald.Blies'));
	WriteLn(GetSupportOrg('HP_Ronald.Blies'));
	WriteLn(GetSupportOrg('EDS_Ronald.Blies'));
	
	WriteLn(GetDomainFromDn('CN=KPN_Daniel.Heinsius,OU=KPN,OU=Beheer,DC=rs,DC=root,DC=nedtrain,DC=test'));
	WriteLn(GetDomainFromDn('CN=GTN_Adri.Kusters,OU=GTN,OU=Beheer,DC=ontwikkel,DC=ns,DC=nl'));
	WriteLn(IsBeheeraccount('GTN_Adri.Kusters'));
	WriteLn(IsBeheeraccount('SVC_Testing'));
	}
	ProgDone();
end. // of program BACleanup