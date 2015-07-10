@echo off
::
::	Export the last password set of administrator accounts to a TSV file for all defined domains.
::


::
::	Script settings
::
::set EXPORT_FILE=export.tmp

::echo .
::echo Export to file %EXPORT_FILE%
::echo .


::
::	Create the log folder when it doesn't exist.
::
:: if not exist %LOGFOLDER% md %LOGFOLDER%


::
::	Delete existing log file.
::
::if exist %EXPORT_FILE% del %EXPORT_FILE%


::
::	Export the password age and whenCreate date time to an output file.
::
:: extended more fields: adfind.exe -b %%c,%%a -binenc -f "&(objectClass=user)(objectCategory=person)" sAMAccountName displayName givenName sn cn title description homeDirectory profilePath userAccountControl lastLogontimeStamp pwdLastSet whenCreated -jtsv -tdcs -tdcgt -tdcfmt "%%YYYY%%-%%MM%%-%%DD%% %%HH%%:%%mm%%:%%ss%%" -tdcsfmt "%%YYYY%%-%%MM%%-%%DD%% %%HH%%:%%mm%%:%%ss%%" >>%LOGPATH%
:: small: adfind.exe -b %%c,%%a -binenc -f "&(objectClass=user)(objectCategory=person)" sAMAccountName description userAccountControl lastLogontimeStamp whenCreated -nocsvq -jtsv -tdcs -tdcgt -tdcfmt "%%YYYY%%-%%MM%%-%%DD%% %%HH%%:%%mm%%:%%ss%%" -tdcsfmt "%%YYYY%%-%%MM%%-%%DD%% %%HH%%:%%mm%%:%%ss%%" >>%LOGPATH%
::	Settings used:
::		-jtsv		Output in TSV file format: Tab Seperated Values
::		-csvnoq		Do not use a field quote chars, e.g. do not enclose the values with "
::		-dpdn		Include Parent DN
::		
:: org: adfind.exe -b %%d -binenc -f "(&(objectClass=user)(objectCategory=person)(sAMAccountName=SVC_*))" sAMAccountName displayName description userAccountControl lastLogontimeStamp pwdLastSet whenCreated -jtsv -csvnoq -dpdn -tdcs -tdcgt -tdcfmt "%%YYYY%%-%%MM%%-%%DD%% %%HH%%:%%mm%%:%%ss%%" -tdcsfmt "%%YYYY%%-%%MM%%-%%DD%% %%HH%%:%%mm%%:%%ss%%" >>service-accounts.tsv
::
::for /f %%d in (rootdse.txt) do (
::	echo Exporting domain %%d
::	adfind.exe -b %%d -binenc -f "(&(objectClass=user)(objectCategory=person))" sAMAccountName description userAccountControl userPrincipalName lastLogontimeStamp whenCreated -jtsv -csvnoq -tdcs -tdcgt -tdcfmt "%%YYYY%%-%%MM%%-%%DD%% %%HH%%:%%mm%%:%%ss%%" -tdcsfmt "%%YYYY%%-%%MM%%-%%DD%% %%HH%%:%%mm%%:%%ss%%" >>%EXPORT_FILE%
::)



::echo File created:
::dir %EXPORT_FILE%


:: Process export file
echo Running program Housekeeping Beheer Account.
%0\..\hkba.exe


echo Script completed...