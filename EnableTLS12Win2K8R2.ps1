# The following application is provided as is without any guarantees or warranty. 
# Although the author has attempted to find and correct any bugs in the free software programs, 
# the author is not responsible for any damage or losses of any kind caused by the use or misuse of this script. 
# The author is under no obligation to provide support, service, corrections, or upgrades to for this free script. 
# For more information, please send and email to Anthony de Lagarde delagardecodeplex@hotmail.com.com. 
# Script written 10 7, 2016. Script enables TLS 1.2 on Windows Server 2008 R2 and Windows 7.


# The script disables SSL3.0, SSL 2.0, TLS 1.0, TLS 1.1 and enables TLS 1.2
# References https://technet.microsoft.com/en-us/library/dn786419(v=ws.11).aspx https://blogs.msdn.microsoft.com/httpcontext/2012/02/17/how-to-disable-ssl-2-0-on-windows-server-2008-r2/ https://blogs.technet.microsoft.com/askds/2015/12/08/speaking-in-ciphers-and-other-enigmatic-tonguesupdate/ https://blogs.technet.microsoft.com/srd/2013/11/12/security-advisory-2868725-recommendation-to-disable-rc4/

#Writing log to root of C:\ when TLS changes were applied to the server
  $Title = "Enabling TLS 1.2 on this servername:"
  $Eof = "Completed!"
  $startdate = Get-Date -Format "HH:mm:ss.fff"
  $enddate = Get-Date -Format "HH:mm:ss.fff"
  $logfile = "C:\TLS1.2.log"
  $serv = "$env:COMPUTERNAME"
  New-Item $logfile -Type "File" -Force | out-null
  Get-Date | Out-file $logfile -append
  "[$startdate][Startup]  $Title $serv" | Out-file $logfile -append  


 

# Script designed to run on Windows Server 2008 R2. Detecting if the correct OS here and exit if not the right match....
Write-Host -ForegroundColor Yellow "Determining the OS version on your computer.....`r`n"
if ((Get-WMIObject win32_OperatingSystem).Version -eq '6.1.7601') {Write-Host -Foregroundcolor Green "System is the right OS Level (Windows 2008 R2) registry keys will be created! "}
   Else {
 if ((Get-WMIObject win32_OperatingSystem).Version -ne '6.1.7601') {Write-Host -Foregroundcolor Red "SYSTEM IS NOT THE RIGHT OS LEVEL (Windows 2008 R2) SCRIPT WILL STOP!! "} Stop-Process -processname powershell
}

# Reminding operator to install RDP 8.1 for the Windows Server 2008 R2 and Windows 7 (KB3080079 )
 Write-Host -ForegroundColor Yellow "PLEASE MAKE SURE THAT YOU HAVE APPLIED PATCH KB3080079 FOR WINDOWS SERVER 2008 R2 (RDP 8.1) BEFORE DISABLING TLS 1.0.`r`n"
 Write-Host -ForegroundColor Yellow " Validating to see if patch KB3080079 has been installed if not installed the script will halt `r `n"
 
 #Validating the status of the patch installation 
 $patch = get-hotfix -ID KB3080079
  if (-not $patch) {Write-Host -ForegroundColor Red "KB3080079 FOR WINDOWS SERVER 2008 R2 IS NOT INSTALLED PLEASE KILL POWERSHELL NOW!!!!”} 
   else { Write-Host -ForegroundColor green "Patch KB3080079 for Windows Server 2008 R2 is installed script will continue!”  }   

 Start-Sleep -Seconds 5

#Verify if Powershell is running under Administrative credentials.
write-host -ForegroundColor Yellow "Validating if the command shell is running under a Administrative context"

if ( -not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator"))
{

    Write-Host -ForegroundColor yellow "This PowerShell prompt is not elevated."
    Write-Host -ForegroundColor yellow "Please open a new PowerShell session using an Administrative token and please try again."
    return
    }

# Asking the operator for the department name who owns the server
   $proj=(Read-Host "Please enter the Department who own the application on the server.  Example: Finance Department")
                        if ([String]::IsNullOrEmpty($proj))
                            {
                                do
                                {
                                    $proj=(Read-Host "Invalid Data! Please enter the Department who own the application on the server.  Example: Finance Department")
                                    } while ([String]::IsNullOrEmpty($proj));
                                }
                                
   # Asking the operator for the company name who owns the server
   $projown=(Read-Host "Please enter the company name.  Example: Contoso")
                        if ([String]::IsNullOrEmpty($projown))
                            {
                                do
                                {
                                    $projown=(Read-Host "Invalid Data! Please enter the company name.  Example: Contoso")
                                    } while ([String]::IsNullOrEmpty($projown));
                                } 


Write-Host -ForegroundColor Yellow "Creating the Protocol Server and Client registry keys"

# These keys do not exist so they need to be created prior to setting values.
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"


# Enable TLS 1.2 for client and server SCHANNEL communications
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -name "Enabled" -value 1 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -name "DisabledByDefault" -value 0 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -name "Enabled" -value 1 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -name "DisabledByDefault" -value 0 -PropertyType "DWord"
Write-Host -ForegroundColor Yellow "Enabled TLS 1.2 registry keys for client and server SCHANNEL communications"

# Disable TLS 1.1 (TLS 1.1 Server should be disabled by default in Windows Server 2008 R2, but setting it here just in case)
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -name Enabled -value 0 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -name "DisabledByDefault" -value 0 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -name Enabled -value 0 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -name "DisabledByDefault" -value 1 -PropertyType "DWord"
Write-Host -ForegroundColor Yellow "Disabled TLS 1.1 registry keys for client and server SCHANNEL communications"

# Disable TLS 1.0
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -name Enabled -value 0 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -name "DisabledByDefault" -value 0 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -name Enabled -value 0 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -name "DisabledByDefault" -value 0 -PropertyType "DWord"
Write-Host -ForegroundColor Yellow "Disabled TLS 1.0 registry keys for client and server SCHANNEL communications"

# Disable SSL 3.0
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -name Enabled -value 0 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -name "DisabledByDefault" -value 1 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -name Enabled -value 0 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -name "DisabledByDefault" -value 1 -PropertyType "DWord"
Write-Host -ForegroundColor Yellow "Disabled SSL 3.0 registry keys for client and server SCHANNEL communications"

# Disable SSL 2.0 (SSL 2.0 client should be disabled by default in Windows Server 2008 R2 but adding this just in case)
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -name Enabled -value 0 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" -name "DisabledByDefault" -value 1 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -name "DisabledByDefault" -value 1 -PropertyType "DWord"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" -name Enabled -value 0 -PropertyType "DWord"
Write-Host -ForegroundColor Yellow "Disabled SSL 2.0 registry keys for client and server SCHANNEL communications"

# Registering the organization who owns the system in the registry to show up in %WINVER% and to be searched by SCCM or CI Management
Set-itemproperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -name "RegisteredOrganization" -value $projown
Set-itemproperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -name "RegisteredOwner" -value $proj

#Disable Weak Cyphers
Write-Host -ForegroundColor Yellow "Disabling weak Cyphers now" 

md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Null"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Null" -name "Enabled" -value 0 -PropertyType "Dword"
 
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" -name "Enabled" -value 0 -PropertyType "Dword"
 
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" -name "Enabled" -value 0 -PropertyType "Dword"
 
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" -name "Enabled" -value 0 -PropertyType "Dword"
 
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" -name "Enabled" -value 0 -PropertyType "Dword"
 
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" -name "Enabled" -value 0 -PropertyType "Dword"
 
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" -name "Enabled" -value 0 -PropertyType "Dword"
 
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64"
md "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128"
new-itemproperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" -name "Enabled" -value 0 -PropertyType "Dword"

Write-Host -ForegroundColor Green "Finished disabling weak Cyphers now"

#Setting the system to use the strong Crypto for x64 .Net (For 32-bit applications on 32-bit systems and 64-bit applications on x64-based systems)
new-itemproperty -path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -name "SchUseStrongCrypto" -value 1 -PropertyType "Dword"

#Setting the system to use the strong Crypto for x64 .Net (For 64-bit applications on x64-based systems:)
new-itemproperty -path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -name "SchUseStrongCrypto" -value 1 -PropertyType "Dword"

#Setting the recommended cipher order
Write-Host -ForegroundColor Yellow "Adding Cipher Order to the System!"
Set-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" -name "Functions" -value "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA_P384,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_RC4_128_SHA,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256_P384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA_P384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_P256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256_P256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_P384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384_P384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA_P384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA_P384,TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,TLS_DHE_DSS_WITH_AES_128_CBC_SHA,TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,TLS_DHE_DSS_WITH_AES_256_CBC_SHA,TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_RC4_128_MD5,SSL_CK_RC4_128_WITH_MD5,SSL_CK_DES_192_EDE3_CBC_WITH_MD"

#Enabling PowerShell Remoting and also creating Firewall rule

Write-Host -ForegroundColor Yellow "Enabling WinRM Quickconfig on the server"

Winrm quickconfig -q
Enable-PSRemoting -Force

Write-Host -ForegroundColor Green "Finished enabling WinRM Quickconfig on the server"

#Adding firewall Rule for WASMAN to use SSL on TCP 5986
Write-Host -ForegroundColor Yellow "Adding firewall Rule for WSMan to use SSL on TCP 5986!"

netsh advfirewall firewall add rule name="Windows Remote Management (HTTPS-In)" dir=in action=allow protocol=TCP localport=5986
Write-Host -ForegroundColor Green "Please add trusted certificate for WinRM and listener to use SSL on TCP 5986!"


# Closing to the log file when the process completed
"[$enddate][End]  $Eof" | Out-file $logfile -append

Write-Host -ForegroundColor Green "Completed! Please check registry keys and TLS compliance after the reboot to complete the process.`r`n"
Write-Host -ForegroundColor Green "The system will reboot in ten seconds. `r`n"

Start-Sleep -Seconds 10

# Rebooting Server for shanges to take effect
Restart-Computer -ComputerName $serv -force