# W2K8R2-TLS-1.2-Enable
PowerShell script to enable TLS 1.2 on a Windows Server 2008 R2 SP1

This project leverages a custom PowerShell script allowing administrators to make their Windows Server 2008 R2 Server SP1 TLS 1.2 compliant.The script disables legacy ciphers, SSL 3.0, SSL 2.0, TLS 1.0, and TLS, 1.1. The script will validate if the proper patches have been installed to avoid disrupting Remote Desktop Services connectivity when TLS 1.0 is disabled.
If your environment has a majority of Windows 7 and Windows Server 2008 R2  SP1 systems you will require the following patch KB3080079. There is a version for Windows 7 and a version for Windows 2008 R2 SP1 to allow the Remote Desktop Client to operate properly once TLS 1.0 has been disabled.

PLEASE NOTE: Windows Server 2003 does not support TLS 1.2.

PLEASE NOTE: Windows Server 2008 SP2 now supports TLS 1.1 and 1.2. Please see the following patch that has been released by Microsoft:
https://support.microsoft.com/en-us/help/4019276/update-to-add-support-for-tls-1-1-and-tls-1-2-in-windows 

Requirements

Requirements set PowerShell execution policy to "remotesigned" or "unrestricted" to allow the script to execute. You must execute the script with administrative credentials.
Apply patch KB3080079 for remote desktop communication prior to executing the PowerShell script to avoid breaking the Remote Desktop Client functionality once TLS 1.0 is disabled on the Windows 2008 R2  SP1 Server.
Also patch NDP45-KB2954853-x64 has to be applied for .Net (assumes minimal version of .Net 4.5.2 is installed on the server) to become TLS compatible. Please check your version of  .Net.

Guidance

The project follows the following Microsoft guidance:
https://technet.microsoft.com/en-us/library/dn786419(v=ws.11).aspx 
https://blogs.msdn.microsoft.com/httpcontext/2012/02/17/how-to-disable-ssl-2-0-on-windows-server-2008-r2/ 
https://blogs.technet.microsoft.com/askds/2015/12/08/speaking-in-ciphers-and-other-enigmatic-tonguesupdate/ 
https://blogs.technet.microsoft.com/srd/2013/11/12/security-advisory-2868725-recommendation-to-disable-rc4/
