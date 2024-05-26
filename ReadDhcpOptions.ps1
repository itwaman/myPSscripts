# 
# Name        : ReadDhcpOptions.ps1
# Author      : Ingmar Verheij - http://www.ingmarverheij.com
# Version     : 1.0, 12 july 2013
# Description : Shows the Dhcp options received by all Dhcp enabled NICs
# 

#http://www.sans.org/windows-security/2010/02/11/powershell-byte-array-hex-convert
function Convert-ByteArrayToString {
################################################################
#.Synopsis
# Returns the string representation of a System.Byte[] array.
# ASCII string is the default, but Unicode, UTF7, UTF8 and
# UTF32 are available too.
#.Parameter ByteArray
# System.Byte[] array of bytes to put into the file. If you
# pipe this array in, you must pipe the [Ref] to the array.
# Also accepts a single Byte object instead of Byte[].
#.Parameter Encoding
# Encoding of the string: ASCII, Unicode, UTF7, UTF8 or UTF32.
# ASCII is the default.
################################################################
[CmdletBinding()] Param (
 [Parameter(Mandatory = $True, ValueFromPipeline = $True)] [System.Byte[]] $ByteArray,
 [Parameter()] [String] $Encoding = "ASCII"
)
switch ( $Encoding.ToUpper() )
{
 "ASCII" { $EncodingType = "System.Text.ASCIIEncoding" }
 "UNICODE" { $EncodingType = "System.Text.UnicodeEncoding" }
 "UTF7" { $EncodingType = "System.Text.UTF7Encoding" }
 "UTF8" { $EncodingType = "System.Text.UTF8Encoding" }
 "UTF32" { $EncodingType = "System.Text.UTF32Encoding" }
 Default { $EncodingType = "System.Text.ASCIIEncoding" }
}
$Encode = new-object $EncodingType
$Encode.GetString($ByteArray)
}


#Fill an array with the "DHCP Message Type 53 values" from http://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
#(the dirty way)
$DhcpMessageType53Values+= @("")
$DhcpMessageType53Values+= @("DHCPDISCOVER")
$DhcpMessageType53Values+= @("DHCPOFFER")
$DhcpMessageType53Values+= @("DHCPREQUEST")
$DhcpMessageType53Values+= @("DHCPDECLINE")
$DhcpMessageType53Values+= @("DHCPACK")
$DhcpMessageType53Values+= @("DHCPNAK")
$DhcpMessageType53Values+= @("DHCPRELEASE")
$DhcpMessageType53Values+= @("DHCPINFORM")
$DhcpMessageType53Values+= @("DHCPFORCERENEW")
$DhcpMessageType53Values+= @("DHCPLEASEQUERY")
$DhcpMessageType53Values+= @("DHCPLEASEUNASSIGNED")
$DhcpMessageType53Values+= @("DHCPLEASEUNKNOWN")
$DhcpMessageType53Values+= @("DHCPLEASEACTIVE")
$DhcpMessageType53Values+= @("DHCPBULKLEASEQUERY")
$DhcpMessageType53Values+= @("DHCPLEASEQUERYDONE")


#Read dhcp-option information from CSV (ignore if the file can't be read)
$DhcpOptionsCSV = 'Code;Name;Type
0;Pad;
1;Subnet Mask;IP
2;Time Offset;time
3;Router;string
4;Time Server;ip
5;Name Server;string
6;Domain Server;ip
7;Log Server;
8;Quotes Server;
9;LPR Server;
10;Impress Server;
11;RLP Server;
12;Hostname;string
13;Boot File Size;
14;Merit Dump File;
15;Domain Name;string
16;Swap Server;
17;Root Path;
18;Extension File;
19;Forward On/Off;
20;SrcRte On/Off;
21;Policy Filter;
22;Max DG Assembly;
23;Default IP TTL;
24;MTU Timeout;
25;MTU Plateau;
26;MTU Interface;
27;MTU Subnet;
28;Broadcast Address;
29;Mask Discovery;
30;Mask Supplier;
31;Router Discovery;
32;Router Request;
33;Static Route;
34;Trailers;
35;ARP Timeout;
36;Ethernet;
37;Default TCP TTL;
38;Keepalive Time;
39;Keepalive Data;
40;NIS Domain;
41;NIS Servers;
42;NTP Servers;
43;Vendor Specific;
44;NETBIOS Name Srv;
45;NETBIOS Dist Srv;
46;NETBIOS Node Type;
47;NETBIOS Scope;
48;X Window Font;
49;X Window Manager;
50;Address Request;
51;Address Time;time
52;Overload;
53;DHCP Msg Type;dhcpmsgtype
54;DHCP Server Id;ip
55;Parameter List;
56;DHCP Message;
57;DHCP Max Msg Size;
58;Renewal Time;time
59;Rebinding Time;time
60;Class Id;
61;Client Id;
62;NetWare/IP Domain;
63;NetWare/IP Option;
64;NIS-Domain-Name;
65;NIS-Server-Addr;
66;Server-Name;
67;Bootfile-Name;
68;Home-Agent-Addrs;
69;SMTP-Server;
70;POP3-Server;
71;NNTP-Server;
72;WWW-Server;
73;Finger-Server;
74;IRC-Server;
75;StreetTalk-Server;
76;STDA-Server;
77;User-Class;
78;Directory Agent;
79;Service Scope;
80;Rapid Commit;
81;Client FQDN;
82;Relay Agent Information;
83;iSNS;
84;REMOVED/Unassigned;
85;NDS Servers;
86;NDS Tree Name;
87;NDS Context;
88;BCMCS Controller Domain Name list;
89;BCMCS Controller IPv4 address option;
90;Authentication;
91;client-last-transaction-time option;
92;associated-ip option;
93;Client System;
94;Client NDI;
95;LDAP;
96;REMOVED/Unassigned;
97;UUID/GUID;
98;User-Auth;
99;GEOCONF_CIVIC;
100;PCode;
101;TCode;
108;REMOVED/Unassigned;
109;Unassigned;
110;REMOVED/Unassigned;
111;Unassigned;
112;Netinfo Address;
113;Netinfo Tag;
114;URL;
115;REMOVED/Unassigned;
116;Auto-Config;
117;Name Service Search;
118;Subnet Selection Option;
119;Domain Search;
120;SIP Servers DHCP Option;
121;Classless Static Route Option;
122;CCC;
123;GeoConf Option;
124;V-I Vendor Class;
125;V-I Vendor-Specific Information;
126;Removed/Unassigned;
127;Removed/Unassigned;
128;PXE - undefined (vendor specific);
128;"Etherboot signature. 6 bytes: E4:45:74:68:00:00";
128;"DOCSIS ""full security"" server IP address";
128;"TFTP Server IP address (for IP Phone software load)";
129;PXE - undefined (vendor specific);
129;"Kernel options. Variable length string";
129;Call Server IP address;
130;PXE - undefined (vendor specific);
130;"Ethernet interface. Variable length string.";
130;"Discrimination string (to identify vendor)";
131;PXE - undefined (vendor specific);
131;Remote statistics server IP address;
132;PXE - undefined (vendor specific);
132;IEEE 802.1Q VLAN ID;
133;PXE - undefined (vendor specific);
133;IEEE 802.1D/p Layer 2 Priority;
134;PXE - undefined (vendor specific);
134;"Diffserv Code Point (DSCP) for VoIP signalling and media streams";
135;PXE - undefined (vendor specific);
135;"HTTP Proxy for phone-specific applications";
136;OPTION_PANA_AGENT;
137;OPTION_V4_LOST;
138;OPTION_CAPWAP_AC_V4;
139;OPTION-IPv4_Address-MoS;
140;OPTION-IPv4_FQDN-MoS;
141;SIP UA Configuration Service Domains;
142;OPTION-IPv4_Address-ANDSF;
143;OPTION-IPv6_Address-ANDSF;
144;GeoLoc;
145;FORCERENEW_NONCE_CAPABLE;
146;RDNSS Selection;
150;TFTP server address;
150;Etherboot;
150;GRUB configuration path name;
151;status-code;
152;base-time;
153;start-time-of-state;
154;query-start-time;
155;query-end-time;
156;dhcp-state;
157;data-source;
175;"Etherboot (Tentatively Assigned - 2005-06-23)";
176;"IP Telephone (Tentatively Assigned - 2005-06-23)";
177;"Etherboot (Tentatively Assigned - 2005-06-23)";
177;"PacketCable and CableHome (replaced by 122)";
208;PXELINUX Magic;
209;Configuration File;
210;Path Prefix;
211;Reboot Time;
212;OPTION_6RD;
213;OPTION_V4_ACCESS_DOMAIN;
220;Subnet Allocation Option;
221;Virtual Subnet Selection (VSS) Option;
252;Private/Proxy autodiscovery;string;
'
$DhcpOptionsVSCSV = 'Code;Name;Type
10;Windows 2000 option 1;string
11;Windows 2000 option 2;string
12;Windows 2000 option 3;string
212;RES Workspace Manager;string
220;NAP-SoH;string
'

try {
	$dhcpOptionDetails = @();
	#$dhcpOptionDetails = Import-Csv ".\DhcpOptions.csv" -Delimiter ";"
	$dhcpOptionDetails = $DhcpOptionsCSV | ConvertFrom-Csv -Delimiter ";"
} catch { }
try {
	$dhcpOptionVSDetails = @(); 
	#$dhcpOptionVSDetails = Import-Csv "DhcpOptionsVS.csv" -Delimiter ";" 
	$dhcpOptionVSDetails = $DhcpOptionsVSCSV | ConvertFrom-Csv -Delimiter ";"
} catch { }

#Iterate through NIC's with IP obtained via DHCP
$objWin32NAC = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -namespace "root\CIMV2" -computername "." -Filter "IPEnabled = 'True' AND DHCPEnabled ='True'" 
foreach ($objNACItem in $objWin32NAC) 
{

	#Write adapter neame
	Write-Host -NoNewline -ForegroundColor White "Reading DHCP options of NIC "
	Write-Host -ForegroundColor Yellow $objNACItem.Caption 
	Write-Host ""

	#Write IP information
	Write-Host -NoNewline -ForegroundColor White "  IP address : " 
	Write-Host ((Get-ItemProperty -Path ("HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0}" -f $objNACItem.SettingID) -Name DhcpIPAddress).DhcpIPAddress)
	Write-Host -NoNewline -ForegroundColor White "  DHCP server: " 
	
	#Write DHCP options
	Write-Host ((Get-ItemProperty -Path ("HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0}" -f $objNACItem.SettingID) -Name DhcpServer).DhcpServer)
	Write-Host -ForegroundColor White "  Options    :" 
	
	#Read DHCP options
	$DhcpInterfaceOptions = (Get-ItemProperty -Path ("HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0}" -f $objNACItem.SettingID) -Name DhcpInterfaceOptions).DhcpInterfaceOptions
	$DhcpOptions = @(); for ( $i = 0 ; $i -lt 256; $i++ ) { $DhcpOptions += @("") }
	$DhcpVendorSpecificOptions = @(); for ( $i = 0 ; $i -lt 256; $i++ ) { $DhcpVendorSpecificOptions += @("") }
	
	#Iterate through DHCP options
	$intPosition = 0
	while ($intPosition -lt $DhcpInterfaceOptions.length) 
	{
		#Read Dhcp code 
		$DhcpOptionCode = $DhcpInterfaceOptions[$intPosition]
		$intPosition = $intPosition + 8 #shift 8 bytes
		
		#Read length
		$DhcpOptionLength = $DhcpInterfaceOptions[$intPosition]
		$intPosition = $intPosition + 4 #shift 4 bytes
		
		#Is this a vendor specific option?
		$DhcpIsVendorSpecific = $DhcpInterfaceOptions[$intPosition]
		$intPosition = $intPosition + 4 #shift 4 bytes
		
		#Read "unknown data"
		$DhcpUnknownData = ""
		for ($i=0; $i -lt 4; $i++) { $DhcpUnknownData = $DhcpUnknownData + $DhcpInterfaceOptions[$intPosition + $i] }
		$intPosition = $intPosition + 4 #shift 4 bytes
		
		#Read value
		if (($DhcpOptionLength % 4) -eq 0) {$DhcpOptionBytesToRead = ($DhcpOptionLength - ($DhcpOptionLength % 4))} else {$DhcpOptionBytesToRead = ($DhcpOptionLength - ($DhcpOptionLength % 4)+4)}
		$DhcpOptionValue = New-Object Byte[] $DhcpOptionBytesToRead
		for ($i=0; $i -lt $DhcpOptionLength; $i++) { $DhcpOptionValue[$i] = $DhcpInterfaceOptions[$intPosition + $i] }
		$intPosition = $intPosition + $DhcpOptionBytesToRead #shift the number of bytes read
		
		
		#Add option to (vendor specific) array
		if ($DhcpIsVendorSpecific -eq 0)
		{
		   $DhcpOptions[$DhcpOptionCode] = $DhcpOptionValue
		} else {
		   $DhcpVendorSpecificOptions[$DhcpOptionCode] = $DhcpOptionValue
		}
	}
	
	#Show Dhcp Options
	for ( $i = 0 ; $i -lt 256; $i++ ) 
	{ 
		#Is this option 43 (vendor specific)?
		if ($i -ne 43)
		{
				$DhcpOptionIndex = $i
				$DhcpOptionValue = $DhcpOptions[$DhcpOptionIndex]
		
				if ($DhcpOptionValue) { 
					$dhcpOptionName = ($dhcpOptionDetails | Where-Object {$_.Code -eq $DhcpOptionIndex}).Name; if (-not [string]::IsNullOrEmpty($dhcpOptionName)) {$dhcpOptionName = (" ({0})" -f $dhcpOptionName)}
					$dhcpOptionType = ($dhcpOptionDetails | Where-Object {$_.Code -eq $DhcpOptionIndex}).Type; if ([string]::IsNullOrEmpty($dhcpOptionType)) {$dhcpOptionType = "unknown"}
					
					Write-Host -NoNewline ("  - {0}{1}: " -f $DhcpOptionIndex, ($dhcpOptionName))
					switch ($dhcpOptionType.ToLower())
					{
						"ip" {Write-Host ("{0}.{1}.{2}.{3}" -f ($DhcpOptionValue[0], $DhcpOptionValue[1], $DhcpOptionValue[2], $DhcpOptionValue[3]))}
						"string" {Write-Host (Convert-ByteArrayToString $DhcpOptionValue)}
						"time" { Write-host ("{0} seconds" -f [Convert]::ToInt32(($DhcpOptionValue[0].ToString("X2") + $DhcpOptionValue[1].ToString("X2") + $DhcpOptionValue[2].ToString("X2") + $DhcpOptionValue[3].ToString("X2")), 16) ) }
						"dhcpmsgtype" { Write-Host ("{0} ({1})" -f $DhcpOptionValue[0], $DhcpMessageType53Values[$DhcpOptionValue[0]])}
						default { Write-Host ($DhcpOptionValue | ForEach-Object {$_.ToString("X2")}) }
					}
			}
		} else {
			Write-Host ("  - {0} (vendor specific)" -f $i)
			for ( $j = 0 ; $j -lt 256; $j++ ) 
			{
				$DhcpOptionIndex = $j
				$DhcpOptionValue = $DhcpVendorSpecificOptions[$DhcpOptionIndex]
							
				if ($DhcpOptionValue) { 
					$dhcpOptionName = ($dhcpOptionVSDetails | Where-Object {$_.Code -eq $DhcpOptionIndex}).Name; if (-not [string]::IsNullOrEmpty($dhcpOptionName)) {$dhcpOptionName = (" ({0})" -f $dhcpOptionName)}
					$dhcpOptionType = ($dhcpOptionVSDetails | Where-Object {$_.Code -eq $DhcpOptionIndex}).Type; if ([string]::IsNullOrEmpty($dhcpOptionType)) {$dhcpOptionType = "unknown"}
					
					Write-Host -NoNewline ("     - {0}{1}: " -f $DhcpOptionIndex, ($dhcpOptionName))
					switch ($dhcpOptionType.ToLower())
					{
						"ip" {Write-Host ("{0}.{1}.{2}.{3}" -f ($DhcpOptionValue[0], $DhcpOptionValue[1], $DhcpOptionValue[2], $DhcpOptionValue[3]))}
						"string" {Write-Host (Convert-ByteArrayToString $DhcpOptionValue)}
						"time" { Write-host ("{0} seconds" -f [Convert]::ToInt32(($DhcpOptionValue[0].ToString("X2") + $DhcpOptionValue[1].ToString("X2") + $DhcpOptionValue[2].ToString("X2") + $DhcpOptionValue[3].ToString("X2")), 16) ) }
						"dhcpmsgtype" { Write-Host ("{0} ({1})" -f $DhcpOptionValue[0], $DhcpMessageType53Values[$DhcpOptionValue[0]])}
						default { Write-Host ($DhcpOptionValue | ForEach-Object {$_.ToString("X2")}) }
					}
				}
			}
		}
	}
	
	Write-Host ""
	Write-Host ""
}
