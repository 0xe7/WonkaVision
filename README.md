# WonkaVision
----

WonkaVision is a proof of concept (POC) tool to analyze Kerberos tickets and attempt to determine if they are forged. This tool was created by [Charlie Clark](https://twitter.com/exploitph) and [Andrew Schwartz](https://twitter.com/4ndr3w6s).

**It should be noted that this POC is not intended to be a production-ready enterprise application, but rather to generate ideas on how to better detect forged tickets while publicising discovered IOAs.**

[Charlie Clark](https://twitter.com/exploitph) is the primary author of this code base.

Much of the code to dump session information, dump Kerberos tickets and decrypt/encrypt Kerberos tickets was taken from [Rubeus](https://github.com/GhostPack/Rubeus). The GetNCChanges code was adapted from [Vincent Le Toux](https://twitter.com/mysmartlogon)'s [MakeMeEnterpriseAdmin](https://github.com/vletoux/MakeMeEnterpriseAdmin).

It has 3 functions:

* `/createkeys` - Creates a public/private key pair for use by the dumper and analyzer
* `/dump` - To be run on servers/workstations, dumps session data with associated Kerberos tickets
* `/analyze` - Run against a directory containing all of the dump files, analyzes all sessions and tickets within the dumps, generates scores and writes to the event log

WonkaVision has the following dependancies:

* Newtonsoft.Json - For serializing/deserializing json objects
* dnMerge - For merging the Newtonsoft.Json DLL into a single binary for easier deployment when dumping tickets

The slide deck from the talk is [here](/Andrew_Charlie_SANS_Hackfest_2022_revised.pdf).

WonkaVision is licensed under the BSD 3-Clause license.

## Table of Contents

- [WonkaVision](#WonkaVision)
  - [Create Keys](#createkeys)
  - [Dump](#dump)
  - [Analyze](#analyze)
     -  [Event Log Sample](#event-log-sample)
     -  [SIEM Log Forwarding Sample](#siem-forwarding-sample)
        -  [Example with Splunk](#example-with-splunk)
        -  [Example with Sentinel](#example-with-sentinel)
- [Talk Demos](#talk-demos)
- [Kerberos Sniffer](#krbsniffer-poc)
- [Acknowledgements](#acknowledgements)
- [TODO](#todo)

## CreateKeys

Generates a public and private key pair using the Elliptic Curve Diffie-Hellman (ECDH) key exchange algorithm using the P-256 curve. By default it outputs the keys to the terminal as base64 encoded blobs but has the `/outdir:PATH` argument to write the keys to files.

**IF WRITING TO FILES, THE private.key FILE SHOULD BE PROTECTED AS IF IT WAS THE KRBTGT KEY**

Example 1:
```
C:\WonkaVision>WonkaVision.exe /createkeys
====================PublicKey====================
RUNLMSAAAABN/odC5C5W7meBvf6rKmWOoVW9qRTRcyCJBFuvRbEvMFuMa8cV20W1e+rRd4f9jSfr5vDVJ0+I/SJsZI1ondws
==================End PublicKey==================


====================PrivateKey====================
RUNLMiAAAABN/odC5C5W7meBvf6rKmWOoVW9qRTRcyCJBFuvRbEvMFuMa8cV20W1e+rRd4f9jSfr5vDVJ0+I/SJsZI1ondwsto7Fc/J4akdJdCix51F0ELLKWlsdMDlkYx2shFEV3AA=
==================End PrivateKey==================
```

Example 2:
```
C:\WonkaVision>WonkaVision.exe /createkeys /outdir:.
[!] Writing key files to ., be sure to protect the private key as if it was the krbtgt key!
[*] Written public key to .\public.key
[*] Written private key to .\private.key

C:\WonkaVision>dir
 Volume in drive C is System
 Volume Serial Number is 22BC-4361

 Directory of C:\WonkaVision

10/14/2022  01:10 PM    <DIR>          .
10/14/2022  01:10 PM    <DIR>          ..
10/14/2022  01:10 PM               104 private.key
10/14/2022  01:10 PM                72 public.key
10/14/2022  01:08 PM         1,383,424 WonkaVision.exe
               3 File(s)      1,383,600 bytes
               2 Dir(s)  71,813,464,064 bytes free
```

## Dump

Dumps session information of sessions that contain Kerberos tickets, including the Kerberos tickets themselves in KERB-CRED format. It does this by executing [LsaCallAuthenticationPackage](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsacallauthenticationpackage) to request session information, information about the ticket cache and request tickets as KERB-CREDs (the same way [Rubeus](https://github.com/GhostPack/Rubeus)' `dump` command does).

2 primary arguments are required:

* `/publickey:KEY` - public key to be used for encryption of the dumped data
* `/dumpdir:DIR` - directory to store the dumped data

Once the data has been dumped, WonkaVision does the following:

1. Stores the data in a Json string
2. Generates a public/private key pair for the dumper
3. Uses its private key along with the public key passed to it using the `/publickey:KEY` argument to derive a symmetric key
4. Encrypts the Json string with AES using the symmetric key
5. Stores the encrypted data, it's public key and the IV within a Json string and writes that to the directory specified by the `/dumpdir:DIR` argument

It is possible to specify specific sessions (with the `/luid:X` argument), users (with the `/user:USER` argument), services (with the `/service:SVC` argument) and/or servers (with the `/server:Y` argument) but these have not currently been under much testing.

Example:
```
WonkaVision.exe /dump /publickey:\\server\dumpshare\public.key /dumpdir:\\server\dumpshare\dumps
```

## Analyze

Analyzes dumps created using the `/dump` command. It loops through all of the child directories points to by `/dumpdir:DIR` recursively and reads any .json files it encounters. Once it deserializes the json file, it loops through all sessions stored within it and all tickets within the sessions and analyzes them in as much depth as possible, allocating a score for each deviation from expected found. Afterwards, it adds up these scores to produce a total score and generates 2 different types of Windows events, 9988 and 9989, for _WonkaVision Session_ and _WonkaVision Ticket_ respectively, containing all of the discovered issues.

It is possible to specify `/creduser:USER`, `/creddomain:DOMAIN` and `/credpass:PASSWORD` to use alternative credentials for the LDAP queries and DCsyncing. This however is not advised in production use, they were implemented for debugging issues a little easier.

2 primary arguments are required:

* `/privatekey:KEY` - private key used to decrypt the encrypted dumps
* `/dumpdir:DIR` - directory where the encrypted dumps are stored

Example:
```
WonkaVision.exe /analyze /privatekey:C:\keys\private.key /dumpdir:C:\dumpshare\dumps
```

### Event Log Sample
Although, WonkaVision will return analysis output via the terminal, a more detailed description of Indicator of Attack (IOA) analysis can be found in the Windows Application Event Log channel. It is here that an analyst will be given greater insight and context in terms of the Total Score, the specific IOAs, the reason(s) for the IOAs, and tool scores. Two events are written, 9988 (Session Event) and 9989 (Ticket Event) respectively. A sample of Events can be found [here](https://github.com/0xe7/WonkaVisionDev/blob/main/EVTX%20Sample/WV-demo.evtx). 

The following is an example of a WonkaVision Session Event (9988):
![9988 Event](media/EVTX%20Screenshots/WV_Event_9988_Session.jpg)

The following is an example of a WonkaVision Ticket Event (9989):

Example of Possible Forged Golden Ticket with Mimikatz in EVTX logs:
![9989 Event](media/EVTX%20Screenshots/WV_Event_9989_Mimikatz_1.jpg)

![9989 Event 2](media/EVTX%20Screenshots/WV_Event_9989_Mimikatz_2.jpg)

### SIEM Log Forwarding Sample
As noted above, WonkaVision's logs are written to the Windows Application Event Log channel. If configured, these logs can be forwarded to a SIEM (e.g. Splunk, Sentinel, etc.).

#### Example with Splunk
A suggested query using Splunk "Classic" WinEvnet Logging can also be used:
```
index="wv_demo_wineventlog" source="WinEventLog:Application" (Total_Score>=8) | table _time,Total_Score,User,Machine_Name,Service_Principal_Name,Mimikatz_Score,Rubeus_Score,Impacket_Score,Cobalt_Strike_Score,IOA_Reasons
```

Example of Possible Forged Golden Ticket with Mimikatz WonkaVision in Splunk:
![Mimikatz WonkaVisvion Splunk](media/SIEM%20Screenshots/mimikatz_wonkavision_splunk.jpg)

Example of Possible Forged Golden Ticket with Rubeus from WonkaVision in Splunk:![Rubeus WonkaVisvion Splunk](media/SIEM%20Screenshots/rubeus_wonkavision_splunk.jpg)

#### Example with Sentinel
Logging with Sentinel can also be accomplished. However, this may require additional parsing. An example query from Jonathan Johnson (@jsecurity101) is below of how WonkaVision may appear parsed in Sentinel:

```
Event
    | where Computer contains "asgard" and Source contains "Wonka"
    | extend ParsedEventData=parse_xml(EventData)
    | extend Data=ParsedEventData.DataItem.EventData.Data
    | parse-where Data with *
            "Total Score: " TotalScore:string
            "Session: " Session:string
            "Machine Name: " MachineName:string
            "User: " User:string
            "Service Principal Name: " ServicePrincipalName:string
            "IOAs: " IOAs:string
            "SessionUser: " IOA_SessionUser:string
            "KDCCalled: " IOA_KDCCalled:string
            "Mimikatz Score: " TScore_MimikatzScore:string 
            "Impacket Score: " TScore_ImpacketScore:string 
            "Rubeus Score: " TScore_RubeusScore:string 
            "Cobalt Strike Score: " TScore_CobaltStrikeScore:string 
            "IOA Reasons: " IOA_Reasons:string
    | where IOA_SessionUser contains "thor"
```
Example of Possible Forged Golden Ticket from WonkaVision in Sentinel:
![WonkaVisvion Sentinel](media/SIEM%20Screenshots/wonakvision_sentinel.jpg)

## Talk Demos

Demo 1 - Golden Ticket Creation:

https://user-images.githubusercontent.com/13423848/202441525-aec75260-a991-4a4d-8df1-6fbf92ddbb4c.mp4

Demo 2 - Key Pair Creation and Session/Ticket Dump:

https://user-images.githubusercontent.com/13423848/202441775-b753ae06-d012-4258-9ea0-25d88dc80549.mp4

Demo 3 - Dump Analysis and Windows Event Output:

https://user-images.githubusercontent.com/13423848/202441909-04bd1b2a-f204-41c4-a13a-dcfa42eebcf3.mp4

Demo 4 - Kerberos Network Sniffer:

https://user-images.githubusercontent.com/13423848/202442125-822cc4a4-1c87-447f-88ae-2e5c2fbf58d3.mp4

## KrbSniffer POC

The Kerberos Traffic Sniffer POC that we demonstrated in our talk ([Demo 4](media/Demo%20Videos/Demo%204%20-%20Kerberos%20Sniffer.mp4)) was implemented with [SharpPCap](https://github.com/dotpcap/sharppcap) but could easily be modified to use raw sockets, removing that dependancy as well as the need for installing [npcap](https://npcap.com/) on the system. 

As it was only a minimal POC most of the indicators that were implemented were the unencrypted indicators mentioned in Charlie's YASCON 2020 talk detailed on slide 18 of [this slide deck](https://github.com/0xe7/Talks/blob/main/Inspecting%20Kerberos%20Ticket%20Requests%20v1.pdf), although many more could be implemented.

## Acknowledgements
* Will Schroeder (@harmj0y) for [Rubeus](https://github.com/GhostPack/Rubeus) code base
* Vincent Le Toux (@mysmartlogon) for '[Make Me Enterprise Admin](https://github.com/vletoux/MakeMeEnterpriseAdmin)' code base
* Jared Atkinson (@jaredcatkinson) for '[Get-KerberosTicketGrantingTicket.ps1](https://gist.github.com/jaredcatkinson/c95fd1e4e76a4b9b966861f64782f5a9#file-get-kerberosticketgrantingticket-ps1)' & '[Test-KerberosTicketGrantingTicket.ps1](https://gist.github.com/jaredcatkinson/c95fd1e4e76a4b9b966861f64782f5a9#file-test-kerberosticketgrantingticket-ps1)' code base
* Jonathan Johnson (@jsecurity101) for help in troubleshooting a DCSync error :), POC Testing, Microsoft Sentinel testing & advice/guidnace on writing to the Windows Event log
* Elad Shamir (@elad_shamir) for advice/guidnace
* The 'sisoc-tokyo' team (The University of Tokyo, Wataru Matsuda, Mariko Fujimoto, & Takuho Mitsunaga) who presented '[Real-time detection of attacks leveraging Domain Administrator privilege](https://i.blackhat.com/eu-18/Wed-Dec-5/eu-18-Matsuda-Real-time-Detection-of-Attacks-Leveraging-Domain-Administrator-Privilege.pdf)' at BlackHat Europe 2018 whose work we found post POC. Their project can can be found [here](https://github.com/sisoc-tokyo/Real-timeDetectionAD_ver2) 
* Semperis (@SemperisTech) & Trustedsec (@TrustedSec) for allowing us to complete this project

## TODO
- [ ] Refactor and Cleanup Code
- [ ] Implement Trust Key Retrieval
