### **Awesome Penetration Testing** [![Links Check](https://travis-ci.org/enaqx/awesome-pentest.svg?branch=master)](https://travis-ci.org/enaqx/awesome-pentest)


A collection of awesome penetration testing resources

[This project is supported by Netsparker Web Application Security Scanner](https://www.netsparker.com/?utm_source=github.com&utm_content=awesome+penetration+testing&utm_medium=referral&utm_campaign=generic+advert)


- [Online Resources](#online-resources)
  - [Penetration Testing Resources](#penetration-testing-resources)
  - [Exploit development](#exploit-development)
  - [Social Engineering Resources](#social-engineering-resources)
  - [Lock Picking Resources](#lock-picking-resources)
- [Tools](#tools)
  - [Penetration Testing Distributions](#penetration-testing-distributions)
  - [Basic Penetration Testing Tools](#basic-penetration-testing-tools)
  - [Docker for Penetration Testing](#docker-for-penetration-testing)
  - [Vulnerability Scanners](#vulnerability-scanners)
  - [Network Tools](#network-tools)
  - [Wireless Network Tools](#wireless-network-tools)
  - [SSL Analysis Tools](#ssl-analysis-tools)
  - [Web exploitation](#web-exploitation)
  - [Hex Editors](#hex-editors)
  - [Crackers](#crackers)
  - [Windows Utils](#windows-utils)
  - [Linux Utils](#linux-utils)
  - [DDoS Tools](#ddos-tools)
  - [Social Engineering Tools](#social-engineering-tools)
  - [OSInt Tools](#osint-tools)
  - [Anonymity Tools](#anonymity-tools)
  - [Reverse Engineering Tools](#reverse-engineering-tools)
  - [CTF Tools](#ctf-tools)
- [Books](#books)
  - [Penetration Testing Books](#penetration-testing-books)
  - [Hackers Handbook Series](#hackers-handbook-series)
  - [Network Analysis Books](#network-analysis-books)
  - [Reverse Engineering Books](#reverse-engineering-books)
  - [Malware Analysis Books](#malware-analysis-books)
  - [Windows Books](#windows-books)
  - [Social Engineering Books](#social-engineering-books)
  - [Lock Picking Books](#lock-picking-books)
- [Vulnerability Databases](#vulnerability-databases)
- [Security Courses](#security-courses)
- [Information Security Conferences](#information-security-conferences)
- [Information Security Magazines](#information-security-magazines)
- [Awesome Lists](#awesome-lists)
- [Contribution](#contribution)
- [License](#license)


### Online Resources
#### Penetration Testing Resources
* [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/) - Free Offensive Security Metasploit course
* [PTES](http://www.pentest-standard.org/) - Penetration Testing Execution Standard
* [OWASP](https://www.owasp.org/index.php/Main_Page) - Open Web Application Security Project
* [PENTEST-WIKI](https://github.com/nixawk/pentest-wiki) - A free online security knowledge library for pentesters / researchers.

#### Exploit development
* [Shellcode Tutorial](http://www.vividmachines.com/shellcode/shellcode.html) - Tutorial on how to write shellcode
* [Shellcode Examples](http://shell-storm.org/shellcode/) - Shellcodes database
* [Exploit Writing Tutorials](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/) - Tutorials on how to develop exploits
* [shellsploit](https://github.com/b3mb4m/shellsploit-framework) - New Generation Exploit Development Kit
* [Voltron](https://github.com/snare/voltron) - A hacky debugger UI for hackers

#### Social Engineering Resources
* [Social Engineering Framework](http://www.social-engineer.org/framework/general-discussion/) - An information resource for social engineers

#### Lock Picking Resources
* [Schuyler Towne channel](https://www.youtube.com/user/SchuylerTowne/) - Lockpicking videos and security talks
* [/r/lockpicking](https://www.reddit.com/r/lockpicking) - Resources for learning lockpicking, equipment recommendations.

### Tools
#### Penetration Testing Distributions
* [Kali](https://www.kali.org/) - A Linux distribution designed for digital forensics and penetration testing
* [ArchStrike](https://archstrike.org/) - An Arch Linux repository for security professionals and enthusiasts
* [BlackArch](https://www.blackarch.org/) - Arch Linux-based distribution for penetration testers and security researchers
* [NST](http://networksecuritytoolkit.org/) - Network Security Toolkit distribution
* [Pentoo](http://www.pentoo.ch/) - Security-focused livecd based on Gentoo
* [BackBox](https://backbox.org/) - Ubuntu-based distribution for penetration tests and security assessments
* [Parrot](https://www.parrotsec.org/) - A distribution similar to Kali, with multiple architecture

#### Basic Penetration Testing Tools
* [Metasploit Framework](https://www.metasploit.com/) - World's most used penetration testing software
* [Burp Suite](https://portswigger.net/burp/) - An integrated platform for performing security testing of web applications
* [ExploitPack](http://exploitpack.com/) - Graphical tool for penetration testing with a bunch of exploits
* [BeeF](https://github.com/beefproject/beef) - The Browser Exploitation Framework Project
* [faraday](https://github.com/infobyte/faraday) - Collaborative Penetration Test and Vulnerability Management Platform
* [evilgrade](https://github.com/infobyte/evilgrade) - The update explotation framework
* [commix](https://github.com/stasinopoulos/commix) - Automated All-in-One OS Command Injection and Exploitation Tool
* [routersploit](https://github.com/reverse-shell/routersploit) - Automated penetration testing software for router
* [redsnarf] (https://github.com/nccgroup/redsnarf) - Post-exploitation tool for grabbing credentials

#### Docker for Penetration Testing
* `docker pull kalilinux/kali-linux-docker` [official Kali Linux](https://hub.docker.com/r/kalilinux/kali-linux-docker/)
* `docker pull owasp/zap2docker-stable` - [official OWASP ZAP](https://github.com/zaproxy/zaproxy)
* `docker pull wpscanteam/wpscan` - [official WPScan](https://hub.docker.com/r/wpscanteam/wpscan/)
* `docker pull pandrew/metasploit` - [docker-metasploit](https://hub.docker.com/r/pandrew/metasploit/)
* `docker pull citizenstig/dvwa` - [Damn Vulnerable Web Application (DVWA)](https://hub.docker.com/r/citizenstig/dvwa/)
* `docker pull wpscanteam/vulnerablewordpress` - [Vulnerable WordPress Installation](https://hub.docker.com/r/wpscanteam/vulnerablewordpress/)
* `docker pull hmlio/vaas-cve-2014-6271` - [Vulnerability as a service: Shellshock](https://hub.docker.com/r/hmlio/vaas-cve-2014-6271/)
* `docker pull hmlio/vaas-cve-2014-0160` - [Vulnerability as a service: Heartbleed](https://hub.docker.com/r/hmlio/vaas-cve-2014-0160/)
* `docker pull opendns/security-ninjas` - [Security Ninjas](https://hub.docker.com/r/opendns/security-ninjas/)
* `docker pull diogomonica/docker-bench-security` - [Docker Bench for Security](https://hub.docker.com/r/diogomonica/docker-bench-security/)
* `docker pull ismisepaul/securityshepherd` - [OWASP Security Shepherd](https://hub.docker.com/r/ismisepaul/securityshepherd/)
* `docker pull danmx/docker-owasp-webgoat` - [OWASP WebGoat Project docker image](https://hub.docker.com/r/danmx/docker-owasp-webgoat/)
* `docker pull citizenstig/nowasp` - [OWASP Mutillidae II Web Pen-Test Practice Application](https://hub.docker.com/r/citizenstig/nowasp/)

#### Vulnerability Scanners
* [Nexpose](https://www.rapid7.com/products/nexpose/) - Vulnerability Management & Risk Management Software
* [Nessus](http://www.tenable.com/products/nessus-vulnerability-scanner) - Vulnerability, configuration, and compliance assessment
* [Nikto](https://cirt.net/nikto2) - Web application vulnerability scanner
* [OpenVAS](http://www.openvas.org/) - Open Source vulnerability scanner and manager
* [OWASP Zed Attack Proxy](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) - Penetration testing tool for web applications
* [Secapps](https://secapps.com/) - Integrated web application security testing environment
* [w3af](https://github.com/andresriancho/w3af) - Web application attack and audit framework
* [Wapiti](http://wapiti.sourceforge.net/) - Web application vulnerability scanner
* [WebReaver](http://www.webreaver.com/) - Web application vulnerability scanner for Mac OS X
* [DVCS Ripper](https://github.com/kost/dvcs-ripper) - Rip web accessible (distributed) version control systems: SVN/GIT/HG/BZR
* [arachni](https://github.com/Arachni/arachni) - Web Application Security Scanner Framework

#### Network Tools
* [nmap](https://nmap.org/) - Free Security Scanner For Network Exploration & Security Audits
* [pig](https://github.com/rafael-santiago/pig) - A Linux packet crafting tool
* [tcpdump/libpcap](http://www.tcpdump.org/) - A common packet analyzer that runs under the command line
* [Wireshark](https://www.wireshark.org/) - A network protocol analyzer for Unix and Windows
* [Network Tools](http://network-tools.com/) - Different network tools: ping, lookup, whois, etc
* [netsniff-ng](https://github.com/netsniff-ng/netsniff-ng) - A Swiss army knife for for network sniffing
* [Intercepter-NG](http://sniff.su/) - a multifunctional network toolkit
* [SPARTA](http://sparta.secforce.com/) - Network Infrastructure Penetration Testing Tool
* [dnschef](http://thesprawl.org/projects/dnschef/) - A highly configurable DNS proxy for pentesters
* [DNSDumpster](https://dnsdumpster.com/) - Online DNS recon and search service
* [dnsenum](https://github.com/fwaeytens/dnsenum/) - Perl script that enumerates DNS information from a domain, attempts zone transfers, performs a brute force dictionary style attack, and then performs reverse look-ups on the results
* [dnsmap](https://github.com/makefu/dnsmap/) - Passive DNS network mapper
* [dnsrecon](https://github.com/darkoperator/dnsrecon/) - DNS Enumeration Script
* [dnstracer](http://www.mavetju.org/unix/dnstracer.php) - Determines where a given DNS server gets its information from, and follows the chain of DNS servers
* [passivedns-client](https://github.com/chrislee35/passivedns-client) - Provides a library and a query tool for querying several passive DNS providers
* [passivedns](https://github.com/gamelinux/passivedns) - A network sniffer that logs all DNS server replies for use in a passive DNS setup
* [Mass Scan](https://github.com/robertdavidgraham/masscan) - TCP port scanner, spews SYN packets asynchronously, scanning entire Internet in under 5 minutes.
* [Zarp](https://github.com/hatRiot/zarp) - Zarp is a network attack tool centered around the exploitation of local networks
* [mitmproxy](https://github.com/mitmproxy/mitmproxy) - An interactive SSL-capable intercepting HTTP proxy for penetration testers and software developers
* [mallory](https://github.com/justmao945/mallory) - HTTP/HTTPS proxy over SSH
* [Netzob](https://github.com/netzob/netzob) - Reverse engineering, traffic generation and fuzzing of communication protocols
* [DET](https://github.com/sensepost/DET) - DET is a proof of concept to perform Data Exfiltration using either single or multiple channel(s) at the same time
* [pwnat](https://github.com/samyk/pwnat) - punches holes in firewalls and NATs
* [dsniff](https://www.monkey.org/~dugsong/dsniff/) - a collection of tools for network auditing and pentesting
* [tgcd](http://tgcd.sourceforge.net/) - a simple Unix network utility to extend the accessibility of TCP/IP based network services beyond firewalls
* [smbmap](https://github.com/ShawnDEvans/smbmap) - a handy SMB enumeration tool
* [scapy](https://github.com/secdev/scapy) - a python-based interactive packet manipulation program & library
* [Dshell](https://github.com/USArmyResearchLab/Dshell) - Network forensic analysis framework
* [Debookee (MAC OS X)](http://www.iwaxx.com/debookee/) - Intercept traffic from any device on your network
* [Dripcap](https://github.com/dripcap/dripcap) - Caffeinated packet analyzer

#### Wireless Network Tools
* [Aircrack-ng](http://www.aircrack-ng.org/) - a set of tools for auditing wireless network
* [Kismet](https://kismetwireless.net/) - Wireless network detector, sniffer, and IDS
* [Reaver](https://code.google.com/archive/p/reaver-wps) - Brute force attack against Wifi Protected Setup
* [Wifite](https://github.com/derv82/wifite) - Automated wireless attack tool
* [wifiphisher](https://github.com/sophron/wifiphisher) - Automated phishing attacks against Wi-Fi networks

#### SSL Analysis Tools
* [SSLyze](https://github.com/nabla-c0d3/sslyze) - SSL configuration scanner
* [sslstrip](https://www.thoughtcrime.org/software/sslstrip/) - a demonstration of the HTTPS stripping attacks
* [sslstrip2](https://github.com/LeonardoNve/sslstrip2) - SSLStrip version to defeat HSTS
* [tls_prober](https://github.com/WestpointLtd/tls_prober) - fingerprint a server's SSL/TLS implementation

#### Web exploitation
* [WPScan](https://wpscan.org/) - Black box WordPress vulnerability scanner
* [SQLmap](http://sqlmap.org/) - Automatic SQL injection and database takeover tool
* [weevely3](https://github.com/epinna/weevely3) - Weaponized web shell
* [Wappalyzer](https://wappalyzer.com/) - Wappalyzer uncovers the technologies used on websites
* [cms-explorer](https://code.google.com/archive/p/cms-explorer/) - CMS Explorer is designed to reveal the the specific modules, plugins, components and themes that various CMS driven web sites are running.
* [joomscan](https://www.owasp.org/index.php/Category:OWASP_Joomla_Vulnerability_Scanner_Project) - Joomla CMS scanner
* [WhatWeb](https://github.com/urbanadventurer/WhatWeb) - Website Fingerprinter
* [BlindElephant](http://blindelephant.sourceforge.net/) - Web Application Fingerprinter
* [fimap](https://github.com/kurobeats/fimap) - Find, prepare, audit, exploit and even google automatically for LFI/RFI bugs
* [Kadabra](https://github.com/D35m0nd142/Kadabra) - Automatic LFI exploiter and scanner
* [Kadimus](https://github.com/P0cL4bs/Kadimus) - LFI scan and exploit tool
* [liffy](https://github.com/hvqzao/liffy) - LFI exploitation tool

#### Hex Editors
* [HexEdit.js](https://hexed.it) - Browser-based hex editing
* [Hexinator](https://hexinator.com/) (commercial) - World's finest Hex Editor

#### Crackers
* [John the Ripper](http://www.openwall.com/john/) - Fast password cracker
* [Online MD5 cracker](http://www.md5crack.com/) - Online MD5 hash Cracker
* [Hashcat](http://hashcat.net/hashcat/) - The more fast hash cracker

#### Windows Utils
* [Sysinternals Suite](https://technet.microsoft.com/en-us/sysinternals/bb842062) - The Sysinternals Troubleshooting Utilities
* [Windows Credentials Editor](http://www.ampliasecurity.com/research/windows-credentials-editor/) - security tool to list logon sessions and add, change, list and delete associated credentials
* [mimikatz](http://blog.gentilkiwi.com/mimikatz) - Credentials extraction tool for Windows OS
* [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) - A PowerShell Post-Exploitation Framework
* [Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester) - Detects potential missing patches on the target
* [Responder](https://github.com/SpiderLabs/Responder) - A LLMNR, NBT-NS and MDNS poisoner
* [Empire](https://github.com/PowerShellEmpire/Empire) - Empire is a pure PowerShell post-exploitation agent
* [Fibratus](https://github.com/rabbitstack/fibratus) - Tool for exploration and tracing of the Windows kernel

#### Linux Utils
* [Linux Exploit Suggester](https://github.com/PenturaLabs/Linux_Exploit_Suggester) - Linux Exploit Suggester; based on operating system release number.

#### DDoS Tools
* [LOIC](https://github.com/NewEraCracker/LOIC/) - An open source network stress tool for Windows
* [JS LOIC](http://metacortexsecurity.com/tools/anon/LOIC/LOICv1.html) - JavaScript in-browser version of LOIC
* [T50](https://sourceforge.net/projects/t50/) - The more fast network stress tool

#### Social Engineering Tools
* [SET](https://github.com/trustedsec/social-engineer-toolkit) - The Social-Engineer Toolkit from TrustedSec

#### OSInt Tools
* [Maltego](http://www.paterva.com/web7/) - Proprietary software for open source intelligence and forensics, from Paterva.
* [theHarvester](https://github.com/laramies/theHarvester) - E-mail, subdomain and people names harvester
* [creepy](https://github.com/ilektrojohn/creepy) - A geolocation OSINT tool
* [metagoofil](https://github.com/laramies/metagoofil) - Metadata harvester
* [Google Hacking Database](https://www.exploit-db.com/google-hacking-database/) - a database of Google dorks; can be used for recon
* [Censys](https://www.censys.io/) - Collects data on hosts and websites through daily ZMap and ZGrab scans
* [Shodan](https://www.shodan.io/) - Shodan is the world's first search engine for Internet-connected devices
* [recon-ng](https://bitbucket.org/LaNMaSteR53/recon-ng) - A full-featured Web Reconnaissance framework written in Python
* [github-dorks](https://github.com/techgaun/github-dorks) - CLI tool to scan github repos/organizations for potential sensitive information leak
* [vcsmap](https://github.com/melvinsh/vcsmap) - A plugin-based tool to scan public version control systems for sensitive information
* [Spiderfoot](http://www.spiderfoot.net/) - multi-source OSINT automation tool with a Web UI and report visualizations

#### Anonymity Tools
* [Tor](https://www.torproject.org/) - The free software for enabling onion routing online anonymity
* [I2P](https://geti2p.net/en/) - The Invisible Internet Project
* [Nipe](https://github.com/GouveaHeitor/nipe) - Script to redirect all traffic from the machine to the Tor network.

#### Reverse Engineering Tools
* [IDA Pro](https://www.hex-rays.com/products/ida/) - A Windows, Linux or Mac OS X hosted multi-processor disassembler and debugger
* [IDA Free](https://www.hex-rays.com/products/ida/support/download_freeware.shtml) - The freeware version of IDA v5.0
* [WDK/WinDbg](https://msdn.microsoft.com/en-us/windows/hardware/hh852365.aspx) - Windows Driver Kit and WinDbg
* [OllyDbg](http://www.ollydbg.de/) - An x86 debugger that emphasizes binary code analysis
* [Radare2](http://rada.re/r/index.html) - Opensource, crossplatform reverse engineering framework
* [x64_dbg](http://x64dbg.com/) - An open-source x64/x32 debugger for windows
* [Immunity Debugger](http://debugger.immunityinc.com/) - A powerful new way to write exploits and analyze malware
* [Evan's Debugger](http://www.codef00.com/projects#debugger) - OllyDbg-like debugger for Linux
* [Medusa disassembler](https://github.com/wisk/medusa) - An open source interactive disassembler
* [plasma](https://github.com/joelpx/plasma) - Interactive disassembler for x86/ARM/MIPS. Generates indented pseudo-code with colored syntax code
* [peda](https://github.com/longld/peda) - Python Exploit Development Assistance for GDB
* [dnSpy](https://github.com/0xd4d/dnSpy) - dnSpy is a tool to reverse engineer .NET assemblies

#### CTF Tools
* [Pwntools](https://github.com/Gallopsled/pwntools) - CTF framework for use in CTFs

### Books
#### Penetration Testing Books
* [The Art of Exploitation by Jon Erickson, 2008](https://www.nostarch.com/hacking2.htm)
* [Metasploit: The Penetration Tester's Guide by David Kennedy et al., 2011](https://www.nostarch.com/metasploit)
* [Penetration Testing: A Hands-On Introduction to Hacking by Georgia Weidman, 2014](https://www.nostarch.com/pentesting)
* [Rtfm: Red Team Field Manual by Ben Clark, 2014](http://www.amazon.com/Rtfm-Red-Team-Field-Manual/dp/1494295504/)
* [The Hacker Playbook by Peter Kim, 2014](http://www.amazon.com/The-Hacker-Playbook-Practical-Penetration/dp/1494932636/)
* [The Basics of Hacking and Penetration Testing by Patrick Engebretson, 2013](https://www.elsevier.com/books/the-basics-of-hacking-and-penetration-testing/engebretson/978-1-59749-655-1)
* [Professional Penetration Testing by Thomas Wilhelm, 2013](https://www.elsevier.com/books/professional-penetration-testing/wilhelm/978-1-59749-993-4)
* [Advanced Penetration Testing for Highly-Secured Environments by Lee Allen, 2012](http://www.packtpub.com/networking-and-servers/advanced-penetration-testing-highly-secured-environments-ultimate-security-gu)
* [Violent Python by TJ O'Connor, 2012](https://www.elsevier.com/books/violent-python/unknown/978-1-59749-957-6)
* [Fuzzing: Brute Force Vulnerability Discovery by Michael Sutton et al., 2007](http://www.fuzzing.org/)
* [Black Hat Python: Python Programming for Hackers and Pentesters by Justin Seitz, 2014](http://www.amazon.com/Black-Hat-Python-Programming-Pentesters/dp/1593275900)
* [Penetration Testing: Procedures & Methodologies by EC-Council, 2010](http://www.amazon.com/Penetration-Testing-Procedures-Methodologies-EC-Council/dp/1435483677)
* [Unauthorised Access: Physical Penetration Testing For IT Security Teams by Wil Allsopp, 2010](http://www.amazon.com/Unauthorised-Access-Physical-Penetration-Security-ebook/dp/B005DIAPKE)
* [Advanced Persistent Threat Hacking: The Art and Science of Hacking Any Organization by Tyler Wrightson, 2014](http://www.amazon.com/Advanced-Persistent-Threat-Hacking-Organization/dp/0071828362)
* [Bug Hunter's Diary by Tobias Klein, 2011](https://www.nostarch.com/bughunter)

#### Hackers Handbook Series
* [The Database Hacker's Handbook, David Litchfield et al., 2005](http://www.wiley.com/WileyCDA/WileyTitle/productCd-0764578014.html)
* [The Shellcoders Handbook by Chris Anley et al., 2007](http://www.wiley.com/WileyCDA/WileyTitle/productCd-047008023X.html)
* [The Mac Hacker's Handbook by Charlie Miller & Dino Dai Zovi, 2009](http://www.wiley.com/WileyCDA/WileyTitle/productCd-0470395362.html)
* [The Web Application Hackers Handbook by D. Stuttard, M. Pinto, 2011](http://www.wiley.com/WileyCDA/WileyTitle/productCd-1118026470.html)
* [iOS Hackers Handbook by Charlie Miller et al., 2012](http://www.wiley.com/WileyCDA/WileyTitle/productCd-1118204123.html)
* [Android Hackers Handbook by Joshua J. Drake et al., 2014](http://www.wiley.com/WileyCDA/WileyTitle/productCd-111860864X.html)
* [The Browser Hackers Handbook by Wade Alcorn et al., 2014](http://www.wiley.com/WileyCDA/WileyTitle/productCd-1118662091.html)
* [The Mobile Application Hackers Handbook by Dominic Chell et al., 2015](http://www.wiley.com/WileyCDA/WileyTitle/productCd-1118958500.html)
* [Car Hacker's Handbook by Craig Smith, 2016](https://www.nostarch.com/carhacking)

#### Network Analysis Books
* [Nmap Network Scanning by Gordon Fyodor Lyon, 2009](https://nmap.org/book/)
* [Practical Packet Analysis by Chris Sanders, 2011](https://www.nostarch.com/packet2.htm)
* [Wireshark Network Analysis by by Laura Chappell & Gerald Combs, 2012](http://www.wiresharkbook.com/)
* [Network Forensics: Tracking Hackers through Cyberspace by Sherri Davidoff & Jonathan Ham, 2012](http://www.amazon.com/Network-Forensics-Tracking-Hackers-Cyberspace-ebook/dp/B008CG8CYU/)

#### Reverse Engineering Books
* [Reverse Engineering for Beginners by Dennis Yurichev](http://beginners.re/)
* [Hacking the Xbox by Andrew Huang, 2003](https://www.nostarch.com/xbox.htm)
* [The IDA Pro Book by Chris Eagle, 2011](https://www.nostarch.com/idapro2.htm)
* [Practical Reverse Engineering by Bruce Dang et al., 2014](http://www.wiley.com/WileyCDA/WileyTitle/productCd-1118787315.html)
* [Gray Hat Hacking The Ethical Hacker's Handbook by Daniel Regalado et al., 2015](http://www.amazon.com/Hacking-Ethical-Hackers-Handbook-Edition/dp/0071832386)

#### Malware Analysis Books
* [Practical Malware Analysis by Michael Sikorski & Andrew Honig, 2012](https://www.nostarch.com/malware)
* [The Art of Memory Forensics by Michael Hale Ligh et al., 2014](http://www.wiley.com/WileyCDA/WileyTitle/productCd-1118825098.html)
* [Malware Analyst's Cookbook and DVD by Michael Hale Ligh et al., 2010](http://www.wiley.com/WileyCDA/WileyTitle/productCd-0470613033.html)

#### Windows Books
* [Windows Internals by Mark Russinovich et al., 2012](http://www.amazon.com/Windows-Internals-Part-Developer-Reference/dp/0735648735/)

#### Social Engineering Books
* [The Art of Deception by Kevin D. Mitnick & William L. Simon, 2002](http://www.wiley.com/WileyCDA/WileyTitle/productCd-0471237124.html)
* [The Art of Intrusion by Kevin D. Mitnick & William L. Simon, 2005](http://www.wiley.com/WileyCDA/WileyTitle/productCd-0764569597.html)
* [Ghost in the Wires by Kevin D. Mitnick & William L. Simon, 2011](http://www.hachettebookgroup.com/titles/kevin-mitnick/ghost-in-the-wires/9780316134477/)
* [No Tech Hacking by Johnny Long & Jack Wiles, 2008](https://www.elsevier.com/books/no-tech-hacking/mitnick/978-1-59749-215-7)
* [Social Engineering: The Art of Human Hacking by Christopher Hadnagy, 2010](http://www.wiley.com/WileyCDA/WileyTitle/productCd-0470639539.html)
* [Unmasking the Social Engineer: The Human Element of Security by Christopher Hadnagy, 2014](http://www.wiley.com/WileyCDA/WileyTitle/productCd-1118608577.html)
* [Social Engineering in IT Security: Tools, Tactics, and Techniques by Sharon Conheady, 2014](https://www.mhprofessional.com/product.php?isbn=0071818464)

#### Lock Picking Books
* [Practical Lock Picking by Deviant Ollam, 2012](https://www.elsevier.com/books/practical-lock-picking/ollam/978-1-59749-989-7)
* [Keys to the Kingdom by Deviant Ollam, 2012](https://www.elsevier.com/books/keys-to-the-kingdom/ollam/978-1-59749-983-5)
* [CIA Lock Picking Field Operative Training Manual](https://www.scribd.com/doc/7207/CIA-Lock-Picking-Field-Operative-Training-Manual)
* [Lock Picking: Detail Overkill by Solomon](https://www.dropbox.com/s/y39ix9u9qpqffct/Lockpicking%20Detail%20Overkill.pdf?dl=0)
* [Eddie the Wire books](https://www.dropbox.com/sh/k3z4dm4vyyojp3o/AAAIXQuwMmNuCch_StLPUYm-a?dl=0)

### Vulnerability Databases
* [NVD](https://nvd.nist.gov/) - US National Vulnerability Database
* [CERT](https://www.us-cert.gov/) - US Computer Emergency Readiness Team
* [OSVDB](https://blog.osvdb.org/) - Open Sourced Vulnerability Database
* [Bugtraq](http://www.securityfocus.com/) - Symantec SecurityFocus
* [Exploit-DB](https://www.exploit-db.com/) - Offensive Security Exploit Database
* [Fulldisclosure](http://seclists.org/fulldisclosure/) - Full Disclosure Mailing List
* [MS Bulletin](https://technet.microsoft.com/en-us/security/bulletins) - Microsoft Security Bulletin
* [MS Advisory](https://technet.microsoft.com/en-us/security/advisories) - Microsoft Security Advisories
* [Inj3ct0r](http://www.1337day.com/) - Inj3ct0r Exploit Database
* [Packet Storm](https://packetstormsecurity.com/) - Packet Storm Global Security Resource
* [SecuriTeam](http://www.securiteam.com/) - Securiteam Vulnerability Information
* [CXSecurity](http://cxsecurity.com/) - CSSecurity Bugtraq List
* [Vulnerability Laboratory](http://www.vulnerability-lab.com/) - Vulnerability Research Laboratory
* [ZDI](http://www.zerodayinitiative.com/) - Zero Day Initiative

### Security Courses
* [Offensive Security Training](https://www.offensive-security.com/information-security-training/) - Training from BackTrack/Kali developers
* [SANS Security Training](http://www.sans.org/) - Computer Security Training & Certification
* [Open Security Training](http://opensecuritytraining.info/) - Training material for computer security classes
* [CTF Field Guide](https://trailofbits.github.io/ctf/) - everything you need to win your next CTF competition

### Information Security Conferences
* [DEF CON](https://www.defcon.org/) - An annual hacker convention in Las Vegas
* [Black Hat](http://www.blackhat.com/) - An annual security conference in Las Vegas
* [BSides](http://www.securitybsides.com/) - A framework for organising and holding security conferences
* [CCC](https://events.ccc.de/congress/) - An annual meeting of the international hacker scene in Germany
* [DerbyCon](https://www.derbycon.com/) - An annual hacker conference based in Louisville
* [PhreakNIC](http://phreaknic.info/) - A technology conference held annually in middle Tennessee
* [ShmooCon](http://shmoocon.org/) - An annual US east coast hacker convention
* [CarolinaCon](http://www.carolinacon.org/) - An infosec conference, held annually in North Carolina
* [SummerCon](http://www.summercon.org/) - One of the oldest hacker conventions, held during Summer
* [Hack.lu](https://2016.hack.lu/) - An annual conference held in Luxembourg
* [HITB](https://conference.hitb.org/) - Deep-knowledge security conference held in Malaysia and The Netherlands
* [Troopers](https://www.troopers.de) - Annual international IT Security event with workshops held in Heidelberg, Germany
* [Hack3rCon](http://hack3rcon.org/) - An annual US hacker conference
* [ThotCon](http://thotcon.org/) - An annual US hacker conference held in Chicago
* [LayerOne](http://www.layerone.org/) - An annual US security conference held every spring in Los Angeles
* [DeepSec](https://deepsec.net/) - Security Conference in Vienna, Austria
* [SkyDogCon](http://www.skydogcon.com/) - A technology conference in Nashville
* [SECUINSIDE](http://secuinside.com) - Security Conference in [Seoul](https://en.wikipedia.org/wiki/Seoul)
* [DefCamp](http://def.camp/) - Largest Security Conference in Eastern Europe, held anually in Bucharest, Romania
* [AppSecUSA](https://appsecusa.org/) - An annual conference organised by OWASP
* [BruCON](http://brucon.org) - An annual security conference in Belgium
* [Infosecurity Europe](http://www.infosecurityeurope.com/) - Europe's number one information security event, held in London, UK
* [Nullcon](http://nullcon.net/website/) - An annual conference in Delhi and Goa, India
* [RSA Conference USA](https://www.rsaconference.com/) - An annual security conference in San Francisco, California, USA
* [Swiss Cyber Storm](https://www.swisscyberstorm.com/) - An annual security conference in Lucerne, Switzerland
* [Virus Bulletin Conference](https://www.virusbulletin.com/conference/index) - An annual conference going to be held in Denver, USA for 2016
* [Ekoparty](http://www.ekoparty.org) - Largest Security Conference in Latin America, held annually in Buenos Aires, Argentina
* [44Con](https://44con.com/) - Annual Security Conference held in London
* [BalCCon](https://www.balccon.org) - Balkan Computer Congress, annualy held in Novi Sad, Serbia
* [FSec](http://fsec.foi.hr) - FSec - Croatian Information Security Gathering in Varaždin, Croatia

### Information Security Magazines
* [2600: The Hacker Quarterly](https://www.2600.com/Magazine/DigitalEditions) - An American publication about technology and computer "underground"
* [Phrack Magazine](http://www.phrack.org/) - By far the longest running hacker zine

### Awesome Lists
* [Kali Linux Tools](http://tools.kali.org/tools-listing) - List of tools present in Kali Linux
* [SecTools](http://sectools.org/) - Top 125 Network Security Tools
* [C/C++ Programming](https://github.com/fffaraz/awesome-cpp) - One of the main language for open source security tools
* [.NET Programming](https://github.com/quozd/awesome-dotnet) - A software framework for Microsoft Windows platform development
* [Shell Scripting](https://github.com/alebcay/awesome-shell) - Command-line frameworks, toolkits, guides and gizmos
* [Ruby Programming by @dreikanter](https://github.com/dreikanter/ruby-bookmarks) - The de-facto language for writing exploits
* [Ruby Programming by @markets](https://github.com/markets/awesome-ruby) - The de-facto language for writing exploits
* [Ruby Programming by @Sdogruyol](https://github.com/Sdogruyol/awesome-ruby) - The de-facto language for writing exploits
* [JavaScript Programming](https://github.com/sorrycc/awesome-javascript) - In-browser development and scripting
* [Node.js Programming by @sindresorhus](https://github.com/sindresorhus/awesome-nodejs) - JavaScript in command-line
* [Node.js Programming by @vndmtrx](https://github.com/vndmtrx/awesome-nodejs) -  JavaScript in command-line
* [Python tools for penetration testers](https://github.com/dloss/python-pentest-tools) - Lots of pentesting tools are written in Python
* [Python Programming by @svaksha](https://github.com/svaksha/pythonidae) - General Python programming
* [Python Programming by @vinta](https://github.com/vinta/awesome-python) - General Python programming
* [Android Security](https://github.com/ashishb/android-security-awesome) - A collection of android security related resources
* [Awesome Awesomness](https://github.com/bayandin/awesome-awesomeness) - The List of the Lists
* [AppSec](https://github.com/paragonie/awesome-appsec) - Resources for learning about application security
* [CTFs](https://github.com/apsdehal/awesome-ctf) - Capture The Flag frameworks, libraries, etc
* [Hacking](https://github.com/carpedm20/awesome-hacking) - Tutorials, tools, and resources
* [Honeypots](https://github.com/paralax/awesome-honeypots) - Honeypots, tools, components, and more
* [Infosec](https://github.com/onlurking/awesome-infosec) - Information security resources for pentesting, forensics, and more
* [Malware Analysis](https://github.com/rshipp/awesome-malware-analysis) - Tools and resources for analysts
* [PCAP Tools](https://github.com/caesar0301/awesome-pcaptools) - Tools for processing network traffic
* [Security](https://github.com/sbilly/awesome-security) - Software, libraries, documents, and other resources
* [Awesome List](https://github.com/sindresorhus/awesome) - A curated list of awesome lists
* [SecLists](https://github.com/danielmiessler/SecLists) - Collection of multiple types of lists used during security assessments
* [Security Talks](https://github.com/PaulSec/awesome-sec-talks) - A curated list of security conferences

### Contribution
Your contributions and suggestions are heartily♥ welcome. (✿◕‿◕). Please check the [Contributing Guidelines](.github/CONTRIBUTING.md) for more details.

### License

[![Creative Commons License](http://i.creativecommons.org/l/by/4.0/88x31.png)](https://creativecommons.org/licenses/by/4.0/)

This work is licensed under a [Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/)
