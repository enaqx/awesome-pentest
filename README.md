# Awesome Penetration Testing [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

> A collection of awesome penetration testing resources.

**[This project is supported by Netsparker Web Application Security Scanner](https://www.netsparker.com/?utm_source=github.com&utm_content=awesome+penetration+testing&utm_medium=referral&utm_campaign=generic+advert)**

[Penetration testing](https://en.wikipedia.org/wiki/Penetration_test) is the practice of launching authorized, simulated attacks against computer systems and their physical infrastructure to expose potential security weaknesses and vulnerabilities.

Your contributions and suggestions are heartily♥ welcome. (✿◕‿◕). Please check the [Contributing Guidelines](CONTRIBUTING.md) for more details. This work is licensed under a [Creative Commons Attribution 4.0 International License](http://creativecommons.org/licenses/by/4.0/).

## Contents

* [Online Resources](#online-resources)
  * [Penetration Testing Resources](#penetration-testing-resources)
  * [Exploit Development](#exploit-development)
  * [Open Source Intelligence (OSINT) Resources](#osint-resources)
  * [Social Engineering Resources](#social-engineering-resources)
  * [Lock Picking Resources](#lock-picking-resources)
  * [Operating Systems](#operating-systems)
* [Tools](#tools)
  * [Penetration Testing Distributions](#penetration-testing-distributions)
  * [Docker for Penetration Testing](#docker-for-penetration-testing)
  * [Multi-paradigm Frameworks](#multi-paradigm-frameworks)
  * [Network Vulnerability scanners](#network-vulnerability-scanners)
    * [Static Analyzers](#static-analyzers)
    * [Web Vulnerability Scanners](#web-vulnerability-scanners)
  * [Network Tools](#network-tools)
  * [Wireless Network Tools](#wireless-network-tools)
  * [Transport Layer Security Tools](#transport-layer-security-tools)
  * [Web Exploitation](#web-exploitation)
  * [Hex Editors](#hex-editors)
  * [File Format Analysis Tools](#file-format-analysis-tools)
  * [Defense Evasion Tools](#defense-evasion-tools)
  * [Hash Cracking Tools](#hash-cracking-tools)
  * [Windows Utilities](#windows-utilities)
  * [GNU/Linux Utilities](#gnulinux-utilities)
  * [macOS Utilities](#macos-utilities)
  * [DDoS Tools](#ddos-tools)
  * [Social Engineering Tools](#social-engineering-tools)
  * [OSINT Tools](#osint-tools)
  * [Anonymity Tools](#anonymity-tools)
  * [Reverse Engineering Tools](#reverse-engineering-tools)
  * [Physical Access Tools](#physical-access-tools)
  * [Side-channel Tools](#side-channel-tools)
  * [CTF Tools](#ctf-tools)
  * [Penetration Testing Report Templates](#penetration-testing-report-templates)
* [Books](#books)
  * [Penetration Testing Books](#penetration-testing-books)
  * [Hackers Handbook Series](#hackers-handbook-series)
  * [Defensive Development](#defensive-development)
  * [Network Analysis Books](#network-analysis-books)
  * [Reverse Engineering Books](#reverse-engineering-books)
  * [Malware Analysis Books](#malware-analysis-books)
  * [Windows Books](#windows-books)
  * [Social Engineering Books](#social-engineering-books)
  * [Lock Picking Books](#lock-picking-books)
  * [Defcon Suggested Reading](#defcon-suggested-reading)
* [Vulnerability Databases](#vulnerability-databases)
* [Security Courses](#security-courses)
* [Information Security Conferences](#information-security-conferences)
* [Information Security Magazines](#information-security-magazines)
* [Awesome Lists](#awesome-lists)

## Online Resources

### Penetration Testing Resources

* [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/) - Free Offensive Security Metasploit course.
* [Penetration Testing Execution Standard (PTES)](http://www.pentest-standard.org/) - Documentation designed to provide a common language and scope for performing and reporting the results of a penetration test.
* [Open Web Application Security Project (OWASP)](https://www.owasp.org/index.php/Main_Page) - Worldwide not-for-profit charitable organization focused on improving the security of especially Web-based and Application-layer software.
* [PENTEST-WIKI](https://github.com/nixawk/pentest-wiki) - Free online security knowledge library for pentesters and researchers.
* [Penetration Testing Framework (PTF)](http://www.vulnerabilityassessment.co.uk/Penetration%20Test.html) - Outline for performing penetration tests compiled as a general framework usable by vulnerability analysts and penetration testers alike.
* [XSS-Payloads](http://www.xss-payloads.com) - Ultimate resource for all things cross-site including payloads, tools, games and documentation.
* [MITRE's Adversarial Tactics, Techniques & Common Knowledge (ATT&CK)](https://attack.mitre.org/) - Curated knowledge base and model for cyber adversary behavior.

### Exploit Development

* [Shellcode Tutorial](http://www.vividmachines.com/shellcode/shellcode.html) - Tutorial on how to write shellcode.
* [Shellcode Examples](http://shell-storm.org/shellcode/) - Shellcodes database.
* [Exploit Writing Tutorials](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/) - Tutorials on how to develop exploits.

### OSINT Resources

* [OSINT Framework](http://osintframework.com/) - Collection of various OSINT tools broken out by category.
* [Intel Techniques](https://inteltechniques.com/menu.html) - Collection of OSINT tools. Menu on the left can be used to navigate through the categories.
* [NetBootcamp OSINT Tools](http://netbootcamp.org/osinttools/) - Collection of OSINT links and custom Web interfaces to other services such as [Facebook Graph Search](http://netbootcamp.org/facebook.html) and [various paste sites](http://netbootcamp.org/pastesearch.html).
* [WiGLE.net](https://wigle.net/) - Information about wireless networks world-wide, with user-friendly desktop and web applications.

### Social Engineering Resources

* [Social Engineering Framework](http://www.social-engineer.org/framework/general-discussion/) - Information resource for social engineers.

### Lock Picking Resources

* [Schuyler Towne channel](https://www.youtube.com/user/SchuylerTowne/) - Lockpicking videos and security talks.
* [bosnianbill](https://www.youtube.com/user/bosnianbill) - More lockpicking videos.
* [/r/lockpicking](https://www.reddit.com/r/lockpicking) - Resources for learning lockpicking, equipment recommendations.

### Operating Systems

* [Security related Operating Systems @ Rawsec](http://list.rawsec.ml/operating_systems.html) - Complete list of security related operating systems.
* [Security @ Distrowatch](http://distrowatch.com/search.php?category=Security) - Website dedicated to talking about, reviewing, and keeping up to date with open source operating systems.
* [cuckoo](https://github.com/cuckoosandbox/cuckoo) - Open source automated malware analysis system.
* [Digital Evidence & Forensics Toolkit (DEFT)](http://www.deftlinux.net/) - Live CD for forensic analysis runnable without tampering or corrupting connected devices where the boot process takes place.
* [Tails](https://tails.boum.org/) - Live OS aimed at preserving privacy and anonymity.

## Tools

### Penetration Testing Distributions

* [Kali](https://www.kali.org/) - GNU/Linux distribution designed for digital forensics and penetration testing.
* [ArchStrike](https://archstrike.org/) - Arch GNU/Linux repository for security professionals and enthusiasts.
* [BlackArch](https://www.blackarch.org/) - Arch GNU/Linux-based distribution for penetration testers and security researchers.
* [Network Security Toolkit (NST)](http://networksecuritytoolkit.org/) - Fedora-based bootable live operating system designed to provide easy access to best-of-breed open source network security applications.
* [BackBox](https://backbox.org/) - Ubuntu-based distribution for penetration tests and security assessments.
* [Parrot](https://www.parrotsec.org/) - Distribution similar to Kali, with multiple architecture.
* [Buscador](https://inteltechniques.com/buscador/) - GNU/Linux virtual machine that is pre-configured for online investigators.
* [Fedora Security Lab](https://labs.fedoraproject.org/en/security/) - Provides a safe test environment to work on security auditing, forensics, system rescue and teaching security testing methodologies.
* [The Pentesters Framework](https://github.com/trustedsec/ptf) - Distro organized around the Penetration Testing Execution Standard (PTES), providing a curated collection of utilities that eliminates often unused toolchains.
* [AttifyOS](https://github.com/adi0x90/attifyos) - GNU/Linux distribution focused on tools useful during Internet of Things (IoT) security assessments.

### Docker for Penetration Testing

* `docker pull kalilinux/kali-linux-docker` [official Kali Linux](https://hub.docker.com/r/kalilinux/kali-linux-docker/)
* `docker pull owasp/zap2docker-stable` - [official OWASP ZAP](https://github.com/zaproxy/zaproxy)
* `docker pull wpscanteam/wpscan` - [official WPScan](https://hub.docker.com/r/wpscanteam/wpscan/)
* `docker pull citizenstig/dvwa` - [Damn Vulnerable Web Application (DVWA)](https://hub.docker.com/r/citizenstig/dvwa/)
* `docker pull wpscanteam/vulnerablewordpress` - [Vulnerable WordPress Installation](https://hub.docker.com/r/wpscanteam/vulnerablewordpress/)
* `docker pull hmlio/vaas-cve-2014-6271` - [Vulnerability as a service: Shellshock](https://hub.docker.com/r/hmlio/vaas-cve-2014-6271/)
* `docker pull hmlio/vaas-cve-2014-0160` - [Vulnerability as a service: Heartbleed](https://hub.docker.com/r/hmlio/vaas-cve-2014-0160/)
* `docker pull opendns/security-ninjas` - [Security Ninjas](https://hub.docker.com/r/opendns/security-ninjas/)
* `docker pull diogomonica/docker-bench-security` - [Docker Bench for Security](https://hub.docker.com/r/diogomonica/docker-bench-security/)
* `docker pull ismisepaul/securityshepherd` - [OWASP Security Shepherd](https://hub.docker.com/r/ismisepaul/securityshepherd/)
* `docker pull danmx/docker-owasp-webgoat` - [OWASP WebGoat Project docker image](https://hub.docker.com/r/danmx/docker-owasp-webgoat/)
* `docker-compose build && docker-compose up` - [OWASP NodeGoat](https://github.com/owasp/nodegoat#option-3---run-nodegoat-on-docker)
* `docker pull citizenstig/nowasp` - [OWASP Mutillidae II Web Pen-Test Practice Application](https://hub.docker.com/r/citizenstig/nowasp/)
* `docker pull bkimminich/juice-shop` - [OWASP Juice Shop](https://github.com/bkimminich/juice-shop#docker-container--)
* `docker pull kalilinux/kali-linux-docker` - [Kali Linux Docker Image](https://www.kali.org/news/official-kali-linux-docker-images/)
* `docker pull phocean/msf` - [docker-metasploit](https://hub.docker.com/r/phocean/msf/)

### Multi-paradigm Frameworks

* [Metasploit](https://www.metasploit.com/) - Software for offensive security teams to help verify vulnerabilities and manage security assessments.
* [Armitage](http://fastandeasyhacking.com/) - Java-based GUI front-end for the Metasploit Framework.
* [Faraday](https://github.com/infobyte/faraday) - Multiuser integrated pentesting environment for red teams performing cooperative penetration tests, security audits, and risk assessments.
* [ExploitPack](https://github.com/juansacco/exploitpack) - Graphical tool for automating penetration tests that ships with many pre-packaged exploits.
* [Pupy](https://github.com/n1nj4sec/pupy) - Cross-platform (Windows, Linux, macOS, Android) remote administration and post-exploitation tool.
* [AutoSploit](https://github.com/NullArray/AutoSploit) - Automated mass exploiter, which collects target by employing the Shodan.io API and programmatically chooses Metasploit exploit modules based on the Shodan query.

### Network Vulnerability Scanners

* [Netsparker Application Security Scanner](https://www.netsparker.com/) - Application security scanner to automatically find security flaws.
* [Nexpose](https://www.rapid7.com/products/nexpose/) - Commercial vulnerability and risk management assessment engine that integrates with Metasploit, sold by Rapid7.
* [Nessus](https://www.tenable.com/products/nessus-vulnerability-scanner) - Commercial vulnerability management, configuration, and compliance assessment platform, sold by Tenable.
* [OpenVAS](http://www.openvas.org/) - Free software implementation of the popular Nessus vulnerability assessment system.
* [Vuls](https://github.com/future-architect/vuls) - Agentless vulnerability scanner for GNU/Linux and FreeBSD, written in Go.

#### Static Analyzers

* [Brakeman](https://github.com/presidentbeef/brakeman) - Static analysis security vulnerability scanner for Ruby on Rails applications.
* [cppcheck](http://cppcheck.sourceforge.net/) - Extensible C/C++ static analyzer focused on finding bugs.
* [FindBugs](http://findbugs.sourceforge.net/) - Free software static analyzer to look for bugs in Java code.
* [sobelow](https://github.com/nccgroup/sobelow) - Security-focused static analysis for the Phoenix Framework.
* [bandit](https://pypi.python.org/pypi/bandit/) - Security oriented static analyser for python code.
* [Progpilot](https://github.com/designsecurity/progpilot) - Static security analysis tool for PHP code.

#### Web Vulnerability Scanners

* [Netsparker Application Security Scanner](https://www.netsparker.com/) - Application security scanner to automatically find security flaws.
* [Nikto](https://cirt.net/nikto2) - Noisy but fast black box web server and web application vulnerability scanner.
* [Arachni](http://www.arachni-scanner.com/) - Scriptable framework for evaluating the security of web applications.
* [w3af](https://github.com/andresriancho/w3af) - Web application attack and audit framework.
* [Wapiti](http://wapiti.sourceforge.net/) - Black box web application vulnerability scanner with built-in fuzzer.
* [SecApps](https://secapps.com/) - In-browser web application security testing suite.
* [WebReaver](https://www.webreaver.com/) - Commercial, graphical web application vulnerability scanner designed for macOS.
* [WPScan](https://wpscan.org/) - Black box WordPress vulnerability scanner.
* [Zoom](https://github.com/UltimateHackers/Zoom) - Powerful wordpress username enumerator with infinite scanning.
* [cms-explorer](https://code.google.com/archive/p/cms-explorer/) - Reveal the specific modules, plugins, components and themes that various websites powered by content management systems are running.
* [joomscan](https://www.owasp.org/index.php/Category:OWASP_Joomla_Vulnerability_Scanner_Project) - Joomla vulnerability scanner.
* [ACSTIS](https://github.com/tijme/angularjs-csti-scanner) - Automated client-side template injection (sandbox escape/bypass) detection for AngularJS.
* [SQLmate](https://github.com/UltimateHackers/sqlmate) - A friend of sqlmap that identifies sqli vulnerabilities based on a given dork and website (optional).


### Network Tools

* [zmap](https://zmap.io/) - Open source network scanner that enables researchers to easily perform Internet-wide network studies.
* [nmap](https://nmap.org/) - Free security scanner for network exploration & security audits.
* [pig](https://github.com/rafael-santiago/pig) - GNU/Linux packet crafting tool.
* [scanless](https://github.com/vesche/scanless) - Utility for using websites to perform port scans on your behalf so as not to reveal your own IP.
* [tcpdump/libpcap](http://www.tcpdump.org/) - Common packet analyzer that runs under the command line.
* [Wireshark](https://www.wireshark.org/) - Widely-used graphical, cross-platform network protocol analyzer.
* [Network-Tools.com](http://network-tools.com/) - Website offering an interface to numerous basic network utilities like `ping`, `traceroute`, `whois`, and more.
* [netsniff-ng](https://github.com/netsniff-ng/netsniff-ng) - Swiss army knife for for network sniffing.
* [Intercepter-NG](http://sniff.su/) - Multifunctional network toolkit.
* [SPARTA](https://sparta.secforce.com/) - Graphical interface offering scriptable, configurable access to existing network infrastructure scanning and enumeration tools.
* [dnschef](https://github.com/iphelix/dnschef) - Highly configurable DNS proxy for pentesters.
* [DNSDumpster](https://dnsdumpster.com/) - Online DNS recon and search service.
* [CloudFail](https://github.com/m0rtem/CloudFail) - Unmask server IP addresses hidden behind Cloudflare by searching old database records and detecting misconfigured DNS.
* [dnsenum](https://github.com/fwaeytens/dnsenum/) - Perl script that enumerates DNS information from a domain, attempts zone transfers, performs a brute force dictionary style attack, and then performs reverse look-ups on the results.
* [dnsmap](https://github.com/makefu/dnsmap/) - Passive DNS network mapper.
* [dnsrecon](https://github.com/darkoperator/dnsrecon/) - DNS enumeration script.
* [dnstracer](http://www.mavetju.org/unix/dnstracer.php) - Determines where a given DNS server gets its information from, and follows the chain of DNS servers.
* [passivedns-client](https://github.com/chrislee35/passivedns-client) - Library and query tool for querying several passive DNS providers.
* [passivedns](https://github.com/gamelinux/passivedns) - Network sniffer that logs all DNS server replies for use in a passive DNS setup.
* [Mass Scan](https://github.com/robertdavidgraham/masscan) - TCP port scanner, spews SYN packets asynchronously, scanning entire Internet in under 5 minutes.
* [Zarp](https://github.com/hatRiot/zarp) - Network attack tool centered around the exploitation of local networks.
* [mitmproxy](https://github.com/mitmproxy/mitmproxy) - Interactive TLS-capable intercepting HTTP proxy for penetration testers and software developers.
* [Morpheus](https://github.com/r00t-3xp10it/morpheus) - Automated ettercap TCP/IP Hijacking tool.
* [mallory](https://github.com/justmao945/mallory) - HTTP/HTTPS proxy over SSH.
* [SSH MITM](https://github.com/jtesta/ssh-mitm) - Intercept SSH connections with a proxy; all plaintext passwords and sessions are logged to disk.
* [Netzob](https://github.com/netzob/netzob) - Reverse engineering, traffic generation and fuzzing of communication protocols.
* [DET](https://github.com/sensepost/DET) - Proof of concept to perform data exfiltration using either single or multiple channel(s) at the same time.
* [pwnat](https://github.com/samyk/pwnat) - Punches holes in firewalls and NATs.
* [dsniff](https://www.monkey.org/~dugsong/dsniff/) - Collection of tools for network auditing and pentesting.
* [tgcd](http://tgcd.sourceforge.net/) - Simple Unix network utility to extend the accessibility of TCP/IP based network services beyond firewalls.
* [smbmap](https://github.com/ShawnDEvans/smbmap) - Handy SMB enumeration tool.
* [scapy](https://github.com/secdev/scapy) - Python-based interactive packet manipulation program & library.
* [Dshell](https://github.com/USArmyResearchLab/Dshell) - Network forensic analysis framework.
* [Debookee](http://www.iwaxx.com/debookee/) - Simple and powerful network traffic analyzer for macOS.
* [Dripcap](https://github.com/dripcap/dripcap) - Caffeinated packet analyzer.
* [Printer Exploitation Toolkit (PRET)](https://github.com/RUB-NDS/PRET) - Tool for printer security testing capable of IP and USB connectivity, fuzzing, and exploitation of PostScript, PJL, and PCL printer language features.
* [Praeda](http://h.foofus.net/?page_id=218) - Automated multi-function printer data harvester for gathering usable data during security assessments.
* [routersploit](https://github.com/reverse-shell/routersploit) - Open source exploitation framework similar to Metasploit but dedicated to embedded devices.
* [evilgrade](https://github.com/infobyte/evilgrade) - Modular framework to take advantage of poor upgrade implementations by injecting fake updates.
* [XRay](https://github.com/evilsocket/xray) - Network (sub)domain discovery and reconnaissance automation tool.
* [Ettercap](http://www.ettercap-project.org) - Comprehensive, mature suite for machine-in-the-middle attacks.
* [BetterCAP](https://www.bettercap.org/) - Modular, portable and easily extensible MITM framework.
* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - Swiss army knife for pentesting networks.
* [impacket](https://github.com/CoreSecurity/impacket) - Collection of Python classes for working with network protocols.
* [ACLight](https://github.com/cyberark/ACLight) - Script for advanced discovery of sensitive Privileged Accounts - includes Shadow Admins.
* [dnstwist](https://github.com/elceef/dnstwist) - Domain name permutation engine for detecting typo squatting, phishing and corporate espionage.

### Wireless Network Tools

* [Aircrack-ng](http://www.aircrack-ng.org/) - Set of tools for auditing wireless networks.
* [Kismet](https://kismetwireless.net/) - Wireless network detector, sniffer, and IDS.
* [Reaver](https://code.google.com/archive/p/reaver-wps) - Brute force attack against WiFi Protected Setup.
* [Wifite](https://github.com/derv82/wifite) - Automated wireless attack tool.
* [Fluxion](https://github.com/FluxionNetwork/fluxion) - Suite of automated social engineering based WPA attacks.

### Transport Layer Security Tools

* [SSLyze](https://github.com/nabla-c0d3/sslyze) - Fast and comprehensive TLS/SSL configuration analyzer to help identify security mis-configurations.
* [tls_prober](https://github.com/WestpointLtd/tls_prober) - Fingerprint a server's SSL/TLS implementation.
* [testssl.sh](https://github.com/drwetter/testssl.sh) - Command line tool which checks a server's service on any port for the support of TLS/SSL ciphers, protocols as well as some cryptographic flaws.
* [crackpkcs12](https://github.com/crackpkcs12/crackpkcs12) - Multithreaded program to crack PKCS#12 files (`.p12` and `.pfx` extensions), such as TLS/SSL certificates.

### Web Exploitation

* [OWASP Zed Attack Proxy (ZAP)](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) - Feature-rich, scriptable HTTP intercepting proxy and fuzzer for penetration testing web applications.
* [Fiddler](https://www.telerik.com/fiddler) - Free cross-platform web debugging proxy with user-friendly companion tools.
* [Burp Suite](https://portswigger.net/burp/) - Integrated platform for performing security testing of web applications.
* [autochrome](https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2017/march/autochrome/) - Easy to install a test browser with all the appropriate setting needed for web application testing with native Burp support, from NCCGroup.
* [Browser Exploitation Framework (BeEF)](https://github.com/beefproject/beef) - Command and control server for delivering exploits to commandeered Web browsers.
* [Offensive Web Testing Framework (OWTF)](https://www.owasp.org/index.php/OWASP_OWTF) - Python-based framework for pentesting Web applications based on the OWASP Testing Guide.
* [Wordpress Exploit Framework](https://github.com/rastating/wordpress-exploit-framework) - Ruby framework for developing and using modules which aid in the penetration testing of WordPress powered websites and systems.
* [WPSploit](https://github.com/espreto/wpsploit) - Exploit WordPress-powered websites with Metasploit.
* [SQLmap](http://sqlmap.org/) - Automatic SQL injection and database takeover tool.
* [tplmap](https://github.com/epinna/tplmap) - Automatic server-side template injection and Web server takeover tool.
* [weevely3](https://github.com/epinna/weevely3) - Weaponized web shell.
* [Wappalyzer](https://www.wappalyzer.com/) - Wappalyzer uncovers the technologies used on websites.
* [WhatWeb](https://github.com/urbanadventurer/WhatWeb) - Website fingerprinter.
* [BlindElephant](http://blindelephant.sourceforge.net/) - Web application fingerprinter.
* [wafw00f](https://github.com/EnableSecurity/wafw00f) - Identifies and fingerprints Web Application Firewall (WAF) products.
* [fimap](https://github.com/kurobeats/fimap) - Find, prepare, audit, exploit and even Google automatically for LFI/RFI bugs.
* [Kadabra](https://github.com/D35m0nd142/Kadabra) - Automatic LFI exploiter and scanner.
* [Kadimus](https://github.com/P0cL4bs/Kadimus) - LFI scan and exploit tool.
* [liffy](https://github.com/hvqzao/liffy) - LFI exploitation tool.
* [Commix](https://github.com/commixproject/commix) - Automated all-in-one operating system command injection and exploitation tool.
* [DVCS Ripper](https://github.com/kost/dvcs-ripper) - Rip web accessible (distributed) version control systems: SVN/GIT/HG/BZR.
* [GitTools](https://github.com/internetwache/GitTools) - Automatically find and download Web-accessible `.git` repositories.
* [sslstrip](https://www.thoughtcrime.org/software/sslstrip/) - Demonstration of the HTTPS stripping attacks.
* [sslstrip2](https://github.com/LeonardoNve/sslstrip2) - SSLStrip version to defeat HSTS.
* [NoSQLmap](http://nosqlmap.net/) - Automatic NoSQL injection and database takeover tool.
* [VHostScan](https://github.com/codingo/VHostScan) - A virtual host scanner that performs reverse lookups, can be used with pivot tools, detect catch-all scenarios, aliases and dynamic default pages.
* [FuzzDB](https://github.com/fuzzdb-project/fuzzdb) - Dictionary of attack patterns and primitives for black-box application fault injection and resource discovery.
* [EyeWitness](https://github.com/ChrisTruncer/EyeWitness) - Tool to take screenshots of websites, provide some server header info, and identify default credentials if possible.
* [webscreenshot](https://github.com/maaaaz/webscreenshot) - A simple script to take screenshots of list of websites.

### Hex Editors

* [HexEdit.js](https://hexed.it) - Browser-based hex editing.
* [Hexinator](https://hexinator.com/) - World's finest (proprietary, commercial) Hex Editor.
* [Frhed](http://frhed.sourceforge.net/) - Binary file editor for Windows.
* [0xED](http://www.suavetech.com/0xed/0xed.html) - Native macOS hex editor that supports plug-ins to display custom data types.
* [Hex Fiend](http://ridiculousfish.com/hexfiend/) - Fast, open source, hex editor for macOS with support for viewing  binary diffs.

### File Format Analysis Tools

* [Kaitai Struct](http://kaitai.io/) - File formats and network protocols dissection language and web IDE, generating parsers in C++, C#, Java, JavaScript, Perl, PHP, Python, Ruby.
* [Veles](https://codisec.com/veles/) - Binary data visualization and analysis tool.
* [Hachoir](http://hachoir3.readthedocs.io/) - Python library to view and edit a binary stream as tree of fields and tools for metadata extraction.

### Defense Evasion Tools

* [Veil](https://www.veil-framework.com/) - Generate metasploit payloads that bypass common anti-virus solutions.
* [shellsploit](https://github.com/Exploit-install/shellsploit-framework) - Generates custom shellcode, backdoors, injectors, optionally obfuscates every byte via encoders.
* [Hyperion](http://nullsecurity.net/tools/binary.html) - Runtime encryptor for 32-bit portable executables ("PE `.exe`s").
* [AntiVirus Evasion Tool (AVET)](https://github.com/govolution/avet) - Post-process exploits containing executable files targeted for Windows machines to avoid being recognized by antivirus software.
* [peCloak.py](https://www.securitysift.com/pecloak-py-an-experiment-in-av-evasion/) - Automates the process of hiding a malicious Windows executable from antivirus (AV) detection.
* [peCloakCapstone](https://github.com/v-p-b/peCloakCapstone) - Multi-platform fork of the peCloak.py automated malware antivirus evasion tool.
* [UniByAv](https://github.com/Mr-Un1k0d3r/UniByAv) - Simple obfuscator that takes raw shellcode and generates Anti-Virus friendly executables by using a brute-forcable, 32-bit XOR key.
* [Shellter](https://www.shellterproject.com/) - Dynamic shellcode injection tool, and the first truly dynamic PE infector ever created.

### Hash Cracking Tools

* [John the Ripper](http://www.openwall.com/john/) - Fast password cracker.
* [Hashcat](http://hashcat.net/hashcat/) - The more fast hash cracker.
* [CeWL](https://digi.ninja/projects/cewl.php) - Generates custom wordlists by spidering a target's website and collecting unique words.
* [JWT Cracker](https://github.com/lmammino/jwt-cracker) - Simple HS256 JWT token brute force cracker.
* [Rar Crack](http://rarcrack.sourceforge.net) - RAR bruteforce cracker.
* [BruteForce Wallet](https://github.com/glv2/bruteforce-wallet) - Find the password of an encrypted wallet file (i.e. `wallet.dat`).

### Windows Utilities

* [Sysinternals Suite](https://technet.microsoft.com/en-us/sysinternals/bb842062) - The Sysinternals Troubleshooting Utilities.
* [Windows Credentials Editor](http://www.ampliasecurity.com/research/windows-credentials-editor/) - Inspect logon sessions and add, change, list, and delete associated credentials, including Kerberos tickets.
* [mimikatz](http://blog.gentilkiwi.com/mimikatz) - Credentials extraction tool for Windows operating system.
* [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) - PowerShell Post-Exploitation Framework.
* [Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester) - Detects potential missing patches on the target.
* [Responder](https://github.com/SpiderLabs/Responder) - LLMNR, NBT-NS and MDNS poisoner.
* [Bloodhound](https://github.com/adaptivethreat/Bloodhound/wiki) - Graphical Active Directory trust relationship explorer.
* [Empire](https://www.powershellempire.com/) - Pure PowerShell post-exploitation agent.
* [Fibratus](https://github.com/rabbitstack/fibratus) - Tool for exploration and tracing of the Windows kernel.
* [wePWNise](https://labs.mwrinfosecurity.com/tools/wepwnise/) - Generates architecture independent VBA code to be used in Office documents or templates and automates bypassing application control and exploit mitigation software.
* [redsnarf](https://github.com/nccgroup/redsnarf) - Post-exploitation tool for retrieving password hashes and credentials from Windows workstations, servers, and domain controllers.
* [Magic Unicorn](https://github.com/trustedsec/unicorn) - Shellcode generator for numerous attack vectors, including Microsoft Office macros, PowerShell, HTML applications (HTA), or `certutil` (using fake certificates).
* [DeathStar](https://github.com/byt3bl33d3r/DeathStar) - Python script that uses Empire's RESTful API to automate gaining Domain Admin rights in Active Directory environments.

### GNU/Linux Utilities

* [Linux Exploit Suggester](https://github.com/PenturaLabs/Linux_Exploit_Suggester) - Heuristic reporting on potentially viable exploits for a given GNU/Linux system.

### macOS Utilities

* [Bella](https://github.com/Trietptm-on-Security/Bella) - Pure Python post-exploitation data mining and remote administration tool for macOS.

### DDoS Tools

* [LOIC](https://github.com/NewEraCracker/LOIC/) - Open source network stress tool for Windows.
* [JS LOIC](http://metacortexsecurity.com/tools/anon/LOIC/LOICv1.html) - JavaScript in-browser version of LOIC.
* [SlowLoris](https://github.com/gkbrk/slowloris) - DoS tool that uses low bandwidth on the attacking side.
* [HOIC](https://sourceforge.net/projects/high-orbit-ion-cannon/) - Updated version of Low Orbit Ion Cannon, has 'boosters' to get around common counter measures.
* [T50](https://sourceforge.net/projects/t50/) - Faster network stress tool.
* [UFONet](https://github.com/epsylon/ufonet) - Abuses OSI layer 7 HTTP to create/manage 'zombies' and to conduct different attacks using; `GET`/`POST`, multithreading, proxies, origin spoofing methods, cache evasion techniques, etc.
* [Memcrashed](https://github.com/649/Memcrashed-DDoS-Exploit) - DDoS attack tool for sending forged UDP packets to vulnerable Memcached servers obtained using Shodan API.

### Social Engineering Tools

* [Social Engineer Toolkit (SET)](https://github.com/trustedsec/social-engineer-toolkit) - Open source pentesting framework designed for social engineering featuring a number of custom attack vectors to make believable attacks quickly.
* [King Phisher](https://github.com/securestate/king-phisher) - Phishing campaign toolkit used for creating and managing multiple simultaneous phishing attacks with custom email and server content.
* [Evilginx](https://github.com/kgretzky/evilginx) - MITM attack framework used for phishing credentials and session cookies from any Web service.
* [wifiphisher](https://github.com/sophron/wifiphisher) - Automated phishing attacks against WiFi networks.
* [Catphish](https://github.com/ring0lab/catphish) - Tool for phishing and corporate espionage written in Ruby.
* [Beelogger](https://github.com/4w4k3/BeeLogger) - Tool for generating keylooger.

### OSINT Tools

* [Maltego](http://www.paterva.com/web7/) - Proprietary software for open source intelligence and forensics, from Paterva.
* [theHarvester](https://github.com/laramies/theHarvester) - E-mail, subdomain and people names harvester.
* [creepy](https://github.com/ilektrojohn/creepy) - Geolocation OSINT tool.
* [metagoofil](https://github.com/laramies/metagoofil) - Metadata harvester.
* [Google Hacking Database](https://www.exploit-db.com/google-hacking-database/) - Database of Google dorks; can be used for recon.
* [Google-dorks](https://github.com/JohnTroony/Google-dorks) - Common Google dorks and others you probably don't know.
* [GooDork](https://github.com/k3170makan/GooDork) - Command line Google dorking tool.
* [dork-cli](https://github.com/jgor/dork-cli) - Command line Google dork tool.
* [Censys](https://www.censys.io/) - Collects data on hosts and websites through daily ZMap and ZGrab scans.
* [Shodan](https://www.shodan.io/) - World's first search engine for Internet-connected devices.
* [recon-ng](https://bitbucket.org/LaNMaSteR53/recon-ng) - Full-featured Web Reconnaissance framework written in Python.
* [github-dorks](https://github.com/techgaun/github-dorks) - CLI tool to scan github repos/organizations for potential sensitive information leak.
* [vcsmap](https://github.com/melvinsh/vcsmap) - Plugin-based tool to scan public version control systems for sensitive information.
* [Spiderfoot](http://www.spiderfoot.net/) - Multi-source OSINT automation tool with a Web UI and report visualizations
* [BinGoo](https://github.com/Hood3dRob1n/BinGoo) - GNU/Linux bash based Bing and Google Dorking Tool.
* [fast-recon](https://github.com/DanMcInerney/fast-recon) - Perform Google dorks against a domain.
* [snitch](https://github.com/Smaash/snitch) - Information gathering via dorks.
* [Sn1per](https://github.com/1N3/Sn1per) - Automated Pentest Recon Scanner.
* [Threat Crowd](https://www.threatcrowd.org/) - Search engine for threats.
* [Virus Total](https://www.virustotal.com/) - VirusTotal is a free service that analyzes suspicious files and URLs and facilitates the quick detection of viruses, worms, trojans, and all kinds of malware.
* [DataSploit](https://github.com/upgoingstar/datasploit) - OSINT visualizer utilizing Shodan, Censys, Clearbit, EmailHunter, FullContact, and Zoomeye behind the scenes.
* [AQUATONE](https://github.com/michenriksen/aquatone) - Subdomain discovery tool utilizing various open sources producing a report that can be used as input to other tools.
* [Intrigue](http://intrigue.io) - Automated OSINT & Attack Surface discovery framework with powerful API, UI and CLI.
* [ZoomEye](https://www.zoomeye.org/) - Search engine for cyberspace that lets the user find specific network components.
* [gOSINT](https://github.com/Nhoya/gOSINT) - OSINT tool with multiple modules and a telegram scraper.
* [Amass](https://github.com/caffix/amass) - Subdomain enumeration via scraping, web archives, brute forcing, permutations, reverse DNS sweeping, TLS certificates, passive DNS data sources, etc.

### Anonymity Tools

* [Tor](https://www.torproject.org/) - Free software and onion routed overlay network that helps you defend against traffic analysis.
* [OnionScan](https://onionscan.org/) - Tool for investigating the Dark Web by finding operational security issues introduced by Tor hidden service operators.
* [I2P](https://geti2p.net/) - The Invisible Internet Project.
* [Nipe](https://github.com/GouveaHeitor/nipe) - Script to redirect all traffic from the machine to the Tor network.
* [What Every Browser Knows About You](http://webkay.robinlinus.com/) - Comprehensive detection page to test your own Web browser's configuration for privacy and identity leaks.

### Reverse Engineering Tools

* [Interactive Disassembler (IDA Pro)](https://www.hex-rays.com/products/ida/) - Proprietary multi-processor disassembler and debugger for Windows, GNU/Linux, or macOS; also has a free version, [IDA Free](https://www.hex-rays.com/products/ida/support/download_freeware.shtml).
* [WDK/WinDbg](https://msdn.microsoft.com/en-us/windows/hardware/hh852365.aspx) - Windows Driver Kit and WinDbg.
* [OllyDbg](http://www.ollydbg.de/) - x86 debugger for Windows binaries that emphasizes binary code analysis.
* [Radare2](http://rada.re/r/index.html) - Open source, crossplatform reverse engineering framework.
* [x64dbg](http://x64dbg.com/) - Open source x64/x32 debugger for windows.
* [Immunity Debugger](http://debugger.immunityinc.com/) - Powerful way to write exploits and analyze malware.
* [Evan's Debugger](http://www.codef00.com/projects#debugger) - OllyDbg-like debugger for GNU/Linux.
* [Medusa](https://github.com/wisk/medusa) - Open source, cross-platform interactive disassembler.
* [plasma](https://github.com/joelpx/plasma) - Interactive disassembler for x86/ARM/MIPS. Generates indented pseudo-code with colored syntax code.
* [peda](https://github.com/longld/peda) - Python Exploit Development Assistance for GDB.
* [dnSpy](https://github.com/0xd4d/dnSpy) - Tool to reverse engineer .NET assemblies.
* [binwalk](https://github.com/devttys0/binwalk) - Fast, easy to use tool for analyzing, reverse engineering, and extracting firmware images.
* [PyREBox](https://github.com/Cisco-Talos/pyrebox) - Python scriptable Reverse Engineering sandbox by Cisco-Talos.
* [Voltron](https://github.com/snare/voltron) - Extensible debugger UI toolkit written in Python.
* [Capstone](http://www.capstone-engine.org/) - Lightweight multi-platform, multi-architecture disassembly framework.
* [rVMI](https://github.com/fireeye/rVMI) - Debugger on steroids; inspect userspace processes, kernel drivers, and preboot environments in a single tool.
* [Frida](https://www.frida.re/) - Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers.

### Physical Access Tools

* [LAN Turtle](https://lanturtle.com/) - Covert "USB Ethernet Adapter" that provides remote access, network intelligence gathering, and MITM capabilities when installed in a local network.
* [USB Rubber Ducky](http://usbrubberducky.com/) - Customizable keystroke injection attack platform masquerading as a USB thumbdrive.
* [Poisontap](https://samy.pl/poisontap/) - Siphons cookies, exposes internal (LAN-side) router and installs web backdoor on locked computers.
* [WiFi Pineapple](https://www.wifipineapple.com/) - Wireless auditing and penetration testing platform.
* [Proxmark3](https://proxmark3.com/) - RFID/NFC cloning, replay, and spoofing toolkit often used for analyzing and attacking proximity cards/readers, wireless keys/keyfobs, and more.
* [PCILeech](https://github.com/ufrisk/pcileech) - Uses PCIe hardware devices to read and write from the target system memory via Direct Memory Access (DMA) over PCIe.

### Side-channel Tools

* [ChipWhisperer](http://chipwhisperer.com) - Complete open-source toolchain for side-channel power analysis and glitching attacks.

### CTF Tools

* [ctf-tools](https://github.com/zardus/ctf-tools) - Collection of setup scripts to install various security research tools easily and quickly deployable to new machines.
* [Pwntools](https://github.com/Gallopsled/pwntools) - Rapid exploit development framework built for use in CTFs.
* [RsaCtfTool](https://github.com/sourcekris/RsaCtfTool) - Decrypt data enciphered using weak RSA keys, and recover private keys from public keys using a variety of automated attacks.

### Penetration Testing Report Templates

* [Public Pentesting Reports](https://github.com/juliocesarfort/public-pentesting-reports) - Curated list of public penetration test reports released by several consulting firms and academic security groups.
* [Pentesting Report Template](https://www.testandverification.com/wp-content/uploads/template-penetration-testing-report-v03.pdf) - testandverification.com template.
* [Pentesting Report Template](https://www.hitachi-systems-security.com/wp-content/uploads/Above-Security-Technical-Security-Audit-Demo-Report_En_FINAL.pdf) - hitachi-systems-security.com template.
* [Pentesting Report Template](http://lucideus.com/pdf/stw.pdf) - lucideus.com template.
* [Pentesting Report Template](https://www.crest-approved.org/wp-content/uploads/CREST-Penetration-Testing-Guide.pdf) - crest-approved.org templage.
* [Pentesting Report Template](https://www.pcisecuritystandards.org/documents/Penetration_Testing_Guidance_March_2015.pdf) - pcisecuritystandards.org template.

## Books

### Penetration Testing Books

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
* [Advanced Penetration Testing by Wil Allsopp, 2017](https://www.amazon.com/Advanced-Penetration-Testing-Hacking-Networks/dp/1119367689/)

### Hackers Handbook Series

* [The Database Hacker's Handbook, David Litchfield et al., 2005](http://www.wiley.com/WileyCDA/WileyTitle/productCd-0764578014.html)
* [The Shellcoders Handbook by Chris Anley et al., 2007](http://www.wiley.com/WileyCDA/WileyTitle/productCd-047008023X.html)
* [The Mac Hacker's Handbook by Charlie Miller & Dino Dai Zovi, 2009](http://www.wiley.com/WileyCDA/WileyTitle/productCd-0470395362.html)
* [The Web Application Hackers Handbook by D. Stuttard, M. Pinto, 2011](http://www.wiley.com/WileyCDA/WileyTitle/productCd-1118026470.html)
* [iOS Hackers Handbook by Charlie Miller et al., 2012](http://www.wiley.com/WileyCDA/WileyTitle/productCd-1118204123.html)
* [Android Hackers Handbook by Joshua J. Drake et al., 2014](http://www.wiley.com/WileyCDA/WileyTitle/productCd-111860864X.html)
* [The Browser Hackers Handbook by Wade Alcorn et al., 2014](http://www.wiley.com/WileyCDA/WileyTitle/productCd-1118662091.html)
* [The Mobile Application Hackers Handbook by Dominic Chell et al., 2015](http://www.wiley.com/WileyCDA/WileyTitle/productCd-1118958500.html)
* [Car Hacker's Handbook by Craig Smith, 2016](https://www.nostarch.com/carhacking)

### Defensive Development

* [Holistic Info-Sec for Web Developers (Fascicle 0)](https://leanpub.com/holistic-infosec-for-web-developers)
* [Holistic Info-Sec for Web Developers (Fascicle 1)](https://leanpub.com/holistic-infosec-for-web-developers-fascicle1-vps-network-cloud-webapplications)

### Network Analysis Books

* [Nmap Network Scanning by Gordon Fyodor Lyon, 2009](https://nmap.org/book/)
* [Practical Packet Analysis by Chris Sanders, 2011](https://www.nostarch.com/packet2.htm)
* [Wireshark Network Analysis by by Laura Chappell & Gerald Combs, 2012](https://www.amazon.com/Wireshark-Network-Analysis-Second-Certified/dp/1893939944)
* [Network Forensics: Tracking Hackers through Cyberspace by Sherri Davidoff & Jonathan Ham, 2012](http://www.amazon.com/Network-Forensics-Tracking-Hackers-Cyberspace-ebook/dp/B008CG8CYU/)

### Reverse Engineering Books

* [Reverse Engineering for Beginners by Dennis Yurichev](http://beginners.re/)
* [Hacking the Xbox by Andrew Huang, 2003](https://www.nostarch.com/xbox.htm)
* [The IDA Pro Book by Chris Eagle, 2011](https://www.nostarch.com/idapro2.htm)
* [Practical Reverse Engineering by Bruce Dang et al., 2014](http://www.wiley.com/WileyCDA/WileyTitle/productCd-1118787315.html)
* [Gray Hat Hacking The Ethical Hacker's Handbook by Daniel Regalado et al., 2015](http://www.amazon.com/Hacking-Ethical-Hackers-Handbook-Edition/dp/0071832386)

### Malware Analysis Books

* [Practical Malware Analysis by Michael Sikorski & Andrew Honig, 2012](https://www.nostarch.com/malware)
* [The Art of Memory Forensics by Michael Hale Ligh et al., 2014](http://www.wiley.com/WileyCDA/WileyTitle/productCd-1118825098.html)
* [Malware Analyst's Cookbook and DVD by Michael Hale Ligh et al., 2010](http://www.wiley.com/WileyCDA/WileyTitle/productCd-0470613033.html)

### Windows Books

* [Windows Internals by Mark Russinovich et al., 2012](http://www.amazon.com/Windows-Internals-Part-Developer-Reference/dp/0735648735/)
* [Troubleshooting with the Windows Sysinternals Tools by Mark Russinovich & Aaron Margosis, 2016](https://www.amazon.com/Troubleshooting-Windows-Sysinternals-Tools-2nd/dp/0735684448/)

### Social Engineering Books

* [The Art of Deception by Kevin D. Mitnick & William L. Simon, 2002](http://www.wiley.com/WileyCDA/WileyTitle/productCd-0471237124.html)
* [The Art of Intrusion by Kevin D. Mitnick & William L. Simon, 2005](http://www.wiley.com/WileyCDA/WileyTitle/productCd-0764569597.html)
* [Ghost in the Wires by Kevin D. Mitnick & William L. Simon, 2011](http://www.hachettebookgroup.com/titles/kevin-mitnick/ghost-in-the-wires/9780316134477/)
* [No Tech Hacking by Johnny Long & Jack Wiles, 2008](https://www.elsevier.com/books/no-tech-hacking/mitnick/978-1-59749-215-7)
* [Social Engineering: The Art of Human Hacking by Christopher Hadnagy, 2010](http://www.wiley.com/WileyCDA/WileyTitle/productCd-0470639539.html)
* [Unmasking the Social Engineer: The Human Element of Security by Christopher Hadnagy, 2014](http://www.wiley.com/WileyCDA/WileyTitle/productCd-1118608577.html)
* [Social Engineering in IT Security: Tools, Tactics, and Techniques by Sharon Conheady, 2014](https://www.mhprofessional.com/product.php?isbn=0071818464)

### Lock Picking Books

* [Practical Lock Picking by Deviant Ollam, 2012](https://www.elsevier.com/books/practical-lock-picking/ollam/978-1-59749-989-7)
* [Keys to the Kingdom by Deviant Ollam, 2012](https://www.elsevier.com/books/keys-to-the-kingdom/ollam/978-1-59749-983-5)
* [Lock Picking: Detail Overkill by Solomon](https://www.dropbox.com/s/y39ix9u9qpqffct/Lockpicking%20Detail%20Overkill.pdf?dl=0)
* [Eddie the Wire books](https://www.dropbox.com/sh/k3z4dm4vyyojp3o/AAAIXQuwMmNuCch_StLPUYm-a?dl=0)

### Defcon Suggested Reading

* [Defcon Suggested Reading](https://www.defcon.org/html/links/book-list.html)

## Vulnerability Databases

* [Common Vulnerabilities and Exposures (CVE)](https://cve.mitre.org/) - Dictionary of common names (i.e., CVE Identifiers) for publicly known security vulnerabilities.
* [National Vulnerability Database (NVD)](https://nvd.nist.gov/) - United States government's National Vulnerability Database provides additional meta-data (CPE, CVSS scoring) of the standard CVE List along with a fine-grained search engine.
* [US-CERT Vulnerability Notes Database](https://www.kb.cert.org/vuls/) - Summaries, technical details, remediation information, and lists of vendors affected by software vulnerabilities, aggregated by the United States Computer Emergency Response Team (US-CERT).
* [Full-Disclosure](http://seclists.org/fulldisclosure/) - Public, vendor-neutral forum for detailed discussion of vulnerabilities, often publishes details before many other sources.
* [Bugtraq (BID)](http://www.securityfocus.com/bid/) - Software security bug identification database compiled from submissions to the SecurityFocus mailing list and other sources, operated by Symantec, Inc.
* [Exploit-DB](https://www.exploit-db.com/) - Non-profit project hosting exploits for software vulnerabilities, provided as a public service by Offensive Security.
* [Microsoft Security Bulletins](https://technet.microsoft.com/en-us/security/bulletins#sec_search) - Announcements of security issues discovered in Microsoft software, published by the Microsoft Security Response Center (MSRC).
* [Microsoft Security Advisories](https://technet.microsoft.com/en-us/security/advisories#APUMA) - Archive of security advisories impacting Microsoft software.
* [Mozilla Foundation Security Advisories](https://www.mozilla.org/security/advisories/) - Archive of security advisories impacting Mozilla software, including the Firefox Web Browser.
* [Packet Storm](https://packetstormsecurity.com/files/) - Compendium of exploits, advisories, tools, and other security-related resources aggregated from across the industry.
* [CXSecurity](https://cxsecurity.com/) - Archive of published CVE and Bugtraq software vulnerabilities cross-referenced with a Google dork database for discovering the listed vulnerability.
* [SecuriTeam](http://www.securiteam.com/) - Independent source of software vulnerability information.
* [Vulnerability Lab](https://www.vulnerability-lab.com/) - Open forum for security advisories organized by category of exploit target.
* [Zero Day Initiative](http://zerodayinitiative.com/advisories/published/) - Bug bounty program with publicly accessible archive of published security advisories, operated by TippingPoint.
* [Vulners](https://vulners.com/) - Security database of software vulnerabilities.
* [Inj3ct0r](https://www.0day.today/) ([Onion service](http://mvfjfugdwgc5uwho.onion/)) - Exploit marketplace and vulnerability information aggregator.
* [Open Source Vulnerability Database (OSVDB)](https://osvdb.org/) - Historical archive of security vulnerabilities in computerized equipment, no longer adding to its vulnerability database as of April, 2016.
* [HPI-VDB](https://hpi-vdb.de/) - Aggregator of cross-referenced software vulnerabilities offering free-of-charge API access, provided by the Hasso-Plattner Institute, Potsdam.

## Security Courses

* [Offensive Security Training](https://www.offensive-security.com/information-security-training/) - Training from BackTrack/Kali developers.
* [SANS Security Training](http://www.sans.org/) - Computer Security Training & Certification.
* [Open Security Training](http://opensecuritytraining.info/) - Training material for computer security classes.
* [CTF Field Guide](https://trailofbits.github.io/ctf/) - Everything you need to win your next CTF competition.
* [ARIZONA CYBER WARFARE RANGE](http://azcwr.org/) - 24x7 live fire exercises for beginners through real world operations; capability for upward progression into the real world of cyber warfare.
* [Cybrary](http://cybrary.it) - Free courses in ethical hacking and advanced penetration testing. Advanced penetration testing courses are based on the book 'Penetration Testing for Highly Secured Environments'.
* [Computer Security Student](http://computersecuritystudent.com) - Many free tutorials, great for beginners, $10/mo membership unlocks all content.
* [European Union Agency for Network and Information Security](https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material) - ENISA Cyber Security Training material.

## Information Security Conferences

* [DEF CON](https://www.defcon.org/) - Annual hacker convention in Las Vegas.
* [Black Hat](http://www.blackhat.com/) - Annual security conference in Las Vegas.
* [BSides](http://www.securitybsides.com/) - Framework for organising and holding security conferences.
* [CCC](https://events.ccc.de/congress/) - Annual meeting of the international hacker scene in Germany.
* [DerbyCon](https://www.derbycon.com/) - Annual hacker conference based in Louisville.
* [PhreakNIC](http://phreaknic.info/) - Technology conference held annually in middle Tennessee.
* [ShmooCon](http://shmoocon.org/) - Annual US East coast hacker convention.
* [CarolinaCon](http://www.carolinacon.org/) - Infosec conference, held annually in North Carolina.
* [CHCon](https://2016.chcon.nz/) - Christchurch Hacker Con, Only South Island of New Zealand hacker con.
* [SummerCon](http://www.summercon.org/) - One of the oldest hacker conventions, held during Summer.
* [Hack.lu](https://2016.hack.lu/) - Annual conference held in Luxembourg.
* [Hackfest](https://hackfest.ca) - Largest hacking conference in Canada.
* [HITB](https://conference.hitb.org/) - Deep-knowledge security conference held in Malaysia and The Netherlands.
* [Troopers](https://www.troopers.de) - Annual international IT Security event with workshops held in Heidelberg, Germany.
* [ThotCon](http://thotcon.org/) - Annual US hacker conference held in Chicago.
* [LayerOne](http://www.layerone.org/) - Annual US security conference held every spring in Los Angeles.
* [DeepSec](https://deepsec.net/) - Security Conference in Vienna, Austria.
* [SkyDogCon](http://www.skydogcon.com/) - Technology conference in Nashville.
* [SECUINSIDE](http://secuinside.com) - Security Conference in [Seoul](https://en.wikipedia.org/wiki/Seoul).
* [DefCamp](http://def.camp/) - Largest Security Conference in Eastern Europe, held annually in Bucharest, Romania.
* [AppSecUSA](https://2016.appsecusa.org/) - Annual conference organized by OWASP.
* [BruCON](http://brucon.org) - Annual security conference in Belgium.
* [Infosecurity Europe](http://www.infosecurityeurope.com/) - Europe's number one information security event, held in London, UK.
* [Nullcon](http://nullcon.net/website/) - Annual conference in Delhi and Goa, India.
* [RSA Conference USA](https://www.rsaconference.com/) - Annual security conference in San Francisco, California, USA.
* [Swiss Cyber Storm](https://www.swisscyberstorm.com/) - Annual security conference in Lucerne, Switzerland.
* [Virus Bulletin Conference](https://www.virusbulletin.com/conference/index) - Annual conference going to be held in Denver, USA for 2016.
* [Ekoparty](http://www.ekoparty.org) - Largest Security Conference in Latin America, held annually in Buenos Aires, Argentina.
* [44Con](https://44con.com/) - Annual Security Conference held in London.
* [BalCCon](https://www.balccon.org) - Balkan Computer Congress, annually held in Novi Sad, Serbia.
* [FSec](http://fsec.foi.hr) - FSec - Croatian Information Security Gathering in Varaždin, Croatia.

## Information Security Magazines

* [2600: The Hacker Quarterly](https://www.2600.com/Magazine/DigitalEditions) - American publication about technology and computer "underground."
* [Phrack Magazine](http://www.phrack.org/) - By far the longest running hacker zine.

## Awesome Lists

* [Kali Linux Tools](http://tools.kali.org/tools-listing) - List of tools present in Kali Linux.
* [SecTools](http://sectools.org/) - Top 125 Network Security Tools.
* [Pentest Cheat Sheets](https://github.com/coreb1t/awesome-pentest-cheat-sheets) - Awesome Pentest Cheat Sheets.
* [C/C++ Programming](https://github.com/fffaraz/awesome-cpp) - One of the main language for open source security tools.
* [.NET Programming](https://github.com/quozd/awesome-dotnet) - Software framework for Microsoft Windows platform development.
* [Shell Scripting](https://github.com/alebcay/awesome-shell) - Command line frameworks, toolkits, guides and gizmos.
* [Ruby Programming by @dreikanter](https://github.com/dreikanter/ruby-bookmarks) - The de-facto language for writing exploits.
* [Ruby Programming by @markets](https://github.com/markets/awesome-ruby) - The de-facto language for writing exploits.
* [Ruby Programming by @Sdogruyol](https://github.com/Sdogruyol/awesome-ruby) - The de-facto language for writing exploits.
* [JavaScript Programming](https://github.com/sorrycc/awesome-javascript) - In-browser development and scripting.
* [Node.js Programming by @sindresorhus](https://github.com/sindresorhus/awesome-nodejs) - Curated list of delightful Node.js packages and resources.
* [Python tools for penetration testers](https://github.com/dloss/python-pentest-tools) - Lots of pentesting tools are written in Python.
* [Python Programming by @svaksha](https://github.com/svaksha/pythonidae) - General Python programming.
* [Python Programming by @vinta](https://github.com/vinta/awesome-python) - General Python programming.
* [Android Security](https://github.com/ashishb/android-security-awesome) - Collection of Android security related resources.
* [Awesome Awesomness](https://github.com/bayandin/awesome-awesomeness) - The List of the Lists.
* [AppSec](https://github.com/paragonie/awesome-appsec) - Resources for learning about application security.
* [CTFs](https://github.com/apsdehal/awesome-ctf) - Capture The Flag frameworks, libraries, etc.
* [InfoSec § Hacking challenges](https://github.com/AnarchoTechNYC/meta/wiki/InfoSec#hacking-challenges) - Comprehensive directory of CTFs, wargames, hacking challenge websites, pentest practice lab exercises, and more.
* [Hacking](https://github.com/carpedm20/awesome-hacking) - Tutorials, tools, and resources.
* [Honeypots](https://github.com/paralax/awesome-honeypots) - Honeypots, tools, components, and more.
* [Infosec](https://github.com/onlurking/awesome-infosec) - Information security resources for pentesting, forensics, and more.
* [Forensics](https://github.com/Cugu/awesome-forensics) - Free (mostly open source) forensic analysis tools and resources.
* [Malware Analysis](https://github.com/rshipp/awesome-malware-analysis) - Tools and resources for analysts.
* [PCAP Tools](https://github.com/caesar0301/awesome-pcaptools) - Tools for processing network traffic.
* [Security](https://github.com/sbilly/awesome-security) - Software, libraries, documents, and other resources.
* [Awesome Lockpicking](https://github.com/meitar/awesome-lockpicking) - Awesome guides, tools, and other resources about the security and compromise of locks, safes, and keys.
* [SecLists](https://github.com/danielmiessler/SecLists) - Collection of multiple types of lists used during security assessments.
* [Security Talks](https://github.com/PaulSec/awesome-sec-talks) - Curated list of security conferences.
* [OSINT](https://github.com/jivoi/awesome-osint) - Awesome OSINT list containing great resources.
* [YARA](https://github.com/InQuest/awesome-yara) - YARA rules, tools, and people.

# License

[![CC-BY](https://mirrors.creativecommons.org/presskit/buttons/88x31/svg/by.svg)](https://creativecommons.org/licenses/by/4.0/)

This work is licensed under a [Creative Commons Attribution 4.0 International License](https://creativecommons.org/licenses/by/4.0/).
