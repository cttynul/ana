# ana
```
          .---.   ___ .-.     .---.
         / .-, \ (   )   \   / .-, \
        (__) ; |  |  .-. .  (__) ; |
          .'`  |  | |  | |    .'`  |
         / .'| |  | |  | |   / .'| |
        | /  | |  | |  | |  | /  | |
        ; |  ; |  | |  | |  ; |  ; |
        ' `-'  |  | |  | |  ' `-'  |
        `.__.'_. (___)(___) `.__.'_.

```

🐞 SecOps tool to map CVE with KB & CVE with RHSA

## Usage
1. Install needed **libraries**
```
$ pip install -r requirements.txt
```
2. If wanna run automagically, put input **XLSX** file in **ana root folder**, If need an input template you can check `./Input-CVE.xlsx`
3. Run **ana**
```
$ python ana.py [XLS_Input.xls]
      If input file not provied will run wizard waiting for user input
```
4. **Trust the process**
5. Get **output XLSX** file generated in `./output/`

## Example
```
$ python ./main.py Input-CVE.xlsx

          .---.   ___ .-.     .---.
         / .-, \ (   )   \   / .-, \
        (__) ; |  |  .-. .  (__) ; |
          .'`  |  | |  | |    .'`  |
         / .'| |  | |  | |   / .'| |
        | /  | |  | |  | |  | /  | |
        ; |  ; |  | |  | |  ; |  ; |
        ' `-'  |  | |  | |  ' `-'  |
        `.__.'_. (___)(___) `.__.'_.

                            -cttynul

   Server IP          Hostname               OS             CVE  CVE Score
0   10.1.1.2     server.my.lan     Windows 2016  CVE-2021-43217        7.5
1   10.1.2.3    windows.my.lan     Windows 2019  CVE-2021-42284        7.1
2   10.1.3.4  webserver.my.lan  Windows 2012 R2  CVE-2021-42284        7.1
3   10.2.0.3       mock.my.lan        Red Hat 7  CVE-2019-14850        2.6
4  10.2.0.10      rhel8.my.lan        Red Hat 8   CVE-2020-3757        9.3
               CVE                                              Title      Patch                               OS
0   CVE-2021-43217  Windows Encrypting File System (EFS) Remote Co...  KB5008218              Windows Server 2019
1   CVE-2021-43217  Windows Encrypting File System (EFS) Remote Co...  KB5008212  Windows Server, version 20H2...
2   CVE-2021-43217  Windows Encrypting File System (EFS) Remote Co...  KB5008223              Windows Server 2022
3   CVE-2021-43217  Windows Encrypting File System (EFS) Remote Co...  KB5008215              Windows Server 2022
4   CVE-2021-43217  Windows Encrypting File System (EFS) Remote Co...  KB5008207              Windows Server 2016
5   CVE-2021-43217  Windows Encrypting File System (EFS) Remote Co...  KB5008244  Windows Server 2008 R2 for x...
6   CVE-2021-43217  Windows Encrypting File System (EFS) Remote Co...  KB5008282  Windows Server 2008 R2 for x...
7   CVE-2021-43217  Windows Encrypting File System (EFS) Remote Co...  KB5008263           Windows Server 2012 R2
8   CVE-2021-43217  Windows Encrypting File System (EFS) Remote Co...  KB5008285           Windows Server 2012 R2
9   CVE-2021-43217  Windows Encrypting File System (EFS) Remote Co...  KB5008274  Windows Server 2008 for 32-b...
10  CVE-2021-43217  Windows Encrypting File System (EFS) Remote Co...  KB5008271  Windows Server 2008 for 32-b...
11  CVE-2021-43217  Windows Encrypting File System (EFS) Remote Co...  KB5008277              Windows Server 2012
12  CVE-2021-43217  Windows Encrypting File System (EFS) Remote Co...  KB5008255              Windows Server 2012
              CVE                                            Title      Patch                                  OS
0  CVE-2021-42284  Windows Hyper-V Denial of Service Vulnerability  KB5007206                 Windows Server 2019
1  CVE-2021-42284  Windows Hyper-V Denial of Service Vulnerability  KB5007186  Windows Server, version 20H2 (S...
2  CVE-2021-42284  Windows Hyper-V Denial of Service Vulnerability  KB5007205                 Windows Server 2022
3  CVE-2021-42284  Windows Hyper-V Denial of Service Vulnerability  KB5007215                 Windows Server 2022
4  CVE-2021-42284  Windows Hyper-V Denial of Service Vulnerability  KB5007192                 Windows Server 2016
5  CVE-2021-42284  Windows Hyper-V Denial of Service Vulnerability  KB5007247              Windows Server 2012 R2
6  CVE-2021-42284  Windows Hyper-V Denial of Service Vulnerability  KB5007255              Windows Server 2012 R2
Report for CVE-2021-42284 may already been created
              CVE                                              Title           Patch                          OS
0  CVE-2019-14850  nbdkit: denial of service due to premature ope...  RHSA-2020:1167  Red Hat Enterprise Linux 7
             CVE                                              Title           Patch                           OS
0  CVE-2020-3757  flash-plugin: Arbitrary Code Execution vulnera...  RHSA-2020:0513  Red Hat Enterprise Linux...
```

## License
```
                      Learning Only License License (LOL)

                         Copyright (c) 2022, cttynul
                             All rights reserved.

 *  The intended purpose of this code is educational only, and that purpose
    must be considered in any use or redistribution of the code or any
    modified version of the code. Any permissible change in License
    Agreement to any redistribution of this code, derivative or otherwise,
    must be done in good faith considering the original intent.

 *  You are not permitted to use this code or any modification of the code
    in any situation where original authorship is expected, or authorship
    is not able to be made clear in the use of the code. Use of this code
    directly for a homework assignment is explicitly prohibited.

 *  The Learning Only License is subordinate to any other accompanying License
    Agreement, and as such any prohibition or permission of use by accompanying
    License Agreements supersedes any permission or prohibition, respectively,
    provided by the Learning Only License.

 *  You may use this code freely, as is or modified, for any purpose not
    explicitly prohibited by this or any accompanying License Agreements, 
    including redistributing the original code and/or any modified version,
    provided such use is consistent with any other accompanying License 
    Agreements and you do the following:

    1.  Read through the code completely, including all of its comments.
    2.  Attempt to understand how it works.
    3.  Learn something from it.
    4.  Do not simply copy any portion of the code verbatim into another
        application; at the very least, add comments explaining what you are
        using, why you are using it, and where you obtained it.
    5.  Hold only yourself responsible, and not the original author or the 
        author of any modifications, for any bugs in your application that are
        the result of your failure to understand the code.
    6.  Do not hold the original author or author of any modifications
        responsible for bugs in your application that are the results of the
        author's mistakes.
    7.  Attempt to contact the responsible author and report any bugs found in
        the original code or any modifications, explaining what is wrong with
        the code and why it is a bug, so that the responsible author may learn
        from your experiences.
    8.  Keep the author(s)'s contact info, if provided or available, within the
        original or modified code so you can remember where it came from and to
        whom any bugs should be reported. If contact info is not available,
        keep a record of where the original code was obtained within the
        original or modified code.
    9.  Redistribute the original or modified code only if you have given due
        dilligence to understand it fully and can honestly attempt to answer 
        any questions about the code the person(s) to whom you give it may have.
    10. Redistribute a modified version of the code only after clearly marking
        the modifications you have made and adding your contact info in case
        you have introduced a bug into it and the recipient needs to contact you
        to report it.
    11. Do not get a bad attitude with anybody reporting bugs in your original
        or modified code.
    12. Attempt to fix any bugs for which you are responsible, seeking help to
        do so if necessary.
    13. Include a copy of this license with any source you distribute that
        contains the original or modified code. A copy of this license does not
        have to be included with any binaries if they are not distributed with
        the source code of that binary.
    14. If you make a profit from your application that contains the original
        or modified code, attempt to contact the author(s) and thank them for
        their help.
```