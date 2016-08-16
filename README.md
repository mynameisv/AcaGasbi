License
-------

DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 

Version 2, December 2004 
                    
Copyright (C) 2004 Sam Hocevar <sam@hocevar.net> 

Everyone is permitted to copy and distribute verbatim or modified 

copies of this license document, and changing it is allowed as long 

as the name is changed. 

DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
           
TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION 

1. You just DO WHAT THE FUCK YOU WANT TO.



AcaGasbi
--------
```
                                      +            o                           
           +              o       x                                      .     
      x             .                                   x    o    +            
   _____      o           ________       +      ___.   .__                     
  /  _  \   ____ _____   /  _____/_____    _____\_ |__ |__|           x        
 /  /_\  \_/ ___\\__  \ /   \  ___\__  \  /  ___/| __ \|  |                    
/    |    \  \___ / __ \\    \_\  \/ __ \_\___ \ | \_\ \  |     +      o       
\____|__  /\___  >____  /\______  (____  /____  >|___  /__|         .          
        \/     \/     \/        \/     \/     \/     \/                        
Autonomous      CA       Generator  And  Signatory of Binary       x              
                      o                                               o        
      .                                    +           o                       
           +            x           o                                          
_ __ ___ ____ _ _ ____________________________ ______ __ _ ____ _____ _
```

`AcaGasbi` has no relation with Gatsby ;-). My joke is zero... next time, i will generate a random name !

`AcaGasbi` auto-generate a CA installed in LocaleMachine\Root, auto-generate a Signing certificate installed in LocalMachine\Root, auto-compile a C# base service, auto-sign this binary, auto-install it as a service and auto-run it. Enjoy \o/.


PoC PoC PoC
----------------
Beware, it's a PoC, working PoC, but still a PoC.


Why not using makecert.exe ?
----------------
Firstly, have you ever seen a normal enduser workstation including Windows SDK ?

Secondly, i could have included the binary like invoke-mimikatz, but it would have involved an explosion in the size of the script.

Finaly, makecert is deprecated ;-)

https://blogs.technet.microsoft.com/askds/2012/08/14/rsa-key-blocking-is-here/

No makecert, just Posh (looks like a publicity slogan or a punchline ^_^)


You dumb, use certreq.exe !
----------------
Well... I wanted a 100% Posh 2.0 tool


Powershell 2.0 ?
----------------
By default, if you wanna have compatility you'll have to use v2.0, as it's the case for PowerShell Empire.


Functions
---------------
As always, my code can be used as a lib, to do atomic (specific) stuff.


To do
---------------
To do:
* In GetCertInformations, handle the case when a Subject fo not begin with CN= ($aAttributes = $aCerts[$iMagic].Subject.split("=");)
* Clean the code, add try{}catch{}
* Modify the code to be usable as a lib
* Leet way: do all the compilion and signature stuff in memory, without touching the disk


Last word ?
-----------

````
         ///\\\  ( Have Fun )
        / ^  ^ \ /
      __\  __  /__
     / _ `----' _ \
     \__\   _   |__\
      (..) _| _ (..)
       |____(___|     Mynameisv_ 2016
_ __ _ (____)____) _ _________________________________ _'
````