# omon
omon - Onion  Monitor, monitors all your Tor Network traffic,     
when ControlPort and CookieAuthentication is set in your torrc:

ControlPort 9051    
CookieAuthentication 1  
CookieAuthFile /home/your_username/.tor/control_auth_cookie  

This is useful, if you try out the latest Tor apps you find on        
the Internet, or which friends gave to you, to see where all Tor     
traffic goes and how much data you send/receive. But please be aware,    
in a production environment these setting are not mandatory nor are   
they needed, as an attacker, knowing that you use these settings     
can install a little trojan on your PC which then monitors your    
complete Tor traffic and which can't be detected by your AV software.

My advise. Be very careful when you find these settings in your torrc  
and always use the offical [tor.exe](https://www.torproject.org/download/tor/) from torproject.org.  

The good thing, on the other side is, these torrc settings are     
disabled in Tor Browser and it refuses to start, when enabled.

If you like omon consider to buy me a coffee.

<a href="https://www.buymeacoffee.com/Ch1ffr3punk" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-yellow.png" alt="Buy Me A Coffee" height="41" width="174"></a>

omon is dedicated to Alice and Bob.
