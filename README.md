# Recon-ng

Recon-ng is a full-featured Web Reconnaissance framework written in Python. Complete with independent modules, database interaction, built in convenience functions, interactive help, and command completion, Recon-ng provides a powerful environment in which open source web-based reconnaissance can be conducted quickly and thoroughly.

Recon-ng has a look and feel similar to the Metasploit Framework, reducing the learning curve for leveraging the framework. However, it is quite different. Recon-ng is not intended to compete with existing frameworks, as it is designed exclusively for web-based open source reconnaissance. If you want to exploit, use the Metasploit Framework. If you want to social engineer, use the Social-Engineer Toolkit. If you want to conduct reconnaissance, use Recon-ng! See the [Usage Guide](https://bitbucket.org/LaNMaSteR53/recon-ng/wiki/Usage%20Guide) for more information.

Recon-ng is a completely modular framework and makes it easy for even the newest of Python developers to contribute. Each module is a subclass of the "module" class. The "module" class is a customized "cmd" interpreter equipped with built-in functionality that provides simple interfaces to common tasks such as standardizing output, interacting with the database, making web requests, and managing API keys. Therefore, all the hard work has been done. Building modules is simple and takes little more than a few minutes. See the [Development Guide](https://bitbucket.org/LaNMaSteR53/recon-ng/wiki/Development%20Guide) for more information.

## Usage

Forks from [Recon-ng](https://bitbucket.org/LaNMaSteR53/recon-ng/). Please type '**help \<command\>**' for more details.

```
┌─[lab@core]─[/opt/recon-ng]
└──╼  python2 recon-ng --no-check
 _____ 
< IGF >
 ----- 
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||--WWW |
                ||     ||


[IGF v4.7.1, Open-Security (@Github)]

[77] Recon modules
[7]  Reporting modules
[3]  Discovery modules
[2]  Import modules
[2]  Exploitation modules

[IGF][default] > help

Commands (type [help|?] <topic>): 
==================================
add             Adds records to the database
back            Exits the current context
delete          Deletes records from the database
exit            Exits the framework
help            Displays this menu
keys            Manages framework API keys
load            Loads specified module
pdb             Starts a Python Debugger session
query           Queries the database
record          Records commands to a resource file
reload          Reloads all modules
resource        Executes commands from a resource file
search          Searches available modules
set             Sets module options
shell           Executes shell commands
show            Shows various framework items
snapshots       Manages workspace snapshots
spool           Spools output to a file
unset           Unsets module options
use             Loads specified module
workspaces      Manages workspaces

```

## Donations

Recon-ng is free software. However, large amounts of time and effort go into its continued development. If you are interested in financialy supporting the development of Recon-ng, please send your donation to tjt1980[at]gmail.com via PayPal. Thank you.

