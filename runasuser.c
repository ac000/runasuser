/*
 * runasuser.c - Run a command as a specified user
 *
 * Copyright (C) 2010 - Andrew Clayton <andrew@digital-domain.net>
 * Released under the GNU General Public License (GPL) version 2
 * See COPYING
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>


int main(int argc, char **argv)
{
	int i;
	struct passwd *pwd;

	if (argc < 2) {
		fprintf(stderr, "Usage: runrails program [args ...]\n");
		exit(1);
	}

	pwd = getpwnam("rails");
		
	/*
  	 * Order is important, if setuid comes first,
	 * then the setgid is unable to perform.
	 */
	setgid(pwd->pw_gid);
	if (setuid(pwd->pw_uid) != 0) {
		/* It's important to bail if the setuid() fails. */
		fprintf(stderr, "Error: Unable to setuid.\n");
		exit(1);
	}

	setenv("HOME", pwd->pw_dir, 1);
	setenv("USER", pwd->pw_name, 1);
	umask(0007);
	chdir(pwd->pw_dir);

	printf("Execing [ ");
	for (i = 1; i < argc; i++)
		printf("%s ", argv[i]);	

	printf("]\n");

	execvp(argv[1], argv + 1);

	exit(0);
}
