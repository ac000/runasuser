/*
 * runasuser.c - Run a command as a specified user
 *
 * Copyright (C) 2010-2011 - Andrew Clayton <andrew@digital-domain.net>
 * Released under the GNU General Public License (GPL) version 2
 * See COPYING
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <grp.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>

static int check_user_auth(char *from_user, char *to_user, FILE *fp);

static int check_user_auth(char *from_user, char *to_user, FILE *fp)
{
	int ret = 0;
	char buf[513];
	char user[13];
	char *user_list;
	char *token;

	user_list = malloc(sizeof(char *) * 101);
	memset(user_list, 0, 101);

	while (fgets(buf, 512, fp) && !ret) {
		sscanf(buf, "%12s\t%100s[^\n]", user, user_list);
		if (strcmp(user, from_user) == 0) {
			for (;;) {
				token = strtok(user_list, ",");
				if (token == NULL)
					break;
				if (strcmp(token, to_user) == 0) {
					ret = 1;
					break;
				}
				user_list = NULL;
			}
		}
	}
	free(user_list);

	return ret;
}

int main(int argc, char **argv)
{
	int i;
	struct passwd *pwd;
	static FILE *fp;
	char *to_chdir;

	if (argc < 3) {
		fprintf(stderr, "Usage: runasuser user program [args ...]\n");
		exit(-1);
	}

	pwd = getpwnam(argv[1]);
	if (!pwd) {
		fprintf(stderr, "Error: No such user %s\n", argv[1]);
		exit(-1);
	}

	if ((fp = fopen("/etc/runasuser.conf", "r"))) {
		;
	} else if ((fp = fopen("/usr/local/etc/runasuser.conf", "r"))) {
		;
	} else {
		fprintf(stderr, "Error: Can't open runasuser.conf\n");
		exit(-1);
	}

	/* Check the user calling runasuser */
	pwd = getpwuid(getuid()); /* Yes, we want the _real_ uid */
	if (!check_user_auth(pwd->pw_name, argv[1], fp)) {
		fprintf(stderr, "Error: You are not authorized to run as %s\n",
								argv[1]);
		exit(-1);
	}
	fclose(fp);

	/* Drop all supplementary groups from the calling user */
	if (setgroups(0, NULL) != 0) {
		fprintf(stderr, "Error: setgroups() failed.\n");
		exit(-1);
	}

	pwd = getpwnam(argv[1]);
	/*
  	 * Order is important, if setuid comes first,
	 * then the setgid is unable to perform.
	 */
	setgid(pwd->pw_gid);
	if (setuid(pwd->pw_uid) != 0) {
		/* It's important to bail if the setuid() fails. */
		fprintf(stderr, "Error: Unable to setuid.\n");
		exit(-1);
	}

	setenv("HOME", pwd->pw_dir, 1);
	setenv("USER", pwd->pw_name, 1);

	to_chdir = getenv("RUNASUSER_CHDIR");
	if (!to_chdir || atoi(to_chdir) != 0)
		chdir(pwd->pw_dir);

	printf("Execing [ ");
	for (i = 2; i < argc; i++)
		printf("%s ", argv[i]);	

	printf("]\n");

	execvp(argv[2], argv + 2);

	exit(0);
}
