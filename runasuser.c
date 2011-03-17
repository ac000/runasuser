/*
 * runasuser.c - Run a command as a specified user
 *
 * Copyright (C) 2010-2011 - Andrew Clayton <andrew@digital-domain.net>
 * Released under the GNU General Public License (GPL) version 2
 * See COPYING
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

static int command_found(char *command);
static void setup_environment(char *to_user, FILE *fp);
static int check_user_auth(char *from_user, char *to_user, FILE *fp);

static int command_found(char *command)
{
	int ret = 0;
	char *path = strdup(getenv("PATH"));
	char *token;
	struct stat sb;
	char fpath[PATH_MAX + 1];

	/* Handle ./test_command */
	if (strncmp(command, "./", 2) == 0) {
		strncpy(fpath, get_current_dir_name(), PATH_MAX);
		strncat(fpath, "/", PATH_MAX - strlen(fpath));
		strncat(fpath, command + 2, PATH_MAX - strlen(fpath));
		if (stat(fpath, &sb) == 0)
			ret = 1;
	/* Handle /tmp/test_command */
	} else if (strncmp(command, "/", 1) == 0) {
		if (stat(command, &sb) == 0)
			ret = 1;
	/* Handle bin/test_command */
	} else if (strstr(command, "/")) {
		strncpy(fpath, get_current_dir_name(), PATH_MAX);
		strncat(fpath, "/", PATH_MAX - strlen(fpath));
		strncat(fpath, command, PATH_MAX - strlen(fpath));
		if (stat(fpath, &sb) == 0)
			ret = 1;
	} else {
		/* Look for command in PATH */
		for (;;) {
			token = strtok(path, ":");
			if (token == NULL)
				break;
			strncpy(fpath, token, PATH_MAX);
			strncat(fpath, "/", PATH_MAX - strlen(fpath));
			strncat(fpath, command, PATH_MAX - strlen(fpath));
			if (stat(fpath, &sb) == 0) {
				ret = 1;
				break;
			}
			path = NULL;
		}
	}
	free(path);

	return ret;
}

static void setup_environment(char *to_user, FILE *fp)
{
	char *string;
	char *token;
	char *subtoken;
	char *saveptr1 = NULL;
	char *saveptr2 = NULL;
	char *env;
	char *value;
	char buf[4096];
	char user[13];

	string = malloc(4096);
	if (!string) {
		perror("malloc (string)");
		exit(-1);
	}

	while (fgets(buf, 4096, fp)) {
		memset(string, 0, 4096);
		sscanf(buf, "%12s\t%4095s[^\n]", user, string);
		if (strcmp(user, to_user) == 0) {
			for (;;) {
				token = strtok_r(string, ",", &saveptr1);
				if (token == NULL)
					break;

				/*
				 * Split the environment string into its
				 * name and value parts, e.g
				 *
				 * TERM=linux into TERM & linux for passing
				 * to setenv()
				 */
				subtoken = strtok_r(token, "=", &saveptr2);
				env = subtoken;
				token = NULL;
				subtoken = strtok_r(token, "=", &saveptr2);
				value = subtoken;

				setenv(env, value, 1);

				string = NULL;
			}
			break;
		}
	}
	free(string);
}

static int check_user_auth(char *from_user, char *to_user, FILE *fp)
{
	int ret = 0;
	char buf[4096];
	char user[13];
	char *user_list;
	char *token;

	user_list = malloc(101);
	if (!user_list) {
		perror("malloc (user_list)");
		exit(-1);
	}
	memset(user_list, 0, 101);

	while (fgets(buf, 4096, fp) && !ret) {
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
	char *from_user;
	long maxfd;

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
		perror("fopen (runasuser.conf)");
		exit(-1);
	}

	/* Check the user calling runasuser */
	pwd = getpwuid(getuid()); /* Yes, we want the _real_ uid */
	from_user = pwd->pw_name;
	/* Allow root to run as any user */
	if (getuid() > 0) {
		if (!check_user_auth(from_user, argv[1], fp)) {
			fprintf(stderr, "Error: You are not authorized to run "
							"as %s\n", argv[1]);
			exit(-1);
		}
	}
	fclose(fp);

	/* Drop all supplementary groups of the calling user */
	if (setgroups(0, NULL) != 0) {
		perror("setgroups");
		exit(-1);
	}

	pwd = getpwnam(argv[1]);
	/*
	 * Set the supplementary groups for the new user
	 *
	 * This needs to come before setuid() as this needs the
	 * CAP_SETGID capability
	 */
	if (initgroups(pwd->pw_name, pwd->pw_gid) != 0) {
		perror("initgroups");
		exit(-1);
	}

	/*
  	 * Order is important, if setuid comes first,
	 * then the setgid is unable to perform.
	 */
	if (setgid(pwd->pw_gid) != 0) {
		perror("setgid");
		exit(-1);
	}
	if (setuid(pwd->pw_uid) != 0) {
		/* It's important to bail if the setuid() fails. */
		perror("setuid");
		exit(-1);
	}

	/*
	 * Check whether to chdir() into the users home directory
	 *
	 * Needs to come before clearenv()
	 *
	 * YES, if RUNASUSER_CHDIR = 1 (default)
	 * NO, if RUNASUSER_CHDIR = 0
	 */
	to_chdir = getenv("RUNASUSER_CHDIR");
	if (!to_chdir || atoi(to_chdir) != 0)
		chdir(pwd->pw_dir);

	/* Clear the shell environment before setting up a new one */
	if (clearenv() != 0) {
		perror("clearenv");
		exit(-1);
	}
	setenv("HOME", pwd->pw_dir, 1);
	setenv("USER", pwd->pw_name, 1);
	setenv("RUNASUSER_USER", from_user, 1);
	setenv("PATH", "/usr/local/bin:/bin:/usr/bin", 1);
	/* Read the rest of the environment from the config file */
	if ((fp = fopen("/etc/runasuser.env.conf", "r")))
		;
	else ((fp = fopen("/usr/local/etc/runasuser.env.conf", "r")))
		;
	if (fp) {
		setup_environment(pwd->pw_name, fp);
		fclose(fp);
	}

	/* check if the command to run exists */
	if (!command_found(argv[2])) {
		fprintf(stderr, "runasuser: %s: command not found\n", argv[2]);
		exit(-1);
	}

	printf("Execing [ ");
	for (i = 2; i < argc; i++)
		printf("%s ", argv[i]);	

	printf("]\n");

	/*
	 * Close all open file descriptors above 2 (stderr)
	 * A little heavy handed, but gets the job done.
	 */
	maxfd = sysconf(_SC_OPEN_MAX);
	for (i = 3; i < maxfd; i++)
		close(i);

	execvp(argv[2], argv + 2);

	exit(0);
}
