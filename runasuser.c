/*
 * runasuser.c - Run a command as a specified user
 *
 * Copyright (C) 2010-2012 - Andrew Clayton <andrew@digital-domain.net>
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
#include <syslog.h>

#define BUF_SIZE	4096	/* read buffer size */
#define FD_MAX		1024	/* max open file descriptors */

#define SETENV_ERR(env) fprintf(stderr, "setenv: %s: can't set environment "\
							"variable\n", env);


static int do_log(char *from_user, char *to_user, char *cwd, char *cmdpath,
								char **args)
{
	int ret = 1;
	char *cmd;
	char *tmp;
	char *cdn = get_current_dir_name();
	char *tty;

	cmd = malloc(strlen(cmdpath) + 1);
	if (!cmd) {
		perror("malloc cmd");
		ret = 0;
		goto out;
	}
	snprintf(cmd, strlen(cmdpath) + 1, "%s", cmdpath);

	/* Skip past runasuser the user and the command */
	args += 3;
	for ( ; *args != NULL; args++) {
		tmp = realloc(cmd, strlen(cmd) + strlen(*args) + 2);
		if (!tmp) {
			perror("realloc tmp");
			ret = 0;
			goto out;
		}
		cmd = tmp;
		strcat(cmd, " ");
		strncat(cmd, *args, strlen(*args));
	}

	openlog("runasuser", LOG_ODELAY, LOG_AUTHPRIV);
	tty = ttyname(0);
	/*
	 * We do tty + 5 to loose the /dev/ or if there is no tty,
	 * e.g, running from cron, we just display (none).
	 */
	syslog(LOG_INFO, "%s : TTY=%s ; EWD=%s ; PWD=%s ; USER=%s ; "
						"COMMAND=%s",
						from_user,
						(tty) ? tty + 5 : "(none)",
						cwd, cdn, to_user, cmd);
	closelog();
	free(cdn);
	free(cmd);

out:
	return ret;
}

static int command_found(char *command, char *cmdpath)
{
	int ret = 0;
	char *path = strdup(getenv("PATH"));
	char *token;
	struct stat sb;
	char fpath[PATH_MAX];
	char *cdn;

	cdn = get_current_dir_name();
	/* Handle ./test_command */
	if (strncmp(command, "./", 2) == 0) {
		snprintf(fpath, sizeof(fpath), "%s/%s", cdn, command + 2);
		if (stat(fpath, &sb) == 0)
			ret = 1;
	/* Handle /tmp/test_command */
	} else if (strncmp(command, "/", 1) == 0) {
		snprintf(fpath, sizeof(fpath), "%s", command);
		if (stat(fpath, &sb) == 0)
			ret = 1;
	/* Handle bin/test_command */
	} else if (strstr(command, "/")) {
		snprintf(fpath, sizeof(fpath), "%s/%s", cdn, command);
		if (stat(fpath, &sb) == 0)
			ret = 1;
	} else {
		/* Look for command in PATH */
		for (;;) {
			token = strtok(path, ":");
			if (token == NULL)
				break;
			snprintf(fpath, sizeof(fpath), "%s/%s", token,
								command);
			if (stat(fpath, &sb) == 0) {
				ret = 1;
				break;
			}
			path = NULL;
		}
	}
	free(path);
	free(cdn);
	strcpy(cmdpath, fpath);

	return ret;
}

static int setup_environment(char *to_user, FILE *fp)
{
	int ret = 1;
	char *string;
	char *token;
	char *subtoken;
	char *saveptr1 = NULL;
	char *saveptr2 = NULL;
	char *env;
	char *value;
	char buf[BUF_SIZE];
	char user[13];

	string = malloc(BUF_SIZE);
	if (!string) {
		perror("malloc string");
		ret = 0;
		goto out;
	}

	while (fgets(buf, BUF_SIZE, fp)) {
		memset(string, 0, BUF_SIZE);
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

				if (setenv(env, value, 1) != 0) {
					SETENV_ERR(env);
					ret = 0;
					goto out;
				}

				string = NULL;
			}
			break;
		}
	}
	free(string);

out:
	return ret;
}

static int check_user_auth(char *from_user, char *to_user, FILE *fp)
{
	int ret = 0;
	char buf[BUF_SIZE];
	char user[13];
	char *user_list;
	char *token;

	user_list = malloc(101);
	if (!user_list) {
		perror("malloc user_list");
		goto out;
	}
	memset(user_list, 0, 101);

	while (fgets(buf, BUF_SIZE, fp) && !ret) {
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

out:
	return ret;
}

int main(int argc, char **argv)
{
	int ret = EXIT_SUCCESS;
	int i;
	struct passwd *pwd;
	static FILE *fp;
	char *to_chdir;
	char *from_user;
	char *cwd = get_current_dir_name();
	char cmdpath[PATH_MAX];
	long maxfd;

	if (argc < 3) {
		fprintf(stderr, "Usage: runasuser user program [args ...]\n");
		ret = EXIT_FAILURE;
		goto out;
	}

	pwd = getpwnam(argv[1]);
	if (!pwd) {
		fprintf(stderr, "Error: No such user %s\n", argv[1]);
		ret = EXIT_FAILURE;
		goto out;
	}

	fp = fopen("/etc/runasuser.conf", "r");
	if (!fp) {
		fp = fopen("/usr/local/etc/runasuser.conf", "r");
		if (!fp) {
			perror("fopen runasuser.conf");
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	/* Check the user calling runasuser */
	pwd = getpwuid(getuid()); /* Yes, we want the _real_ uid */
	from_user = pwd->pw_name;
	/* Allow root to run as any user */
	if (getuid() > 0) {
		if (!check_user_auth(from_user, argv[1], fp)) {
			fprintf(stderr, "Error: You are not authorized to run "
							"as %s\n", argv[1]);
			ret = EXIT_FAILURE;
			goto out;
		}
	}
	fclose(fp);

	/* Drop all supplementary groups of the calling user */
	if (setgroups(0, NULL) != 0) {
		perror("setgroups");
		ret = EXIT_FAILURE;
		goto out;
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
		ret = EXIT_FAILURE;
		goto out;
	}

	/*
	 * Order is important, if setuid comes first,
	 * then the setgid is unable to perform.
	 */
	if (setgid(pwd->pw_gid) != 0) {
		perror("setgid");
		ret = EXIT_FAILURE;
		goto out;
	}
	if (setuid(pwd->pw_uid) != 0) {
		/* It's important to bail if the setuid() fails. */
		perror("setuid");
		ret = EXIT_FAILURE;
		goto out;
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
	if (!to_chdir || atoi(to_chdir) != 0) {
		if (chdir(pwd->pw_dir) != 0) {
			perror("chdir");
			ret = EXIT_FAILURE;
			goto out;
		}
	}

	/* Clear the shell environment before setting up a new one */
	if (clearenv() != 0) {
		perror("clearenv");
		ret = EXIT_FAILURE;
		goto out;
	}
	if (setenv("HOME", pwd->pw_dir, 1) != 0) {
		SETENV_ERR("HOME");
		ret = EXIT_FAILURE;
		goto out;
	}
	if (setenv("USER", pwd->pw_name, 1) != 0) {
		SETENV_ERR("USER");
		ret = EXIT_FAILURE;
		goto out;
	}
	if (setenv("RUNASUSER_USER", from_user, 1) != 0) {
		SETENV_ERR("RUNASUSER_USER");
		ret = EXIT_FAILURE;
		goto out;
	}
	if (setenv("PATH", "/usr/local/bin:/bin:/usr/bin", 1) != 0) {
		SETENV_ERR("PATH");
		ret = EXIT_FAILURE;
		goto out;
	}
	/* Read the rest of the environment from the config file */
	fp = fopen("/etc/runasuser.env.conf", "r");
	if (!fp)
		fp = fopen("/usr/local/etc/runasuser.env.conf", "r");
	if (fp) {
		if (!setup_environment(pwd->pw_name, fp)) {
			ret = EXIT_FAILURE;
			goto out;
		}
		fclose(fp);
	}

	/* check if the command to run exists */
	if (!command_found(argv[2], cmdpath)) {
		fprintf(stderr, "runasuser: %s: command not found\n", argv[2]);
		ret = EXIT_FAILURE;
		goto out;
	}

	printf("Execing [ ");
	for (i = 2; i < argc; i++)
		printf("%s ", argv[i]);

	printf("]\n");

	/* Log info to syslog, same format as sudo */
	ret = do_log(from_user, pwd->pw_name, cwd, cmdpath, argv);
	if (!ret) {
		ret = EXIT_FAILURE;
		goto out;
	}

	/*
	 * Close all open file descriptors above 2 (stderr)
	 * A little heavy handed, but gets the job done.
	 */
	maxfd = sysconf(_SC_OPEN_MAX);
	if (maxfd == -1)
		maxfd = FD_MAX;
	for (i = 3; i < maxfd; i++)
		close(i);

	if (execvp(argv[2], argv + 2) == -1) {
		perror("exec");
		ret = EXIT_FAILURE;
	}

out:
	free(cwd);
	exit(ret);
}
