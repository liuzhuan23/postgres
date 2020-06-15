/*-------------------------------------------------------------------------
 *
 * encryption.c
 *	  Transparent Data Encryption specific code usable by both frontend and
 *	  backend.
 *
 * Portions Copyright (c) 2019, Cybertec Schönig & Schönig GmbH
 *
 * IDENTIFICATION
 *	  src/common/encryption.c
 *
 *-------------------------------------------------------------------------
 */
#ifndef FRONTEND
#include "postgres.h"
#else
#include "postgres_fe.h"
#endif

#include "common/encryption.h"
#include "common/logging.h"

#ifdef USE_ENCRYPTION
#include <openssl/evp.h>

unsigned char encryption_key[ENCRYPTION_KEY_LENGTH];
#endif	/* USE_ENCRYPTION */

char	   *encryption_key_command = NULL;

/*
 * Run the command that is supposed to generate encryption key and store it
 * where encryption_key points to. If valid string is passed for data_dir,
 * it's used to replace '%D' pattern in the command.
 */
void
run_encryption_key_command(char *data_dir)
{
	FILE	   *fp;
	char	*cmd, *sp, *dp, *endp;

	Assert(encryption_key_command != NULL &&
		   strlen(encryption_key_command) > 0);

	cmd = palloc(strlen(encryption_key_command) + 1);

	/*
	 * Replace %D pattern in the command with the actual data directory path.
	 */
	dp = cmd;
	endp = cmd + strlen(encryption_key_command);
	*endp = '\0';
	for (sp = encryption_key_command; *sp; sp++)
	{
		if (*sp == '%')
		{
			if (sp[1] == 'D')
			{
				if (data_dir == NULL)
				{
#ifdef FRONTEND
					pg_log_fatal("data directory is not known, %%D pattern cannot be replaced");
					exit(EXIT_FAILURE);
#else
					ereport(FATAL,
							(errmsg("data directory is not known, %%D pattern cannot be replaced")));
#endif	/* FRONTEND */
				}

				sp++;
				strlcpy(dp, data_dir, endp - dp);
				make_native_path(dp);
				dp += strlen(dp);
			}
			else if (dp < endp)
				*dp++ = *sp;
			else
				break;
		}
		else
		{
			if (dp < endp)
				*dp++ = *sp;
			else
				break;
		}
	}
	*dp = '\0';

	/* Do not print the command itself, in case it's just "echo <the key>" */
#ifdef FRONTEND
	pg_log_debug("executing encryption key command");
#else
	ereport(DEBUG1,
			(errmsg("executing encryption key command")));
#endif	/* FRONTEND */

	fp = popen(cmd, "r");
	if (fp == NULL)
	{
#ifdef FRONTEND
		pg_log_fatal("could not execute \"%s\"", cmd);
		exit(EXIT_FAILURE);
#else
		ereport(FATAL,
				(errmsg("could not execute \"%s\"", cmd)));
#endif	/* FRONTEND */
	}

	/* Read the key. */
	read_encryption_key_f(fp, cmd);

	if (pclose(fp) != 0)
	{
#ifdef FRONTEND
		pg_log_fatal("could not close pipe to \"%s\"", cmd);
		exit(EXIT_FAILURE);
#else
		ereport(FATAL,
				(errmsg("could not close pipe to \"%s\"", cmd)));
#endif	/* FRONTEND */
	}
	pfree(cmd);
}

/*
 * Read the encryption key from a file stream.
 */
void
read_encryption_key_f(FILE *f, char *command)
{
	char	   buf[ENCRYPTION_KEY_CHARS];
	int		read_len, c;

	read_len = 0;
	while ((c = fgetc(f)) != EOF && c != '\n')
	{
		if (read_len >= ENCRYPTION_KEY_CHARS)
		{
#ifdef FRONTEND
			pg_log_fatal("encryption key is too long");
			exit(EXIT_FAILURE);
#else
			ereport(FATAL,
					(errmsg("encryption key is too long")));
#endif	/* FRONTEND */
		}

		buf[read_len++] = c;
	}

	if (c == EOF && read_len == 0)
	{
		char	src[MAXPGPATH];

		if (command)
			snprintf(src, MAXPGPATH, "command \"%s\"", command);
		else
			snprintf(src, MAXPGPATH, "stdin");

#ifdef FRONTEND
		pg_log_fatal("could not read encryption key from %s: %m", src);
		exit(EXIT_FAILURE);
#else
		ereport(FATAL,
				(errmsg("could not read encryption key from %s: %m",
						src)));
#endif	/* FRONTEND */
	}

	if (read_len < ENCRYPTION_KEY_CHARS)
	{
#ifdef FRONTEND
		pg_log_fatal("encryption key is too short");
		exit(EXIT_FAILURE);
#else
		ereport(FATAL,
				(errmsg("encryption key is too short")));
#endif	/* FRONTEND */
	}

	/* Turn the hexadecimal representation into an array of bytes. */
	encryption_key_from_string(buf);
}

/*
 * Use the input hexadecimal string to initialize the encryption_key variable.
 */
void
encryption_key_from_string(char key_str[ENCRYPTION_KEY_CHARS])
{
	int	encr_key_int[ENCRYPTION_KEY_LENGTH];
	int	i;

	for (i = 0; i < ENCRYPTION_KEY_LENGTH; i++)
	{
		/*
		 * The code would be simpler with %2hhx conversion, but it does not
		 * seem to be well portable. At least mingw build on Windows
		 * complains about it.
		 */
		if (sscanf(key_str + 2 * i, "%2x", encr_key_int + i) == 0)
		{
#ifdef FRONTEND
			pg_log_fatal("invalid character in encryption key at position %d",
						 2 * i);
			exit(EXIT_FAILURE);
#else
			ereport(FATAL,
					(errmsg("invalid character in encryption key at position %d",
							2 * i)));
#endif	/* FRONTEND */
		}
	}
	for (i = 0; i < ENCRYPTION_KEY_LENGTH; i++)
		encryption_key[i] = (char) encr_key_int[i];
}
