/* Values that can be returned by execute_command (). */
#define EXECUTION_FAILURE 1
#define EXECUTION_SUCCESS 0

/* Usage messages by builtins result in a return status of 2. */
#define EX_BADUSAGE	2

#define EX_MISCERROR	2

/* Special exit statuses used by the shell, internally and externally. */
#define EX_RETRYFAIL	124
#define EX_WEXPCOMSUB	125
#define EX_BINARY_FILE	126
#define EX_NOEXEC	126
#define EX_NOINPUT	126
#define EX_NOTFOUND	127

#define EX_SHERRBASE	256	/* all special error values are > this. */

#define EX_BADSYNTAX	257	/* shell syntax error */
#define EX_USAGE	258	/* syntax error in usage */
#define EX_REDIRFAIL	259	/* redirection failed */
#define EX_BADASSIGN	260	/* variable assignment error */
#define EX_EXPFAIL	261	/* word expansion failed */

/* Flag values that control parameter pattern substitution. */
#define MATCH_ANY	0x000
#define MATCH_BEG	0x001
#define MATCH_END	0x002

#define MATCH_TYPEMASK	0x003

#define MATCH_GLOBREP	0x010
#define MATCH_QUOTED	0x020
#define MATCH_STARSUB	0x040

/* Some needed external declarations. */
extern char **shell_environment;
extern WORD_LIST *rest_of_args;

/* Generalized global variables. */
extern int debugging_mode;
extern int executing, login_shell;
extern int interactive, interactive_shell;
extern int startup_state;
extern int subshell_environment;
extern int shell_compatibility_level;

