
/*
 * @copyright
 *
 *  Copyright 2018 Neo Natura
 *
 *  This file is part of the Share Library.
 *  (https://github.com/neonatura/share)
 *        
 *  The Share Library is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version. 
 *
 *  The Share Library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with The Share Library.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  @endcopyright
 */  

#include "shcon.h"

#ifdef HAVE_LIBCURSES
#include <math.h>
#include <locale.h>
#include "cdk.h"

#define RUN_NONE 0
#define RUN_IDLE 10

static int run_state;

#define MAXHISTORY	5000

#ifdef HAVE_XCURSES
char *XCursesProgramName = "coin-console";
#endif


/* This structure is used for keeping command history. */
struct history_st
{
   int count;
   int current;
   char *command[MAXHISTORY];
};



/* Define some local prototypes. */
void help (CDKENTRY *entry);
static BINDFN_PROTO (historyUpCB);
static BINDFN_PROTO (historyDownCB);
static BINDFN_PROTO (viewHistoryCB);
static BINDFN_PROTO (listHistoryCB);
static BINDFN_PROTO (jumpWindowCB);
static BINDFN_PROTO (helpCB);
static BINDFN_PROTO (activateMenuCB);
static BINDFN_PROTO (mineWindowInitCB);

static CDKSCREEN *cdkscreen;
static CDKSWINDOW *commandOutput;
static CDKENTRY *commandEntry;
static CDKMENU *menu;
static CDKENTRY *form;
static CDKLABEL *infoBox    = 0;
static CDKSWINDOW *mineWindow;
static chtype *convert              = 0;
static const char *prompt           = "</B/24> > ";
static int promptLen                = 0;
static int commandFieldWidth        = 0;
static struct history_st history;

static double account_balance;
static char **account_table;
static int connected;
static time_t _net_t;

#define MENU_FILE 0
#define MENU_WALLET 1
#define MENU_SYSTEM 2
#define MENU_ADMIN 3
#define MENU_HELP 4 
#define MAX_MENU 5

#define FIELD_NULL 0
#define FIELD_NUMBER 1
#define FIELD_REAL 2
#define FIELD_STRING 3
#define FIELD_ACCOUNT 4
#define FIELD_ADDRESS 5
#define FIELD_AMOUNT 6
#define FIELD_PATH 7

#define MAX_MENU_LABELS 32

struct menu_t;
typedef void (*menu_f)(const struct menu_t *);

typedef struct menu_t
{
	menu_f func;
	const char *title;
	const char *command;
	const char *labels[MAX_MENU_LABELS];
	const int types[MAX_MENU_LABELS];
} menu_t;

void menu_command_cb(const menu_t *item);
extern uint64_t SHARE_COUNT;
extern uint64_t SHARE_ATTEMPT;
extern uint64_t SHARE_FOUND;
extern double SHARE_TOTAL;
extern double SHARE_MAX;



static const menu_t _file_menu_table[] = 
{
	{ 
		/* Save */
		menu_command_cb,
		"Save", 
		"save"
	},
	{ 
		/* Save */
		menu_command_cb,
		"Exit", 
		"quit"
	},
	{ NULL }
};

static const menu_t _wallet_menu_table[] = 
{
	{ 
		/* Balance */
		menu_command_cb,
		"Balances", 
		"wallet.list"
	},
	{ 
		/* Miner */
		menu_command_cb,
		"CPU Miner", 
		"mine"
	},
	{ 
		/* Save */
		menu_command_cb,
		"Send Coins",
		"wallet.send",
		{ "Account", "Address", "Value", NULL },
		{ FIELD_ACCOUNT, FIELD_ADDRESS, FIELD_AMOUNT } 
	},
	{ 
		/* Save */
		menu_command_cb,
		"Receive Address",
		"wallet.listaddr",
		{ "Account", NULL },
		{ FIELD_ACCOUNT }
	},
	{ NULL }
};

static const menu_t _server_menu_table[] = 
{
	{ 
		/* Block Info */
		menu_command_cb,
		"Blocks",
		"block.info"
	},
	{ 
		/* System Info */
		menu_command_cb,
		"Miners",
		"stratum.list"
	},
	{ 
		/* Node Peers */
		menu_command_cb,
		"Peers",
		"peer.info"
	},
	{ 
		/* System Info */
		menu_command_cb,
		"System",
		"sys.info"
	},
	{ NULL }
};

static const menu_t _admin_menu_table[] = 
{
	{ 
		/* Add Node */
		menu_command_cb,
		"Add Peer",
		"peer.add",
		{ "Hostname", NULL },
		{ FIELD_STRING }
	},
	{ 
		/* Export Wallet */
		menu_command_cb,
		"Configuration",
		"sys.config"
	},
	{ 
		/* Export Wallet */
		menu_command_cb,
		"Export Wallet",
		"wallet.export",
		{ "Filename", NULL },
		{ FIELD_PATH }
	},
	{ 
		/* Shutdown */
		menu_command_cb,
		"Stop Service",
		"sys.shutdown"
	},
	{ NULL }
};

static const menu_t _help_menu_table[] = 
{
	{ 
		/* List Commands */
		menu_command_cb,
		"Command List",
		"help"
	},
	{ 
		/* Shell Commands */
		menu_command_cb,
		"Shell Commands",
		"sh"
	},
	{ 
		/* Window Operations */
		menu_command_cb,
		"Window Actions",
		"winhelp"
	},
	{ NULL }
};

static const menu_t *_menu_table[MAX_MENU] = {
	(menu_t *)_file_menu_table,
	(menu_t *)_wallet_menu_table,
	(menu_t *)_server_menu_table,
	(menu_t *)_admin_menu_table,
	(menu_t *)_help_menu_table
};

static const char *_menu_labels[MAX_MENU] = {
	"File",
	"Wallet",
	"Report",
	"Admin",
	"Help"
};

static char *uc(char *word)
{
   char *upper = 0;
   int length = 0;
   int x;

   /* Make sure the word is not null. */
   if (word == 0)
   {
      return 0;
   }
   length = (int)strlen (word);

   /* Get the memory for the new word. */
   upper = (char *)malloc (sizeof (char) * (size_t) (length + 2));
   if (upper == 0)
   {
      return (word);
   }

   /* Start converting the case. */
   for (x = 0; x < length; x++)
   {
      int ch = (unsigned char)(word[x]);
      if (isalpha (ch))
      {
	 upper[x] = (char)toupper (ch);
      }
      else
      {
	 upper[x] = word[x];
      }
   }
   upper[length] = '\0';
   return upper;
}

static char **split_str(char *text)
{

}

void shcon_gui_println(const char *text)
{
	addCDKSwindow(commandOutput, text, BOTTOM);
}

void shcon_gui_print(const char *text)
{
	int eof;
	int of;

	eof = 0;
	for (of = 0; eof != -1; of += eof + 1) {
		eof = stridx(text + of, '\n');

		if (eof == -1) {
			shcon_gui_println(text + of);
		} else if (eof == 0) {
			shcon_gui_println("");
		} else {
			char *str = strdup(text + of);
			str[eof] = '\000';
			shcon_gui_println(str);
			free(str);
		}
	} 

}

#if 0
static int menuCB(EObjectType cdktype GCC_UNUSED, void *object, void *clientData, chtype input GCC_UNUSED)
{
	/* *INDENT-EQLS* */
	CDKMENU *menu        = (CDKMENU *)object;
	CDKLABEL *infoBox    = (CDKLABEL *)clientData;
	char *mesg[10];
	char temp[256];

	/* Recreate the label message. */
	sprintf (temp, "Title: %.*s",
			(int)(sizeof (temp) - 20),
			menulist[menu->currentTitle][0]);
	mesg[0] = strdup (temp);
	sprintf (temp, "Sub-Title: %.*s",
			(int)(sizeof (temp) - 20),
			menulist[menu->currentTitle][menu->currentSubtitle + 1]);
	mesg[1] = strdup (temp);
	mesg[2] = strdup ("");
#if 0
	sprintf (temp, "<C>%.*s",
			(int)(sizeof (temp) - 20),
			menuInfo[menu->currentTitle][menu->currentSubtitle + 1]);
	mesg[3] = strdup (temp);
#endif

	/* Set the message of the label. */
	setCDKLabel (infoBox, (CDK_CSTRING2) mesg, 3, TRUE);
	drawCDKLabel (infoBox, TRUE);

	freeCharList (mesg, 3);
	return 0;
}
#endif

void shcon_gui_netstate(shjson_t *resp)
{
	shjson_t *obj;
	shjson_t *node;
	char buf[128];
	double bal;
	int tot;
	int idx;

	connected = (resp != NULL);

	if (resp) {
		obj = shjson_obj_get(resp, "result");

		tot = 0;
		for (node = obj->child; node; node = node->next)
			tot++;

		account_table = (char **)calloc(tot+1, sizeof(char *));

		idx = 0;
		bal = 0;
		for (node = obj->child; node; node = node->next) {
			account_table[idx++] = strdup(node->string);
			bal += node->valuedouble;
		}
		account_balance = bal;
	}

	{
		char *mesg[4];
		char buf[64];

		if (connected) {
			sprintf(buf, " </B/24><#DI><!B!24> </B/40>$%u", 
				(unsigned int)round(account_balance));
		} else {
			sprintf(buf, " </B/16><#DI><!B!16> </B/40>$%u", 
				(unsigned int)round(account_balance));
		}
		mesg[0] = buf;

		setCDKLabel (infoBox, (CDK_CSTRING2) mesg, 1, TRUE);
		drawCDKLabel (infoBox, TRUE);
	}

}

static int shcon_gui_command_init(void)
{
	char temp[600];
	char title[256];
	int junk;

	/* Set up the history. */
	history.current = 0;
	history.count = 0;

	/* Create the scrolling window. */
	char *upper = uc((char *)opt_str(OPT_IFACE));
	sprintf(title, "<C></B/5>%s Coin Console", upper);
	free(upper);
	commandOutput = newCDKSwindow (cdkscreen, CENTER, 1, -6, -2,
			title, 1000, TRUE, FALSE);

	/* Convert the prompt to a chtype and determine its length. */
	convert = char2Chtype (prompt, &promptLen, &junk);
	commandFieldWidth = COLS - promptLen - 14;
	freeChtype (convert);

	/* Create the entry field. */
	commandEntry = newCDKEntry (cdkscreen, LEFT, BOTTOM,
			0, prompt,
			A_BOLD | COLOR_PAIR (8),
			COLOR_PAIR (24) | '_',
			vMIXED, commandFieldWidth, 1, 512, FALSE, FALSE);

	/* Create the key bindings. */
	bindCDKObject (vENTRY, commandEntry, KEY_UP, historyUpCB, &history);
	bindCDKObject (vENTRY, commandEntry, KEY_DOWN, historyDownCB, &history);
	bindCDKObject (vENTRY, commandEntry, KEY_TAB, viewHistoryCB, commandOutput);
//	bindCDKObject (vENTRY, commandEntry, CTRL ('^'), listHistoryCB, &history);
	bindCDKObject (vENTRY, commandEntry, CTRL ('G'), jumpWindowCB, commandOutput);
//	bindCDKObject (vENTRY, commandEntry, CTRL ('H'), helpCB, commandOutput);

	/* menubar shortcuts */
	bindCDKObject (vENTRY, commandEntry, CTRL ('F'), activateMenuCB, "file");
	bindCDKObject (vENTRY, commandEntry, CTRL ('W'), activateMenuCB, "wallet");
	bindCDKObject (vENTRY, commandEntry, CTRL ('R'), activateMenuCB, "report");
	bindCDKObject (vENTRY, commandEntry, CTRL ('A'), activateMenuCB, "admin");
	bindCDKObject (vENTRY, commandEntry, CTRL ('H'), activateMenuCB, "help");

	/* Draw the screen. */
	refreshCDKScreen (cdkscreen);

	eraseCDKEntry (commandEntry);

	/* print introduction message */
	shcon_gui_println("");
	shcon_gui_println("<C>Type \"</B>help<!B>\" for a list of commands.");
	shcon_gui_println("<C>Type \"</B>help <command><!B>\" for command usage.");
	shcon_gui_println("<C>Type \"</B><ctrl>-h<!B>\" for additional help.");

}

static int shcon_gui_menu_init(void)
{
	const char *menulist[MAX_MENU_ITEMS][MAX_SUB_ITEMS];
	int submenusize[5], menuloc[5];
//	const char *mesg[5];
	char buf[256];
	int menu_idx;
	int item_idx;

	for (menu_idx = 0; menu_idx < MAX_MENU; menu_idx++) {
		const menu_t *item_list = _menu_table[menu_idx];

		sprintf(buf, "</B>%s<!B>", _menu_labels[menu_idx]); 
		menulist[menu_idx][0] = strdup(buf);
		for (item_idx = 0; item_list[item_idx].title; item_idx++) {
 			sprintf(buf, "</B>%s<!B>", item_list[item_idx].title);
			menulist[menu_idx][item_idx+1] = strdup(buf);
		}

		submenusize[menu_idx] = item_idx + 1;
	}

	menuloc[0] = LEFT;
	menuloc[1] = LEFT;
	menuloc[2] = LEFT;
	menuloc[3] = LEFT;
	menuloc[4] = RIGHT;

	/* Create the menu. */
	menu = newCDKMenu (cdkscreen, menulist, MAX_MENU, submenusize, menuloc,
			TOP, A_UNDERLINE, A_REVERSE);

}

int shcon_gui_net_init(void)
{
	shjson_t *resp;
	char *args[4];
	int err;

	args[0] = "wallet.list";
	err = shcon_command(args, 1, &resp);
	if (err) {
		shcon_gui_netstate(NULL);
		return (err);
	}

	shcon_gui_netstate(resp);
	shjson_free(&resp);
	return (0);
}

/* a psuedo-graphical command-line interface for the sharecoin daemon. */
int shcon_gui_init(void)
{

	setlocale(LC_ALL, "");

	cdkscreen = initCDKScreen(NULL);

	/* Start color. */
	initCDKColor();

	shcon_gui_menu_init();

	shcon_gui_command_init();

	{
		char *mesg[4];
		mesg[0] = "            ";
		infoBox = newCDKLabel(cdkscreen, RIGHT, BOTTOM,
				(CDK_CSTRING2)mesg, 1, TRUE, FALSE);
	}

}


#define MAX_ARGS 256
int shcon_gui_exec(char *text, shjson_t **resp_p)
{
  char *args[MAX_ARGS];
  size_t text_len;
  size_t of;
  int in_quote;
  int arg_idx;
  int err;
  int i;

  for (i = 0; i < MAX_ARGS; i++)
    args[i] = NULL;

  of = 0;
  arg_idx = 0;
  in_quote = FALSE;
  text_len = strlen(text);

	if (text_len == 0)
		return (0);

	args[arg_idx] = (char *)calloc(text_len+1, sizeof(char));

  for (i = 0; i < text_len; i++) {
    if (text[i] == '"') {
      if (!in_quote)
        in_quote = TRUE;
      else
        in_quote = FALSE;
      continue;
    }

    if (!in_quote && text[i] == ' ') {
      if (i > 0 && text[i-1] == ' ') continue; /* skip ws */
      /* alloc */
      arg_idx++;
			args[arg_idx] = (char *)calloc(text_len+1, sizeof(char));

      of = i;
      continue;
    }

		sprintf(args[arg_idx]+strlen(args[arg_idx]), "%c", text[i]);
  }
	arg_idx++;

  err = shcon_command(args, arg_idx, resp_p);

	/* special case to display balance. */
	if (arg_idx == 1 &&
			0 == strcmp(args[0], "wallet.list")) {
		shcon_gui_netstate(*resp_p);
	}

  for (i = 0; args[i]; i++)
    free(args[i]);

  return (err);
}

void shcon_gui_print_json(shjson_t *j)
{
	char *text;

	text = shjson_Print(j);
	if (!text) {
		shcon_log(SHERR_PROTO, "error decoding JSON");
		return;
	}

	if (0 != strcmp(text, "null")) {
		shcon_gui_print(text);
	}

	free(text);

}

void shcon_gui_print_error(int err_code, char *tag)
{
	char buf[1024];

  if (!err_code)
    return;

	sprintf(buf, "Error: %s [Code %d]", sherrstr(err_code), err_code);
	shcon_gui_println(buf);

  if (tag && *tag) {
		sprintf(buf, "<B=%s", tag);
		shcon_gui_println(buf);
	}

}

void shcon_gui_print_result(shjson_t *j)
{
	shjson_t *node;

	node = shjson_obj_get(j, "result");
	if (node) {
		char *text = shjson_astr(j, "result", "");
		if (!text || !*text) {
			shcon_gui_print_json(node);
		} else if (0 != strcmp(text, "null")) {
			shcon_gui_print(text);
		}
	}

	node = shjson_obj_get(j, "error");
	if (node) {
		char *text = shjson_astr(j, "error", "");
		if (!text || !*text) {
			shcon_gui_print_error(
					(int)shjson_array_num(j, "error", 0),
					shjson_array_str(j, "error", 1));
		}
	}


}

void shcon_gui_menu_run(CDKMENU *menu, char *focusItem)
{
	char *mesg[10];
	char temp[600];
	int selection;
	int i;

	/* set the focus item */
	for (i = 0; i < MAX_MENU; i++) {
		if (0 == strcasecmp(_menu_labels[i], focusItem))
			break;
	}
	if (i == MAX_MENU) i = 0;
	setCDKMenuCurrentItem(menu, i, 0);

	/* Activate the menu. */
	selection = activateCDKMenu (menu, 0);

	if (menu->exitType == vNORMAL) {
		int menu_idx = selection / 100;
		int item_idx = selection % 100;
		const menu_t *item_list = _menu_table[menu_idx];

		if (item_list[item_idx].func) {
			(*item_list[item_idx].func)(item_list + item_idx);
		}
	}

#if 0
	/* Determine how the user exited from the widget. */
	if (menu->exitType == vEARLY_EXIT)
	{
		mesg[0] = "<C>You hit escape. No menu item was selected.";
		mesg[1] = "",
			mesg[2] = "<C>Press any key to continue.";
		popupLabel (cdkscreen, (CDK_CSTRING2) mesg, 3);
	}
	else if (menu->exitType == vNORMAL)
	{
		sprintf (temp, "<C>You selected menu #%d, submenu #%d",
				selection / 100,
				selection % 100);
		mesg[0] = temp;
		mesg[1] = "",
			mesg[2] = "<C>Press any key to continue.";
		popupLabel (cdkscreen, (CDK_CSTRING2) mesg, 3);
	}
#endif

}

int shcon_gui_command_run(char *command)
{
	shjson_t *resp;
	char temp[600];
	char *upper;
	int err;

	if (!command)
		command = "";

	while (command[0] && (unsigned int)command[0] < 32)
		command++;
	if (!command[0]) {
		/* Clean the entry field. */
		cleanCDKEntry (commandEntry);
		return (0);
	}

	upper = uc(command);

	/* Check the output of the command. */
	if (strcmp (upper, "QUIT") == 0 ||
			strcmp (upper, "EXIT") == 0 ||
			strcmp (upper, "Q") == 0 ||
			strcmp (upper, "E") == 0)
	{

		run_state = RUN_NONE;

		raise(SIGTERM);
		return (0);
	}

	if (0 == strcmp(upper, "CLEAR")) {
		/* Keep the history. */
		history.command[history.count] = copyChar (command);
		history.count++;
		history.current = history.count;
		cleanCDKSwindow (commandOutput);
	} else if (0 == strcmp(upper, "HISTORY")) {
		/* Display the history list. */
		listHistoryCB (vENTRY, commandEntry, &history, 0);

		if (history.count != 0)
			return; /* keep entry-field contents. */
	} else if (0 == strcmp(upper, "SAVE")) {
		saveCDKSwindowInformation(commandOutput);
	} else if (0 == strncmp(upper, "MINE", 4)) {
		/* Keep the history. */
		history.command[history.count] = copyChar (command);
		history.count++;
		history.current = history.count;

		mineWindowInitCB(vENTRY, NULL, NULL, 0);
	} else if (0 == strcmp(upper, "WINHELP")) {
		help(commandEntry);
		cleanCDKEntry (commandEntry);
	} else if (0 == strncmp(command, "sh ", 3) ||
			0 == strcmp(command, "sh")) {
		/* Keep the history. */
		history.command[history.count] = copyChar (command);
		history.count++;
		history.current = history.count;

		/* Jump to the bottom of the scrolling window. */
		jumpToLineCDKSwindow (commandOutput, BOTTOM);

		/* seperator */
		shcon_gui_println("");

		/* Insert a line providing the command. */
		sprintf (temp, "</R>%s", command);
		addCDKSwindow (commandOutput, temp, BOTTOM);

		/* run the command. */
		if (strlen(command) <= 3) {
			execCDKSwindow (commandOutput, "help", BOTTOM);
		} else {
			execCDKSwindow (commandOutput, command + 3, BOTTOM);
		}
	} else { /* service command */
		/* Keep the history. */
		history.command[history.count] = copyChar (command);
		history.count++;
		history.current = history.count;

		/* Jump to the bottom of the scrolling window. */
		jumpToLineCDKSwindow (commandOutput, BOTTOM);

		/* seperator */
		shcon_gui_println("");

		/* Insert a line providing the command. */
		sprintf (temp, "</R>%s", command);
		addCDKSwindow (commandOutput, temp, BOTTOM);

		/* run the command against the coin service. */
		resp = NULL;
		err = shcon_gui_exec(command, &resp);
		if (!err) {
			shcon_gui_print_result(resp);
		} else {
			shcon_gui_print_error(err, "Network connection");
			_net_t = 0;
		}
	}

	/* Clean the entry field. */
	cleanCDKEntry (commandEntry);

	/* free resources. */
	free(upper);

}

int shcon_gui_run(void)
{
	shjson_t *resp;
	char *command;
	char temp[600];
	char *upper;
	int err;

	/* Get the command. */
	drawCDKEntry (commandEntry, ObjOf (commandEntry)->box);
	command = activateCDKEntry (commandEntry, 0);

  if (run_state == RUN_NONE)
		return (-1);

	return (shcon_gui_command_run(command));
}

/*
 * This is the callback for the down arrow.
 */
static int historyUpCB (EObjectType cdktype GCC_UNUSED, void *object,
			void *clientData,
			chtype key GCC_UNUSED)
{
   CDKENTRY *entry = (CDKENTRY *)object;
   struct history_st *history = (struct history_st *)clientData;

   /* Make sure we don't go out of bounds. */
   if (history->current == 0)
   {
      Beep ();
      return (FALSE);
   }

   /* Decrement the counter. */
   history->current--;

   /* Display the command. */
   setCDKEntryValue (entry, history->command[history->current]);
   drawCDKEntry (entry, ObjOf (entry)->box);
   return (FALSE);
}

/*
 * This is the callback for the down arrow.
 */
static int historyDownCB (EObjectType cdktype GCC_UNUSED, void *object,
			  void *clientData,
			  chtype key GCC_UNUSED)
{
   CDKENTRY *entry = (CDKENTRY *)object;
   struct history_st *history = (struct history_st *)clientData;

   /* Make sure we don't go out of bounds. */
   if (history->current == history->count)
   {
      Beep ();
      return (FALSE);
   }

   /* Increment the counter... */
   history->current++;

   /* If we are at the end, clear the entry field. */
   if (history->current == history->count)
   {
      cleanCDKEntry (entry);
      drawCDKEntry (entry, ObjOf (entry)->box);
      return (FALSE);
   }

   /* Display the command. */
   setCDKEntryValue (entry, history->command[history->current]);
   drawCDKEntry (entry, ObjOf (entry)->box);
   return (FALSE);
}

/*
 * This callback allows the user to play with the scrolling window.
 */
static int viewHistoryCB (EObjectType cdktype GCC_UNUSED, void *object,
			  void *clientData,
				chtype key GCC_UNUSED)
{
	CDKSWINDOW *swindow = (CDKSWINDOW *)clientData;
	CDKENTRY *entry = (CDKENTRY *)object;

	/* Let them play... */
	activateCDKSwindow (swindow, 0);

	/* Redraw the entry field. */
	drawCDKEntry (entry, ObjOf (entry)->box);

	return (TRUE);
}

/*
 * This callback jumps to a line in the scrolling window.
 */
static int jumpWindowCB (EObjectType cdktype GCC_UNUSED, void *object,
			 void *clientData,
			 chtype key GCC_UNUSED)
{
	CDKENTRY *entry = (CDKENTRY *)object;
	CDKSWINDOW *swindow = (CDKSWINDOW *)clientData;
	CDKSCALE *scale = 0;
	int line;

	/* Ask them which line they want to jump to. */
	scale = newCDKScale (ScreenOf (entry), CENTER, CENTER,
			"<C>Jump To Which Line",
			"Line",
			A_NORMAL, 5,
			0, 0, swindow->listSize, 1, 2, TRUE, FALSE);

	/* Get the line. */
	line = activateCDKScale (scale, 0);

	/* Clean up. */
	destroyCDKScale (scale);

	/* Jump to the line. */
	jumpToLineCDKSwindow (swindow, line);

	/* Redraw the widgets. */
	drawCDKEntry (entry, ObjOf (entry)->box);

	/* Clean the entry field. */
	cleanCDKEntry (commandEntry);

	return (TRUE);
}

/*
 * This callback allows the user to pick from the history list from a
 * scrolling list.
 */
static int listHistoryCB (EObjectType cdktype GCC_UNUSED, void *object,
			  void *clientData,
			  chtype key GCC_UNUSED)
{
	CDKENTRY *entry = (CDKENTRY *)object;
	struct history_st *history = (struct history_st *)clientData;
	CDKSCROLL *scrollList;
	int height = (history->count < 10 ? history->count + 3 : 13);
	int selection;

	/* No history, no list. */
	if (history->count == 0)
	{
		/* Popup a little window telling the user there are no commands. */
		const char *mesg[] =
		{
			"<C></B/16>No Commands Entered",
			"<C>No History"
		};
		popupLabel (ScreenOf (entry), (CDK_CSTRING2)mesg, 2);

		/* Redraw the screen. */
		eraseCDKEntry (entry);
		drawCDKScreen (ScreenOf (entry));

		/* And leave... */
		return (FALSE);
	}

	/* Create the scrolling list of previous commands. */
	scrollList = newCDKScroll (ScreenOf (entry), CENTER, CENTER, RIGHT,
			height, 20, "<C></B/29>Command History",
			(CDK_CSTRING2)history->command,
			history->count,
			NUMBERS, A_REVERSE, TRUE, FALSE);

	/* Get the command to execute. */
	selection = activateCDKScroll (scrollList, 0);
	destroyCDKScroll (scrollList);

	/* Check the results of the selection. */
	if (selection >= 0)
	{
		/* Get the command and stick it back in the entry field. */
		setCDKEntryValue (entry, history->command[selection]);
	}

	/* Redraw the screen. */
	eraseCDKEntry (entry);
	drawCDKScreen (ScreenOf (entry));
	return (FALSE);
}


/*
 * This function displays help.
 */
void help(CDKENTRY *entry)
{
   const char *mesg[25];

   /* Create the help message. */
   mesg[0] = "<C></B/29>Help";
   mesg[1] = "";
   mesg[2] = "</B/24>When in the command line.";
   mesg[3] = "<B=history   > Displays the command history.";
   mesg[4] = "<B=clear     > Clear the command history.";
   mesg[5] = "<B=Up Arrow  > Scrolls back one command.";
   mesg[6] = "<B=Down Arrow> Scrolls forward one command.";
   mesg[7] = "<B=Tab       > Activates the scrolling window.";
   mesg[8] = "<B=Esc       > Displays this help window.";
   mesg[9] = "";
   mesg[10] = "</B/24>When in the scrolling window.";
   mesg[11] = "<B=l or L    > Loads a file into the window.";
   mesg[12] = "<B=s or S    > Saves the contents of the window to a file.";
   mesg[13] = "<B=Up Arrow  > Scrolls up one line.";
   mesg[14] = "<B=Down Arrow> Scrolls down one line.";
   mesg[15] = "<B=Page Up   > Scrolls back one page.";
   mesg[16] = "<B=Page Down > Scrolls forward one page.";
   mesg[17] = "<B=Tab/Escape> Returns to the command line.";
   popupLabel (ScreenOf (entry), (CDK_CSTRING2)mesg, 18);

}

#if 0
static int helpCB (EObjectType cdktype GCC_UNUSED, void *object, void *clientData, chtype key GCC_UNUSED)
{
	CDKENTRY *entry = (CDKENTRY *)object;

	help(entry);

	cleanCDKEntry (commandEntry);

	return (TRUE);
}
#endif

static int activateMenuCB(EObjectType cdktype GCC_UNUSED, void *object, void *clientData, chtype key GCC_UNUSED)
{
	char *focus = (char *)clientData;

	shcon_gui_menu_run(menu, focus);

	cleanCDKEntry (commandEntry);

	return (TRUE);
}

static int XXXCB (EObjectType cdktype GCC_UNUSED,
      void *object GCC_UNUSED,
      void *clientData GCC_UNUSED,
      chtype key GCC_UNUSED)
{
   return (TRUE);
}

static char *shcon_gui_form_init(const menu_t *item)
{
	static char ret_str[256];
	CDK_PARAMS params;
	char info[4096];
	char **args;
	char *title;
	char label[256];
	char *err_msg;
	int max_args;
	int idx;
	int y_of;
	int confirm;
	int filter;

	if (!item)
		return (NULL);
	if (!item->command)
		return (NULL);

	memset(&params, 0, sizeof(params));

	memset(ret_str, 0, sizeof(ret_str));
	strcpy(ret_str, item->command);

	for (max_args = 0; item->labels[max_args]; max_args++);
	args = (char **)calloc(max_args+1, sizeof(char *));

	confirm = FALSE;
	for (idx = 0; idx < max_args; idx++) {

		if (item->types[idx] == FIELD_ACCOUNT) {
			title    = "<C>Enter a account name.";
			filter = vMIXED;
		} else if (item->types[idx] == FIELD_ADDRESS) {
			title    = "<C>Enter a coin address.";
			filter = vMIXED;
		} else if (item->types[idx] == FIELD_AMOUNT) {
			title    = "<C>Enter a coin value.";
			filter = vMIXED;
			confirm = TRUE;
		} else if (item->types[idx] == FIELD_PATH) {
			title    = "<C>Enter a disk path.";
			filter = vMIXED;
			confirm = TRUE;
		} else if (item->types[idx] == FIELD_NUMBER) {
			title    = "<C>Enter a whole number value.";
			filter = vINT;
		} else if (item->types[idx] == FIELD_REAL) {
			title    = "<C>Enter a numeric value.";
			filter = vMIXED;
		} else {
			title    = "<C>Enter a string value.";
			filter = vMIXED;
		}
		sprintf(label, "</U/5>%s:<!U!5>", item->labels[idx]);

try_again:
		memset(info, 0, sizeof(info));

		if (item->types[idx] == FIELD_ACCOUNT &&
				account_table && account_table[0] != NULL) {
#if 0
			CDKRADIO *radio;
			int selection;
			int count;

			/* determine total accounts available. */
			for (count = 0; account_table[count]; count++);

			radio = newCDKRadio(cdkscreen,
					CDKparamValue (&params, 'X', CENTER),
					CDKparamValue (&params, 'Y', CENTER),
					CDKparsePosition (CDKparamString2 (&params,
							's',
							"RIGHT")),
					CDKparamValue (&params, 'H', 10),
					CDKparamValue (&params, 'W', 40),
					CDKparamString2 (&params, 't', title),
					CDKparamNumber (&params, 'c') ? 0 : (CDK_CSTRING2)account_table,
					CDKparamNumber (&params, 'c') ? 0 : count,
					'*' | A_REVERSE, 1,
					A_REVERSE,
					CDKparamValue (&params, 'N', TRUE),
					CDKparamValue (&params, 'S', FALSE));

			refreshCDKScreen (cdkscreen);

			selection = activateCDKRadio (radio, 0);
			int exitType = radio->exitType;

			destroyCDKEntry(radio);

			if (exitType != vNORMAL) {
				return (NULL);
			}

			strncpy(info, account_table[selection], sizeof(info)-1);
#endif
			CDKSCROLL *scroll;
			char *title = "<C></U/5>Originating Account\n";
			int selection;
			int count;

			/* determine total accounts available. */
			for (count = 0; account_table[count]; count++);

			scroll = newCDKScroll(cdkscreen,
            CDKparamValue (&params, 'X', CENTER),
            CDKparamValue (&params, 'Y', CENTER),
            CDKparsePosition (CDKparamString2 (&params,
                 's',
                 "RIGHT")),
            CDKparamValue (&params, 'H', 10),
            CDKparamValue (&params, 'W', 50),
            CDKparamString2 (&params, 't', title),
            (CDKparamNumber (&params, 'c')
             ? 0
             : (CDK_CSTRING2)account_table),
            (CDKparamNumber (&params, 'c')
             ? 0
             : count),
            NONUMBERS,
            A_REVERSE,
            CDKparamValue (&params, 'N', TRUE),
            CDKparamValue (&params, 'S', FALSE));

			refreshCDKScreen (cdkscreen);

			selection = activateCDKScroll(scroll, 0);
			int exitType = scroll->exitType;

			destroyCDKEntry(scroll);

			if (exitType != vNORMAL) {
				return (NULL);
			}

			strncpy(info, account_table[selection], sizeof(info)-1);
		} else {
			CDKENTRY *field;
			char *text;

			field = newCDKEntry (cdkscreen,
					CDKparamValue (&params, 'X', CENTER),
					CDKparamValue (&params, 'Y', CENTER),
					title, label, A_NORMAL, '.', filter,//vMIXED,
					40, 0, 256,
					CDKparamValue (&params, 'N', TRUE),
					CDKparamValue (&params, 'S', FALSE));
			bindCDKObject (vENTRY, field, '?', XXXCB, 0);

			refreshCDKScreen (cdkscreen);
			//setCDKEntry(field, "test", 0, 256, TRUE);

			if (item->types[idx] == FIELD_PATH) {
				char path[PATH_MAX+1];

				/* set default value to sharecoin home directory. */
#ifdef WIN32
				sprintf(path, "%s\\.shc\\", getenv("HOMEDIR"));
#else
				sprintf(path, "%s/.shc/", getenv("HOME"));
#endif
				setCDKEntry(field, path, 0, 256, TRUE);
			}
			
			text = activateCDKEntry (field, 0);
			if (text)
				strncpy(info, text, sizeof(info)-1);
			if (field->exitType != vNORMAL) {
				destroyCDKEntry(field);
				return (NULL);
			}

			/* verify field value */
			err_msg = NULL;
			switch (item->types[idx]) {
				case FIELD_ACCOUNT:
					break;
				case FIELD_ADDRESS:
					if (strlen(info) == 0) {
						err_msg = "An invalid coin address has been entered.";
					}
					break;
				case FIELD_REAL:
				case FIELD_AMOUNT:
					if (atof(info) == 0.00000000) {
						err_msg = "An invalid decimal value has been entered.";
					}
					break;
				case FIELD_NUMBER:
					if (atoi(info) == 0 ||
							atof(info) != (double)atoi(info)) {
						err_msg = "An whole number value has not been entered.";
					}
					break;
			}
			if (err_msg) {
				char *mesg[8];
				char buf[256];

				sprintf(buf, "<C>%s", err_msg);
				mesg[0] = buf;
				mesg[1] = "",
					mesg[2] = "<C>Press any key to continue.";
				popupLabel (cdkscreen, (CDK_CSTRING2) mesg, 3);

				destroyCDKEntry(field);

				goto try_again;
			}

			destroyCDKEntry(field);
		}

		strcat(ret_str, " \"");
		strncat(ret_str, info, sizeof(ret_str) - strlen(ret_str) - 4);
		strcat(ret_str, "\"");

		args[idx] = strdup(info);

	}


	/* confirmation dialog */
	if (confirm) {
		char *mesg[20];
		char *buttons[4];
		char temp[256];
		int choice;
		int i;

		mesg[0] = copyChar ("<C></U>Confirm Action");
		mesg[1] = copyChar ("");

		for (i = 2; i < (max_args+2); i++) {
			idx = i-2;
			sprintf(temp, "%s: </B>%s", item->labels[idx], 
					*args[idx] ? args[idx] : "<empty>");
			mesg[i] = copyChar(temp);
		}

		mesg[i++] = copyChar ("");
		mesg[i++] = copyChar ("<C>Are you sure you want to perform");
		sprintf(temp, "<C>this </R>%s<!R> action?", item->title);
		mesg[i++] = copyChar (temp);
		mesg[i++] = copyChar ("");

		buttons[0] = "<Yes>";
		buttons[1] = "<No>";

		choice = popupDialog (cdkscreen,
				(CDK_CSTRING2)mesg, i,
				(CDK_CSTRING2)buttons, 2);
		freeCharList (mesg, i);

		/* Check the results of the confirmation. */
		if (choice != 0) {
			/* cancelled */
			return (NULL);
		}
	}

	return (ret_str);
}

void menu_command_cb(const menu_t *item)
{

	if (!item)
		return;

	if (item->command) {
		if (!item->labels || !item->labels[0]) {
			/* no arguments */
			shcon_gui_command_run((char *)item->command);
		} else {
			char *command = shcon_gui_form_init(item);
			if (command && *command)
				shcon_gui_command_run(command);
		}
	}

}

static int shcon_gui_mine_run(double *diff_p)
{
	const char *command = "block.work";
	shjson_t *resp;
	shjson_t *node;
	char ret_hex[512];
	char buf[512];
	char *args[4];
	char *data;
	int found;
	int err;

	/* obtain something to work on. */
	args[0] = command;
  err = shcon_command(args, 1, &resp);
	if (err)
		return (err);

	node = shjson_obj(resp, "result");
	data = shjson_str(node, "data", "");

	err = shcon_mine_run(data, ret_hex, diff_p);
	shjson_free(&resp);
	if (err)
		return (err);

	/* submit block to service. */
	args[0] = "block.work";
	args[1] = ret_hex;
  err = shcon_command(args, 2, &resp);
	if (err)
		return (err);

	found = shjson_bool(resp, "result", FALSE);
	shjson_free(&resp);

	if (found) {
		char buf[256];

		/* Jump to the bottom of the scrolling window. */
		jumpToLineCDKSwindow (commandOutput, BOTTOM);

		/* seperator */
		shcon_gui_println("");

		/* Insert a line providing the command. */
		sprintf (buf, "</R>block.work %s", ret_hex);
		addCDKSwindow (commandOutput, buf, BOTTOM);
		addCDKSwindow (commandOutput, "true", BOTTOM);
		return (1);
	}

	return (0);
}

void shcon_gui_mine_status(int found, double diff)
{
	static int _clear_index;
	static int _print_index;
	static uint64_t lastSubmits = -1;
	static double share_last;
	static double last_speed;
	double avg_diff;
	double speed;
	double span;
	char buf[256];
	char tbuf[128];
	time_t now;
	int is_new;

	_clear_index++;
	if (0 == (_clear_index % 1000))
		cleanCDKSwindow(mineWindow);


	_print_index++;
	if (lastSubmits == SHARE_COUNT &&
			(0 != (_print_index % 4)))
		return;
	span = (double)time(NULL) - share_last;
	if (lastSubmits != SHARE_COUNT) {
		share_last = (double)time(NULL);
	}
	lastSubmits = SHARE_COUNT;

	now = time(NULL);
	memset(tbuf, 0, sizeof(tbuf));
	strftime(tbuf, sizeof(tbuf)-1, "%T", gmtime(&now)); 

	if (found > 0) {
		sprintf(buf, "[%s] Found a block.", tbuf);
		addCDKSwindow (mineWindow, buf, BOTTOM);

		SHARE_FOUND += 1;
	}

	avg_diff = 0;
	if (SHARE_COUNT > 0)
		avg_diff = SHARE_TOTAL / (double)SHARE_COUNT;

	speed = avg_diff / span * pow(2, 32) / 0xffff;
	last_speed = ((last_speed * 3) + speed) / 4;

	sprintf(buf, "[%s] %uKH/s blocks %u/%u, sdiff: %-1.1f/%-1.1f/%-1.1f", 
			tbuf, (unsigned int)(last_speed/1000), 
			(unsigned int)SHARE_FOUND, (unsigned int)SHARE_COUNT,
			diff, avg_diff, SHARE_MAX);
	addCDKSwindow (mineWindow, buf, BOTTOM);

	/* Draw the scrolling window. */
	drawCDKSwindow (mineWindow, ObjOf (mineWindow)->box);
}

static int mineWindowInitCB (EObjectType cdktype GCC_UNUSED, void *object, void *clientData, chtype key GCC_UNUSED)
{
	static const char *title    = "<C></5>Mining Log";
	CDK_PARAMS params;
	double diff;

	if (!mineWindow) {
		memset(&params, 0, sizeof(params));

		/* Create the scrolling window. */
		mineWindow = newCDKSwindow (cdkscreen,
				CDKparamValue (&params, 'X', CENTER),
				CDKparamValue (&params, 'Y', CENTER),
				CDKparamValue (&params, 'H', 12),
				CDKparamValue (&params, 'W', 65),
				title, 100,
				CDKparamValue (&params, 'N', TRUE),
				CDKparamValue (&params, 'S', FALSE));
		if (!mineWindow)
			return (ERR_INVAL); /* ERR_TERMINAL */
	}

go_again:
	/* Draw the scrolling window. */
	drawCDKSwindow (mineWindow, ObjOf (mineWindow)->box);

	while (1) {
		struct timeval to;
		fd_set set;
		char buf[256];
		int err;

		FD_ZERO(&set);
		FD_SET(0, &set);
		memset(&to, 0, sizeof(to));
		err = select(1, &set, NULL, NULL, &to);

		if (err != 0) {
			/* pending keyboard input */
			addCDKSwindow (mineWindow, "Mining halted due to user input.", BOTTOM);
			break;
		}

		err = shcon_gui_mine_run(&diff);
		if (err >= 0 || err == ERR_AGAIN) {
			shcon_gui_mine_status(err, diff);
		} else {
			sprintf(buf, "Error code %d", err);
			addCDKSwindow (mineWindow, buf, BOTTOM);
			sleep (1);
		}
	}

	activateCDKSwindow(mineWindow, 0);

	if (mineWindow->exitType == vESCAPE_HIT) {
		destroyCDKSwindow(mineWindow);
		mineWindow = NULL;

		drawCDKSwindow (commandOutput, ObjOf (commandOutput)->box);
		return;
	}

	jumpToLineCDKSwindow (mineWindow, BOTTOM);
	addCDKSwindow (mineWindow, "Returning to mining..", BOTTOM);
	goto go_again;
}

static int mineWindowTermCB (EObjectType cdktype GCC_UNUSED, void *object, void *clientData, chtype key GCC_UNUSED)
{
	char *mesg[4];

	if (!mineWindow)
		return (0);

	/* de-allocate resources */
	destroyCDKSwindow(mineWindow);
	mineWindow = NULL;

	mesg[0] = "<C>Automatic mining has been disabled.";
	mesg[1] = "",
	mesg[2] = "<C>Press any key to continue.";
	popupLabel (cdkscreen, (CDK_CSTRING2) mesg, 3);

}

void shcon_gui_cycle(void)
{
	time_t now;

	shcon_gui_init();

	now = time(NULL);
  run_state = RUN_IDLE;
  while (run_state != RUN_NONE) {
		if ((_net_t + 600) < now) {
			if (0 == shcon_gui_net_init())
				_net_t = now;
		}

		shcon_gui_run();
  }

	while (history.count-- > 0)
		free (history.command[history.count]);

	destroyCDKMenu(menu);
	destroyCDKEntry (commandEntry);
	destroyCDKSwindow (commandOutput);
	destroyCDKScreen (cdkscreen);

	endCDK ();

}

#endif /* HAVE_LIBCURSES */

