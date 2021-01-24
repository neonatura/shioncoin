
/*
 *  Copyright 2013 Neo Natura
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
 */  

#include "share.h"
#include "sharetool.h"

char process_path[PATH_MAX + 1];
char process_file_path[PATH_MAX + 1];
char process_outfile_path[PATH_MAX + 1];
char process_socket_host[PATH_MAX + 1];
unsigned int process_socket_port;
int process_run_mode;
int run_flags;

FILE *sharetool_fout;

void print_process_version(void)
{
  char *app_name = shfs_app_name(process_path);
  printf (
      "%s version %s\n"
      "\n"
      "Copyright 2013 Neo Natura\n"
      "Licensed under the GNU GENERAL PUBLIC LICENSE Version 3\n",
      app_name, VERSION); 
}

void print_process_usage(void)
{

  printf (
      "share-util: Command-line tools for the Share Library.\n"
      "\n"
      );
  switch (process_run_mode) {
    case SHM_PACKAGE:
      printf("Usage: %s [COMMAND] [NAME] [[PATH]|[CERT]]\n", process_path);
      printf("Manage file distribution packages.\n");
      break;
    case SHM_CERTIFICATE:
      printf("Usage: %s [COMMAND] [NAME]\n", process_path);
      printf("Manage digital certificates.\n");
      break;
    case SHM_FILE_LIST:
      printf("Usage: %s [OPTION] [PATH]\n", process_path);
      printf("List entries in a shfs partition.\n");
      break;
    case SHM_FILE_MKDIR:
      printf("Usage: %s [OPTION] [PATH]\n", process_path);
      printf("Create a directory in a shfs partition.\n");
      break;
    case SHM_FILE_REMOVE:
      printf("Usage: %s [OPTION] [PATH]\n", process_path);
      printf("Remove a entry in a shfs partition.\n");
      break;
    case SHM_FILE_CAT:
      printf("Usage: %s [OPTION] [PATH]\n", process_path);
      printf("Print a file in a shfs partition.\n");
      break;
    case SHM_FILE_COPY:
      printf("Usage: %s [OPTION] [PATH] ..\n", process_path);
      printf ("Copy a file to another location.\n");
      break;
    case SHM_FILE_INFO:
      printf("Usage: %s [OPTION] [PATH]\n", process_path);
      printf ("Print verbose information on a file path.\n");
      break;
    case SHM_FILE_LINK:
      printf("Usage: %s [OPTION] [PATH] ..\n", process_path);
      printf ("Reference a file from another location.\n");
      break;
    case SHM_FILE_DIFF:
      printf("Usage: %s [OPTION] [PATH]\n", process_path);
      printf("Generate a binary patch file from two files.\n");
      break;
    case SHM_FILE_PATCH:
      printf("Usage: %s [OPTION] [PATH]\n", process_path);
      printf("Apply a binary patch file to a file.\n");
      break;
    case SHM_PREF:
      printf("Usage: %s [OPTION] [PREFERENCE] [<value>]\n", process_path);
      printf("Define or view global preferences.\n");
      break;
    case SHM_FILE_REV:
      printf("Usage: %s [OPTION] [COMMAND] [PATH] [@<hash>]\n", process_path);
      printf("Track file revisions.\n");
      break;
    case SHM_FILE_ATTR:
      printf("Usage: %s [OPTION] [+|-][ATTRIBUTE] [PATH]\n", process_path);
      printf("Set file attributes.\n");
      break;
    case SHM_PEER:
      printf("Usage: %s [OPTION] [PEER]\n", process_path);
      printf("Show network peer information.\n");
      break;
    case SHM_INFO:
      printf("Usage: %s [OPTION] [NAME]\n", process_path);
      printf("Show contextual information.\n");
      break;
    case SHM_PAM:
      printf("Usage: %s [OPTION] [PEER]\n", process_path);
      printf("Account permission access management.\n");
      break;
    case SHM_DATABASE:
      printf("Usage: %s [OPTION] [NAME]\n", process_path);
      printf("Manage the content stored in a database.\n");
      break;
    case SHM_FS_CHECK:
      printf("Usage: %s [OPTION]\n", process_path);
      printf("Verify the integrity of the share-fs filesystem.\n");
      break;
    case SHM_ARCHIVE:
      printf("Usage: %s [OPTION] [ARCHIVE] [PATH]\n", process_path);
      printf("Archive or extract compressed file(s).\n");
      break;
    case SHM_GEO:
      printf("Usage: %s [OPTION]\n", process_path);
      printf("Query and manage the geodetic database.\n");
      break;
    default:
      printf ("Usage: %s [OPTION]\n", process_path);
      break;
  }
  printf
    (
     "\n"
     "Options:\n"
     "\t-h | --help\t\tShows program usage instructions.\n"
     "\t-v | --version\t\tShows program version.\n"
     "\t-q | --quiet\t\tSuppress printing non-critical information.\n"
     "\t-l | --list\t\tList additional verbose information.\n"
     "\t-o | --out <path>\tPrint standard output to a file.\n"
    );

  if (process_run_mode == SHM_FILE_COPY ||
      process_run_mode == SHM_FILE_LINK) {
    printf("\t-r | --recursive\tProcess sub-directories recursively.\n");
  }
  if (process_run_mode == SHM_GEO) {
    printf("\t-s | --set\t\tSet context information for a location.\n");
  }
  if (process_run_mode == SHM_INFO) {
    printf("\t-s | --set\t\tSet a context value.\n");
    printf("\t-k | --key\t\tGet a context value by it's key reference.\n");
    printf("\t-j | --json\t\tStore arguments in JSON format.\n");
  }
  if (process_run_mode == SHM_DATABASE) {
    printf("\t-i | --ignore\tAllow syntax errors when parsing input.");
  }
  if (process_run_mode == SHM_PAM) {
    printf(
        "\t-S\t\t\tShow status information for an account.\n"
#if 0
        "\t-d\t\t\tDelete an account.\n"
        "\t-e\t\t\tExpire a session token for an account.\n"
        "\t-k\t\t\tLock an account from login.\n"
        "\t-t\t\t\tGenerate a session token for an accout.\n"
#endif
        );
  } 
  if (process_run_mode == SHM_ALG) {
    printf("\t-b | --bin <fmt>\tThe binary format to use.\n");
    printf("\t-a | --alg <alg>\tThe algorythm to use.\n");
  }
  if (process_run_mode == SHM_CERTIFICATE) {
    printf("\t-c | --cert [PATH]\tSpecify a x509 file in sharefs path notation.\n");
  }
  if (process_run_mode == SHM_ARCHIVE) {
    printf("\t-x\t\t\tExtract the compressed archive.\n");
    printf("\t-V\t\t\tVerify the compressed archive.\n");
  }

  printf("\n");

  if (process_run_mode == SHM_PACKAGE) {
    printf (
        "Commands:\n"
        "\tlist\t\t\tList the certificates available in the system.\n"
        "\tcreate [NAME]\t\tCreate a new sharefs package.\n"
        "\tadd [NAME] [PATH]\tUpdate an file in a sharefs package.\n"
        "\trm [NAME] [PATH]\tErase a file from a sharefs package.\n"
        "\tsign [NAME] [CERT]\tSign a package with a system certificate.\n"
//        "\tremove [NAME]\tRemove a sharefs package from the system.\n"
        "\tinstall [NAME]\t\tInstall a sharefs package.\n"
        "\tuninstall [NAME]\tUninstall a sharefs package.\n"
        "\n");
  } else if (process_run_mode == SHM_FILE_REV) {
    printf (
        "Commands:\n"
        "\tadd\t\t\tAdd current directory to repository.\n"
        "\tadd <path>\t\tAdd supplemental file(s) to the repository.\n"
        "\tbranch\t\t\tShow all branch revision references.\n"
        "\tbranch <name> [<path>]\tCreate a new repository branch.\n"
        "\tcat [<path>]\t\tPrint last committed revision.\n"
        "\tcat @<hash> [<path>]\tPrint contents of file revision.\n"
        "\tcheckout [<path>]\tSwitch to \"master\" branch.\n"
        "\tcheckout @<hash> [<path>]\n\t\t\t\tSwitch to commit revision.\n"
        "\tcommit\t\t\tCommit current directory's modifications.\n"
        "\tcommit <path>\t\tCommit revision for file(s).\n"
        "\tdiff\t\t\tDisplay the difference between file versions.\n"
        "\tdiff [@hash] [<path>]\tShow modifications since revision.\n"
        "\tlog\t\t\tRevision history of current directory.\n"
        "\tlog [@hash] [<path>]\tDisplay file revision history.\n"
        "\trevert\t\t\tRevert to last commit revision.\n"
        "\trevert [<path>]\t\tRevert working-area to revision.\n"
        "\tstatus\t\t\tDisplay status of modified files.\n"
        "\tstatus [<path>]\t\tDisplay status of file(s).\n"
        "\tswitch\t\t\tSet the current working revision.\n"
        "\tswitch [<path>]\t\tSwitch to \"master\" branch.\n"
        "\tswitch <branch> [<path>]\n\t\t\t\tSwitch working area to branch.\n"
        "\tswitch <tag> [<path>]\tSwitch working area to tag.\n"
        "\tswitch master\t\tSet working area to initial branch.\n"
        "\tswitch PREV\t\tSet working area to prior committed revision.\n"
        "\ttag\t\t\tShow all named tag revision references.\n"
        "\ttag <name> [@hash] [<path>]\n\t\t\t\tTag revision by name.\n"
        "\n"
        "\tNote: Working area defaults to current directory when no path is specified.\n"
//        "Note: Use option '-r' in order to include sub-directory hierarchies in revision operations.\n"
        "\n"
        );
  } else if (process_run_mode == SHM_FILE_ATTR) {
    char *label;
    int i;

    printf(
        "Attributes:\n"
        "\t+a (Arch)\tCopy as tar archive to native file-system.\n"
        "\t-a \t\tCopy directory without archive conversion.\n"
        "\t+c (Compress)\tData content is stored in a compressed format.\n"
        "\t-c \t\tData content is not stored in a compressed format.\n"
        "\t+e (Encrypt)\tData content is stored in a encrypted format.\n"
        "\t-e \t\tData content is not stored in a encrypted format.\n"
        "\t+f (FLock)\tThe underlying data content is locked.\n"
        "\t-f \t\tThe underlying data content is not locked.\n"
        "\t+r (Read)\tThe file has public read access.\n"
        "\t-r \t\tThe file's read access is limited to owner.\n"
        "\t+s (Sync)\tThe underlying data is synchronized with remote peers.\n"
        "\t-s \t\tThe underlying data is limited to local storage.\n"
        "\t+t (Temp)\tThe directory can only be modified by it's owner.\n"
        "\t-t \t\tThe directory can be modified by normal permissions.\n"
        "\t+v (Version)\tCreate a repository to store file revisions.\n"
        "\t-v \t\tRemove a file revision repository.\n"
        "\t+w (Write)\tThe file has public write access.\n"
        "\t-w \t\tThe file's write access is limited to owner.\n"
        "\t+x (Exe)\tThe file has public execute access.\n"
        "\t-x \t\tThe file's execute access is limited to owner.\n"
        "\n");
  }

  if (process_run_mode == SHM_CERTIFICATE) {
    printf (
        "Commands:\n"
        "\tlist [\"alias\"|\"lic\"]\tList the certificates available in the system.\n"
        "\tcreate [<ca-name>]\tCreate a new system certificate.\n"
        "\tremove <name>\tRemove a system share certificate.\n"
        "\tprint <name>\tPrint a certificate's specifications.\n"
        "\tverify <name>\tVerify a certificate's integrity.\n"
        "\tapply <name> <path>\t\tApply a certificate to a shfs file.\n"
/* licensing requires ownership via cmdline */
//        "\tlicense <parent> [<path>]\t\tCreate a new license certificate.\n"
//        "\tlicense <parent>\t\tCreate a new license certificate.\n"
        "\tverlic <parent> <path>\t\tVerify a file's certificate signature.\n"
        "\tvallic <path>\t\tValidate a file is licensed.\n"
        "\n"
        "Managing x509 certificates:\n"
        "\tImport a x509 certificate:\n"
        "\t\tshcert -c x509.crt create <name>\n" 
        "\tPrint a x509 certificate:\n"
        "\t\tshcert -c x509.crt print\n"
        "\n");
  } else if (process_run_mode == SHM_FS_CHECK) {
    printf (
        "Description:\n"
        "\tThe shfsck utility performs various integrity checks against the share-fs file-system. All share-fs partitions are examined for proper inode hierarchy, data checksum verification, duplicate inodes, and unattached inodes. Additional summary information is also provided\n"
        "\n"
        );
  } else if (process_run_mode == SHM_PREF) { 
    printf(
        "Preferences:\n"
        "\tuser.name\tThe login user's real name.\n"
        "\tuser.email\tThe login user's email address.\n"
        "\n"
        );
  } else if (process_run_mode == SHM_PEER ||
      process_run_mode == SHM_PAM) { 
    printf(
        "Peer:\n"
        "\t<app>[:<group>][@<host>[:<port>]]\n"
        "\t\t<app>\tThe application name.\n"
        "\t\t<group>\tA specific group of the application.\n"
        "\t\t<host>\tThe application's network host-name.\n"
        "\t\t<port>\tThe application's network port number.\n"
        "\n"
        );
  } else if (process_run_mode == SHM_ARCHIVE) {
    printf (
        "Description:\n"
        "\tBy default, a compressed archive is created containing the file(s) specified. All directories referenced are recursively processed. The \"-x\" command-line option is used to extract an archive file. A filter file-spec may be specified.\n"
        "\n"
        "Archive:\n"
        "\tThe filename, usually ending in the suffix \".shz\", contains the compressed archive of files. The archive is a reference to a file on the local hard-disk.\n"
        "\n"
        "Path:\n"
        "\tOne or more filenames or directories to compress or optional wildcard file-specs if decompressing.\n"
        "\n"
        "Additional Notes:\n"
        "\tCompression and directory archives are automatically performed in the share file-system with use of the \"shattr\" command. Copying a compressed or archive path from the share-filesystem will result in a suffix (\".shz\" or \".tar\") being appended unless an absolute filename is specified as the destination.\n"
        "\n"
);
  } else if (process_run_mode == SHM_GEO) {
    fprintf(sharetool_fout, 
        "Parameters:\n"
        "\t<city>, <state-abrev>\n"
        "\t<zip code>\n"
        "\t<ipv4 address>\n"
        "\tgeo:<latitude>,<longitude>\n"
        "\n"
        "\t--set geo:<latitude>,<longitude>\n"
        "\n"
        "Examples:\n"
        "\tshgeo \"Missoula, MT\"\n"
        "\tshgeo 59801\n"
        "\tshgeo 100.0.0.1\n"
        "\tshgeo geo:46.9,114.2\n"
        "\n"
        );
  } else if (process_run_mode == SHM_ALG) {
    fprintf(sharetool_fout,
        "Commands:\n"
        "\tcreate <data>\n"
        "\t\tGenerate a <private key> with the \"create\" command.\n"
        "\n"
        "\tpublic <private key>\n"
        "\t\tDerive a <public key> with the \"public\" command.\n"
        "\n"
        "\tsign <private key> <data>\n"
        "\t\tSign <data> to generate a <signature>.\n"
        "\n"
        "\tverify <public key> <signature> <data>\n"
        "\t\tValidate a <signature> with the \"verify\" command.\n"
        "\n"
        "Algorythms:\n"
        "\t\"shr160\"\tShare 160-bit Algorythm (RIPEMD)\n"
        "\t\"shr224\"\tShare 224-bit Algorythm\n"
        "\t\"ecdsa224r\"\t224-bit Elliptic Curve (vr)\n"
        "\t\"ecdsa224k\"\t224-bit Elliptic Curve\n"
        "\t\"ecdsa256r\"\t256-bit Elliptic Curve (vr)\n"
        "\t\"ecdsa256k\"\t256-bit Elliptic Curve\n"
        "\t\"sha1\"\t\tSecure Hash Algorythm 160-bit\n"
        "\t\"sha256\"\tSecure Hash Algorythm 256-bit\n"
        "\t\"sha512\"\tSecure Hash Algorythm 512-bit\n"
        "\n"
        "Formats:\n"
        "\t\"hex\"\t\tHexadecimal Format\n"
        "\t\"shr56\"\t\tShare 56-bit Format\n"
        "\t\"b32\"\t\tBase-32 Format\n"
        "\t\"b58\"\t\tBase-58 Format\n"
        "\t\"b64\"\t\tBase-64 Format\n"
        "\n"
#if 0
        "Additional Notes:\n"
        "\tPrefix a parameter with the \"@\" symbol in order to reference file contents.\n"
        "\tFor Example: shalg verify @pub.key @sig.key @data.txt\n"
        "\n"
#endif
        );
  } else if (process_run_mode == SHM_INFO) {
    fprintf(sharetool_fout, 
        "Parameters:\n"
        "\t<name>\n"
        "\t\tLook up the context value for a given name.\n"
        "\n"
        "\t-k <key>\n"
        "\t\tLook up a context value by it's key reference.\n"
        "\n"
        "\t-s <name> <value>\n"
        "\t\tSet a context value in plain ol' text format.\n"
        "\n"
        "\t-s <name> \"@\"<file>\n"
        "\t\tSet the context to ascii or binary file contents.\n"
        "\n"
        "\t-s -j <name> \"@\"<file>\n"
        "\t\tSet a JSON format context value from arguments in a file.\n"
        "\n"
        "\t-s -j <name> <arg>=<value>[, <arg><value>[, ..]]\n"
        "\t\tSet a context value as a set of arguments in JSON format.\n"
        "\n"
        "Additional Notes:\n"
        "\tContext names are stored as a 160-bit hash. Context names have an unlimited size.\n"
        "\n"
        "\tContext values are limited to 4096 bytes.\n"
        "\n"
        "\tContext records expire after 2 years.\n" 
        "\n"
        "\tContext records can be overwritten on a local machine at any time.\n"
        "\n"
        "\tRemote servers will not accept an 'over-write' of a context by a different owner unless the record has expired.\n"
        "\n"
        );
  } else {
    printf(
        "Paths:\n"
        "\t<filename>\n"
        "\t\tA local hard-drive path in the current directory.\n\n"
        "\t/<path>/[<filename>]\n"
        "\t\tA path in the default share-fs partition.\n\n"
        "\thome:/[<path>/][<filename>]\n"
        "\t\tThe user's home share-fs partition.\n\n"
        "\tfile:/<path>/[<filename>]\n"
        "\t\tAn absolute local hard-drive path.\n\n"
        "\t<app>[:<group>][@<host>[:<port>]]:/<path>/[<filename>]\n"
        "\t\tAn absolute path in a share-fs partition.\n"
        "\n"
        );
  }

  printf(
      "Visit 'http://sharelib.net/libshare/' for libshare API documentation.\n"
      );

}

int main(int argc, char **argv)
{
  shpeer_t *proc_peer;
  char out_path[PATH_MAX+1];
  char peer_name[4096];
  char subcmd[256];
  char *app_name;
  char **args;
  int arg_cnt;
  int err_code;
  int pflags;
  int err;
  int i;

  sharetool_fout = stdout;
  process_run_mode = SHM_NONE;

  app_name = shfs_app_name(argv[0]);
  strncpy(process_path, app_name, PATH_MAX);

  if (0 == strcmp(app_name, "shls")) {
    process_run_mode = SHM_FILE_LIST;
  } else if (0 == strcmp(app_name, "shfsck")) {
    process_run_mode = SHM_FS_CHECK;
  } else if (0 == strcmp(app_name, "shinfo")) {
    process_run_mode = SHM_INFO;
  } else if (0 == strcmp(app_name, "shapp")) {
    process_run_mode = SHM_PEER;
  } else if (0 == strcmp(app_name, "shln")) {
    process_run_mode = SHM_FILE_LINK;
  } else if (0 == strcmp(app_name, "shcp")) {
    process_run_mode = SHM_FILE_COPY;
  } else if (0 == strcmp(app_name, "shstat")) {
    process_run_mode = SHM_FILE_INFO;
  } else if (0 == strcmp(app_name, "shmkdir")) {
    process_run_mode = SHM_FILE_MKDIR;
  } else if (0 == strcmp(app_name, "shrm")) {
    process_run_mode = SHM_FILE_REMOVE;
  } else if (0 == strcmp(app_name, "shgeo")) {
    process_run_mode = SHM_GEO;
  } else if (0 == strcmp(app_name, "shalg")) {
    process_run_mode = SHM_ALG;
  } else if (0 == strcmp(app_name, "shz")) {
    process_run_mode = SHM_ARCHIVE;
  } else if (0 == strcmp(app_name, "shcat")) {
    process_run_mode = SHM_FILE_CAT;
  } else if (0 == strcmp(app_name, "shpref")) {
    process_run_mode = SHM_PREF;
  } else if (0 == strcmp(app_name, "shdiff")) {
    process_run_mode = SHM_FILE_DIFF;
  } else if (0 == strcmp(app_name, "shdelta")) {
    process_run_mode = SHM_FILE_DELTA;
  } else if (0 == strcmp(app_name, "shpatch")) {
    process_run_mode = SHM_FILE_PATCH;
  } else if (0 == strcmp(app_name, "shattr")) {
    process_run_mode = SHM_FILE_ATTR;
  } else if (0 == strcmp(app_name, "shrev")) {
    process_run_mode = SHM_FILE_REV;
  } else if (0 == strcmp(app_name, "shpasswd")) {
    process_run_mode = SHM_PAM;
  } else if (0 == strcmp(app_name, "shpkg")) {
    process_run_mode = SHM_PACKAGE;
  } else if (0 == strcmp(app_name, "shcert")) {
    process_run_mode = SHM_CERTIFICATE;
  } else if (0 == strcmp(app_name, "shdb")) {
    process_run_mode = SHM_DATABASE;
  }

  args = (char **)calloc(argc+1, sizeof(char *));
  args[0] = strdup(process_path);
  arg_cnt = 1;

  pflags = 0;
  memset(out_path, 0, sizeof(out_path));
  memset(peer_name, 0, sizeof(peer_name));
  for (i = 1; i < argc; i++) {
    if (0 == strcmp(argv[i], "-l") ||
        0 == strcmp(argv[i], "--list")) {
      pflags |= PFLAG_VERBOSE;
    } else if (0 == strcmp(argv[i], "-r") ||
        0 == strcmp(argv[i], "--recursive")) {
      pflags |= PFLAG_RECURSIVE;
#if 0
    } else if (0 == strcmp(argv[i], "-l") ||
        0 == strcmp(argv[i], "--local")) {
      pflags |= PFLAG_LOCAL;
#endif
    } else if (0 == strcmp(argv[i], "-h") ||
        0 == strcmp(argv[i], "--help")) {
      pflags |= PFLAG_SYNTAX;
    } else if (0 == strcmp(argv[i], "-v") ||
        0 == strcmp(argv[i], "--version")) {
      pflags |= PFLAG_VERSION;
    } else if (0 == strcmp(argv[i], "-o") ||
        0 == strcmp(argv[i], "--out")) {
      if (i + 1 < argc) {
        i++;
        strncpy(out_path, argv[i], sizeof(out_path) - 1);
      } else {
        printf ("%s: warning: no output path specified.", process_path); 
      } 
#if 0
    } else if (0 == strcmp(argv[i], "-c")) {
      if ( (i + 1) < argc ) {
        i++;
        strncpy(peer_name, argv[i], sizeof(peer_name) - 1);
      }
#endif
    } else if (
        0 == strcmp(argv[i], "-q") ||
        0 == strcmp(argv[i], "--quiet")) {
      pflags |= PFLAG_QUIET;
    } else if (
        0 == strcmp(argv[i], "-i") ||
        0 == strcmp(argv[i], "--ignore")) {
      pflags |= PFLAG_IGNORE;
    } else if (
        0 == strcmp(argv[i], "-V") ||
        0 == strcmp(argv[i], "--verify")) {
      pflags |= PFLAG_VERIFY;
    } else if (0 == strcmp(argv[i], "-x")) {
      pflags |= PFLAG_DECODE;
#if 0
    } else if (0 == strcmp(argv[i], "-b") ||
        0 == strcmp(argv[i], "--binary")) {
      pflags |= PFLAG_BINARY;
#endif
    } else if (0 == strcmp(argv[i], "-j") ||
        0 == strcmp(argv[i], "--json")) {
      pflags |= PFLAG_JSON;
    } else if (0 == strcmp(argv[i], "-s") ||
        0 == strcmp(argv[i], "--set")) {
      pflags |= PFLAG_UPDATE;
    } else {
      args[arg_cnt] = strdup(argv[i]);
      arg_cnt++;
    } 
  }

  if (pflags & PFLAG_VERSION) {
    print_process_version();
    exit(0);
  }
  if (pflags & PFLAG_SYNTAX) {
    print_process_usage();
    exit(0);
  }

  if (pflags & PFLAG_QUIET) {
    /* redirect all non-error output to 'null' device */
    strcpy(out_path, "/dev/null");
  }
  if (*out_path) {
    sharetool_fout = fopen(out_path, "wb");
  }

  memset(subcmd, 0, sizeof(subcmd));
  for (i = 1; i < arg_cnt; i++) {
    if (*subcmd)
      strcat(subcmd, " ");
    strcat(subcmd, args[i]);
  }

  /* register with share daemon */
  //proc_peer = shapp_init(argv[0], NULL, 0);
  proc_peer = shapp_init(NULL, NULL, 0);

  err_code = 0;
  run_flags = pflags;
  switch (process_run_mode) {
    case SHM_FILE_LIST:
      share_file_list(subcmd, pflags);
      break;
#if 0
    case SHM_FILE_IMPORT:
      share_file_import(subcmd, pflags);
      break;
#endif
    case SHM_FILE_CAT:
      for (i = 1; i < arg_cnt; i++) {
        err_code = share_file_cat(args[i], pflags);
        if (err_code) {
          fprintf(stderr, "%s: cannot access %s: %s.\n", process_path, subcmd, sherrstr(err_code)); 
        }
      }
      break;
#if 0
    case SHM_FILE_MKDIR:
      share_file_mkdir(subcmd, pflags);
      break;
#endif

    case SHM_FILE_REMOVE:
      share_file_remove(args, arg_cnt, pflags);
      break;

    case SHM_FILE_ATTR:
      share_file_attr(subcmd, pflags);
      break;

    case SHM_FILE_DIFF:
      err = share_file_diff(args, arg_cnt, pflags);
      if (err) {
        fprintf(stderr, "%s: error: %s.\n", process_path, sherrstr(err));
      }
      break;

    case SHM_FILE_DELTA:
      err = share_file_delta(args, arg_cnt, pflags);
      if (err) {
        fprintf(stderr, "%s: error: %s.\n", process_path, sherrstr(err));
      }
      break;

    case SHM_FILE_PATCH:
      err = share_file_patch(args, arg_cnt, pflags);
      if (err) {
        fprintf(stderr, "%s: error: %s.\n", process_path, sherrstr(err));
      }
      break;

    case SHM_PREF:
      err = sharetool_pref(subcmd);
      if (err) {
        if (err == SHERR_INVAL)
          fprintf(stderr, "%s: error: no preference name specified.\n", process_path);
        else if (err == SHERR_NOENT)
          fprintf(stderr, "%s: warning: preference has no value set.\n", process_path);
        return (1);
      }
      break;

    case SHM_FILE_REV:
      err = share_file_revision(args, arg_cnt, pflags);
      if (err) {
        fprintf(stderr, "%s: error: %s\n", process_path, sherrstr(err));
        return (1);
      }
      break;

    case SHM_GEO:
      err = sharetool_geo(args, arg_cnt);
      if (err) {
        fprintf(stderr, "%s: error: %s\n", process_path, sherrstr(err));
        return (1);
      }
      break;

    case SHM_ALG:
      err = sharetool_alg(args, arg_cnt);
      if (err) {
        fprintf(stderr, "%s: error: %s\n", process_path, sherrstr(err));
        return (1);
      }
      break;

    case SHM_ARCHIVE:
      err = sharetool_archive(args, arg_cnt);
      if (err) {
        fprintf(stderr, "%s: error: %s\n", process_path, sherrstr(err));
        return (1);
      }
      break;

    case SHM_FILE_COPY:
      err = share_file_copy(args, arg_cnt, pflags);
      if (err) {
        fprintf(stderr, "%s: error: %s\n", process_path, sherrstr(err));
        return (1);
      }
      break;

    case SHM_FILE_LINK:
      err = share_file_link(args, arg_cnt, pflags);
      if (err) {
        fprintf(stderr, "%s: error: %s\n", process_path, sherrstr(err));
        return (1);
      }
      break;

    case SHM_FILE_INFO:
      err = share_file_info(args, arg_cnt, pflags);
      if (err) {
        fprintf(stderr, "%s: error: %s\n", process_path, sherrstr(err));
        return (1);
      }
      break;

    case SHM_INFO:
      err = share_info(args, arg_cnt, pflags);
      if (err) {
        fprintf(stderr, "%s: error: %s\n", process_path, sherrstr(err));
        return (1);
      }
      break;

    case SHM_PEER:
      err = share_appinfo(args, arg_cnt, pflags);
      if (err) {
        fprintf(stderr, "%s: error: %s\n", process_path, sherrstr(err));
        return (1);
      }
      break;

    case SHM_PAM:
      err = sharetool_passwd(args, arg_cnt);
      if (err) {
        fprintf(stderr, "%s: error: %s\n", process_path, sherrstr(err));
        return (1);
      }
      break;

    case SHM_PACKAGE:
      err = sharetool_package(args, arg_cnt, pflags);
      if (err) {
        fprintf(stderr, "%s: error: %s\n", process_path, sherrstr(err));
        return (1);
      }
      break;

    case SHM_CERTIFICATE:
      err = sharetool_certificate(args, arg_cnt, pflags);
      if (err) {
        fprintf(stderr, "%s: error: %s\n", process_path, sherrstr(err));
        return (1);
      }
      break;

    case SHM_DATABASE:
      err = sharetool_database(args, arg_cnt, pflags);
      if (err) {
        fprintf(stderr, "%s: error: %s\n", process_path, sherrstr(err));
        return (1);
      }
      break;

    case SHM_FS_CHECK:
      err = sharetool_fscheck();
      break;

    default:
      print_process_usage();
      break;
  }

  if (sharetool_fout) {
    fclose(sharetool_fout);
  }
  shpeer_free(&proc_peer);

	return (err_code);
}


