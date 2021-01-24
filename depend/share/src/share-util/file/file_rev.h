
int share_file_revision(char **args, int arg_cnt, int pflags);

int share_file_revision_diff(revop_t *r, shfs_ino_t *file, shkey_t *rev_key, int pflags);
int share_file_revision_status(revop_t *r, shfs_ino_t *file, int pflags);

int share_file_revision_revert(revop_t *r, shfs_ino_t *file, int pflags);

