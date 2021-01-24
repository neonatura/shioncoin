

#include "sharetool.h"


revop_t *rev_init(void)
{
  revop_t *r;

  r = (revop_t *)calloc(1, sizeof(revop_t));
  if (!r)
    return (NULL);

  return (r);
}

void rev_free(revop_t **r_p)
{
  revop_t *r;

  if (!r_p)
    return;
  r = *r_p;
  if (!r)
    return;
  *r_p = NULL;

  free(r);
}

void rev_command_set(revop_t *rev, int cmd)
{

  if (!rev)
    return;

  rev->cmd = cmd;
}

void rev_command_setstr(revop_t *rev, char *cmd_str)
{
  int cmd;

  if (!rev)
    return;

  cmd = REV_NONE;
  if (0 == strcmp(cmd_str, "log"))
    cmd = REV_LOG;
  else if (0 == strcmp(cmd_str, "add"))
    cmd = REV_ADD;
  else if (0 == strcmp(cmd_str, "checkout"))
    cmd = REV_CHECKOUT;
  else if (0 == strcmp(cmd_str, "diff"))
    cmd = REV_DIFF;
  else if (0 == strcmp(cmd_str, "commit"))
    cmd = REV_COMMIT;
  else if (0 == strcmp(cmd_str, "tag"))
    cmd = REV_TAG;
  else if (0 == strcmp(cmd_str, "branch"))
    cmd = REV_BRANCH;
  else if (0 == strcmp(cmd_str, "status"))
    cmd = REV_STATUS;
  else if (0 == strcmp(cmd_str, "cat"))
    cmd = REV_CAT;
  else if (0 == strcmp(cmd_str, "switch"))
    cmd = REV_SWITCH;
  else if (0 == strcmp(cmd_str, "revert"))
    cmd = REV_REVERT;

  rev_command_set(rev, cmd);

}

void rev_current_set(revop_t *r, shkey_t *kcur)
{

  memcpy(&r->rev_kcur, kcur, sizeof(shkey_t));
  strncpy(r->rev_hcur, shkey_hex(&r->rev_kcur), sizeof(r->rev_hcur) - 1);
#if 0
  r->rev_cur = shfs_inode(r->rev_base, r->rev_hcur, SHINODE_REVISION);
  r->rev_flags |= REVF_CURRENT;
#endif

}

void rev_current_setstr(revop_t *r, char *hash)
{
  shkey_t *key;

  key = shkey_hexgen(hash);
  rev_current_set(r, key);
  shkey_free(&key);

}

