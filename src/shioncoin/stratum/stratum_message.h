

int stratum_send_message(user_t *user, shjson_t *msg);
int stratum_send_difficulty(user_t *user);
int stratum_send_subscribe(user_t *user);
int stratum_send_error(user_t *user, int err_code);

