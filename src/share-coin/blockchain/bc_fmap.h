
void bc_map_free(bc_map_t *map);

int bc_map_open(bc_t *bc, bc_map_t *map);

int bc_map_alloc(bc_t *bc, bc_map_t *map, bcsize_t len);

int bc_map_append(bc_t *bc, bc_map_t *map, void *raw_data, bcsize_t data_len);
int bc_map_write(bc_t *bc, bc_map_t *map, bcsize_t of, void *raw_data, bcsize_t data_len);

int bc_map_trunc(bc_t *bc, bc_map_t *map, bcsize_t len);

shkey_t *get_bcmap_lock(void);

unsigned int bc_fmap_total(bc_t *bc);

int bc_map_idle(bc_t *bc, bc_map_t *map);
