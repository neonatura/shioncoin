







#ifndef __STRATUM__TASK_H__
#define __STRATUM__TASK_H__

/**
 * Maximum time-span before a task assigned to a stratum client expires.
 */
#define MAX_TASK_LIFESPAN 100 


/** */
void task_free(task_t **task_p);

/** */
task_t *stratum_task(unsigned int task_id);

int is_stratum_task_pending(int *ret_iface);

void stratum_task_gen(task_attr_t *attr);

task_t *task_init(task_attr_t *attr);

void stratum_task_weight(task_attr_t *attr);



#endif /* __STRATUM__TASK_H__ */

