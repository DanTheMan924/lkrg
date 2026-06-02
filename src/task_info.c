#include <linux/cred.h>
#include<linux/sched.h>
#include "task_info.h"
#include"risk_engine.h"

void p_collect_task_info(struct task_struct *task, p_task_info *info)
{
    strscpy(info->comm, task->comm, sizeof(info->comm));
    info->pid = task->pid;
    info->tgid = task->tgid;
    info->parent_pid = task->real_parent->pid;
    info->uid = task->cred->uid;
    info->euid = task->cred->euid;
    info->state = task->__state;
    info->flags = task->flags;
    info->risk_score = process_risk_score(info);
}

void p_log_task_info(p_task_info *info)
{
    printk(KERN_INFO
       "LKRG: Suspicious task: comm=%s pid=%d tgid=%d ppid=%d risk_score=%d\n",
       info->comm,
       info->pid,
       info->tgid,
       info->parent_pid,
       info->risk_score);

    printk(KERN_INFO
       "      uid=%u euid=%u state=%ld flags=0x%x\n",
       __kuid_val(info->uid),
       __kuid_val(info->euid),
       info->state,
       info->flags);
}