#ifndef TASK_INFO_H
#define TASK_INFO_H

#include <linux/types.h>
#include <linux/cred.h>
#include<linux/sched.h>



typedef struct p_task_info {
    char comm[16];
    pid_t pid;
    pid_t tgid;
    pid_t parent_pid;
    kuid_t uid;
    kuid_t euid;
    long state; 
    unsigned int flags;
    char exe_path[256];
    int risk_score; //is a process indicative of an existing rootkit?
} p_task_info;


void p_collect_task_info(struct task_struct *task, p_task_info *info);

void p_log_task_info(p_task_info *info);
#endif