//This file collects task information for risk analysis including process pid, uid, executible path, and more

#include <linux/cred.h>
#include<linux/sched.h>
#include "task_info.h"
#include"risk_engine.h"

//dependencies for exec_path:

#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/rcupdate.h>

void p_fill_task_exec_path(struct task_struct *task,
                           char *buf,
                           size_t buf_len)
{
    struct file *exe_file;
    char *tmp_buf;
    char *path;

    if (!task || !task->mm || !buf || !buf_len)
        return;

    buf[0] = '\0';

    rcu_read_lock();

    exe_file = rcu_dereference(task->mm->exe_file);

    if (exe_file)
        get_file(exe_file);

    rcu_read_unlock();

    if (!exe_file)
        return;

    tmp_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!tmp_buf) {
        fput(exe_file);
        return;
    }

    path = d_path(&exe_file->f_path, tmp_buf, PAGE_SIZE);

    if (!IS_ERR(path))
        strscpy(buf, path, buf_len);
    else
        strscpy(buf, "[path_error]", buf_len);

    kfree(tmp_buf);
    fput(exe_file);
}

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
    p_fill_task_exec_path(task, info->exe_path, sizeof(info->exe_path));
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
       printk(KERN_INFO "exe_path=%s\n", info->exe_path);
}