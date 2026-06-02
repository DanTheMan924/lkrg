#include "risk_engine.h"

int process_risk_score(p_task_info *info)
{
    int score = 0;
    if (info->euid.val == 0)
    {
        score += 25; //highest privilage level
    }
    if (info->uid.val != info->euid.val)
    {
        score += 15; //privilage transition
    }
    //if (!strncmp(info->exe_path, "/tmp/", 5))
    //{
        //score += 20;
    //}
    //if (!strncmp(info->exe_path, "/dev/shm/", 9))
    //{
        //score += 20;
    //}
    if (!strcmp(info->comm, "nmap"))
        {
        score += 5; //suspicious title
        }
    if (!strcmp(info->comm, "hydra"))
    {
        score += 5; //Suspicious title
    }
    if (info->flags & PF_KTHREAD)
    {
        score -= 20;
    }
    return score;
}