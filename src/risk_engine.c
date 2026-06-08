/*based on if conditions this file calculates a rough risk score for a process with the hope that this risk engine helps detect rootkits sooner.
In future implementations hopefully this would be customizable and also utalize threat intelegence like virus total*/

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
    if (!strcmp(info->comm, "netcat"))
    {
        score += 5;
    }
    if (info->exe_path[0] == '\0')
    {
        score += 10;
    }
    if (info->exe_path[0] != '\0') {
        if (strstr(info->exe_path, "/tmp/")     ||
        strstr(info->exe_path, "/var/tmp/") ||
        strstr(info->exe_path, "/dev/shm/"))
        {
            score += 20;
        }
    }
    if (info->flags & PF_KTHREAD)
    {
        score -= 20;
    }
    if (score < 0)
    score = 0;
    return score;
}