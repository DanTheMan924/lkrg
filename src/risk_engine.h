#ifndef P_RISK_ENGINE_H
#define P_RISK_ENGINE_H


#include <linux/cred.h>
#include<linux/sched.h>
#include"task_info.h"

int process_risk_score(p_task_info *info);

#endif