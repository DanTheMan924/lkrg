/*Basic implementation of process analysis modes
Future work described near the bottom of the file*/

#include <linux/kernel.h>

#include "modes.h"
#include "task_info.h"

static risk_mode_t current_mode = MODE_ALERT;

#define RISK_MEDIUM_THRESHOLD 20
#define RISK_HIGH_THRESHOLD   40

void set_risk_mode(risk_mode_t mode)
{
    current_mode = mode;
}

risk_mode_t get_risk_mode(void)
{
    return current_mode;
}

void evaluate_risk_response(p_task_info *info)
{
    if (!info)
        return;
    switch (current_mode) {
    case MODE_MONITOR:
        printk(KERN_INFO
               "LKRG: MONITOR mode pid=%d score=%d\n",
               info->pid,
               info->risk_score);
        break;
    case MODE_ALERT:
        if (info->risk_score >= RISK_MEDIUM_THRESHOLD) {
            printk(KERN_WARNING
                   "LKRG: ALERT mode triggered score=%d\n",
                   info->risk_score);
            p_log_task_info(info);
        }
        break;
    case MODE_ENFORCE:
        if (info->risk_score >= RISK_HIGH_THRESHOLD) {
            printk(KERN_ERR
                   "LKRG: ENFORCE mode triggered score=%d\n",
                   info->risk_score);
            p_log_task_info(info);
            /*
             * Future work:
             * terminate process
             * quarantine process
             * notify userspace daemon
             */
        }
        break;
    }
}