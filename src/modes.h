#ifndef MODES_H
#define MODES_H

#include "task_info.h"

typedef enum {
    MODE_MONITOR = 0,
    MODE_ALERT,
    MODE_ENFORCE
} risk_mode_t;

void set_risk_mode(risk_mode_t mode);
risk_mode_t get_risk_mode(void);

void evaluate_risk_response(p_task_info *info);

#endif