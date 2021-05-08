#ifndef __FTRACE_UTIL_H
#define __FTRACE_UTIL_H

#include <linux/ftrace.h>
#include <linux/version.h>

// In 5.11+, ftrace hooks take ftrace_regs as argument.
// Hacky way to fix this for older kernels.
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,11,0)
typedef struct pt_regs* ftrace_regs_ptr;
#define ftrace_get_regs(reg_ptr) reg_ptr;
#define FTRACE_OPS_FL_RECURSION 0
#else
typedef struct ftrace_regs* ftrace_regs_ptr;
#define FTRACE_OPS_FL_RECURSION_SAFE 0
#endif

#endif /* __FTRACE_UTIL_H */
