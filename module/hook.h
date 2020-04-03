#ifndef __AFL_SNAPSHOT_HOOK_H__
#define __AFL_SNAPSHOT_HOOK_H__

int  try_hook(const char *func_name, void *handler);
void unhook(const char *func_name);
void unhook_all(void);

#endif

