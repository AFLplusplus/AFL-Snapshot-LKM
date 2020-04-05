#ifndef __AFL_SNAPSHOT_ASSOCIATED_DATA_H__
#define __AFL_SNAPSHOT_ASSOCIATED_DATA_H__

#include "snapshot.h"
#include <linux/list.h>      // list_head
#include <linux/mm_types.h>  // mm_struct

// TODO(andrea) consider if use a radix tree to map mm_struct* -> mm_data*
// TODO(andrea) locks are needed here

struct mm_data {

  // what mm is this for?
  const struct mm_struct *mm;

  // what data we need for that mm
  struct snapshot ss;

  // list helper
  struct list_head l;

};

struct mm_data *get_mm_data(const struct mm_struct *mm);
struct mm_data *ensure_mm_data(const struct mm_struct *mm);
void            remove_mm_data(struct mm_data *data);

void clear_snapshot(struct mm_data *mm);
void set_had_snapshot(struct mm_data *mm);
void set_snapshot(struct mm_data *mm);
bool have_snapshot(struct mm_data *data);
bool had_snapshot(struct mm_data *data);

struct files_data {

  // what files_struct is this for?
  const struct files_struct *files;

  // what data we need for that mm_struct
  unsigned long *snapshot_open_fds;

  // list helper
  struct list_head l;

};

struct files_data *get_files_data(const struct files_struct *files);
struct files_data *ensure_files_data(const struct files_struct *files);
void               remove_files_data(struct files_data *data);

#endif

