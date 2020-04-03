#include <linux/list.h>  // list_for_each_entry
#include <linux/slab.h>  // kmalloc, GFP_*

#include "associated_data.h"
#include "snapshot.h"

// list of mm's we have data for
LIST_HEAD(mm_datas);

// get mm_data for the given mm, or NULL if not found
struct mm_data *get_mm_data(const struct mm_struct *mm) {

  struct mm_data *data = NULL;
  list_for_each_entry(data, &mm_datas, l) {

    if (data->mm == mm) { return data; }

  }

  return NULL;

}

// return a mm_data for the given mm, creating if necessary
struct mm_data *ensure_mm_data(const struct mm_struct *mm) {

  struct mm_data *data = get_mm_data(mm);
  if (data) { return data; }

  // XXX: this is academic code (tm) so if we run out of memory, too bad!
  data = kmalloc(sizeof(struct mm_data), GFP_KERNEL | __GFP_ZERO);

  INIT_LIST_HEAD(&data->l);
  data->mm = mm;

  list_add(&data->l, &mm_datas);

  return data;

}

void remove_mm_data(struct mm_data *data) {

  list_del(&data->l);

}

/*
 * from mm.h
 */
void clear_snapshot(struct mm_data *data) {

  data->ss.status &= ~SNAPSHOT_MADE;

}

void set_had_snapshot(struct mm_data *data) {

  data->ss.status |= SNAPSHOT_HAD;

}

void set_snapshot(struct mm_data *data) {

  data->ss.status |= SNAPSHOT_MADE;

}

bool have_snapshot(struct mm_data *data) {

  return !!(data->ss.status & SNAPSHOT_MADE);

}

bool had_snapshot(struct mm_data *data) {

  return !!(data->ss.status & SNAPSHOT_HAD);

}

// list of file_structs's we have data for
LIST_HEAD(files_datas);

// get mm_data for the given mm, or NULL if not found
struct files_data *get_files_data(const struct files_struct *files) {

  struct files_data *data = NULL;
  list_for_each_entry(data, &files_datas, l) {

    if (data->files == files) { return data; }

  }

  return NULL;

}

// return a files_data for the given files_struct, creating if necessary
struct files_data *ensure_files_data(const struct files_struct *files) {

  struct files_data *data = get_files_data(files);
  if (data) { return data; }

  data = kmalloc(sizeof(struct files_data), GFP_KERNEL | __GFP_ZERO);

  INIT_LIST_HEAD(&data->l);
  data->files = files;

  list_add(&data->l, &files_datas);

  return data;

}

void remove_files_data(struct files_data *data) {

  list_del(&data->l);

}

