/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED BY BPFTOOL! */
#ifndef __RESTRICTFS_SKEL_H__
#define __RESTRICTFS_SKEL_H__

#include <errno.h>
#include <stdlib.h>
#include <bpf/libbpf.h>

#define BPF_SKEL_SUPPORTS_MAP_AUTO_ATTACH 1

struct restrictfs {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *inner_map;
		struct bpf_map *cgroup_hash;
		struct bpf_map *rodata;
	} maps;
	struct {
		struct bpf_program *restrict_filesystems;
	} progs;
	struct {
		struct bpf_link *restrict_filesystems;
	} links;

#ifdef __cplusplus
	static inline struct restrictfs *open(const struct bpf_object_open_opts *opts = nullptr);
	static inline struct restrictfs *open_and_load();
	static inline int load(struct restrictfs *skel);
	static inline int attach(struct restrictfs *skel);
	static inline void detach(struct restrictfs *skel);
	static inline void destroy(struct restrictfs *skel);
	static inline const void *elf_bytes(size_t *sz);
#endif /* __cplusplus */
};

static void
restrictfs__destroy(struct restrictfs *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
restrictfs__create_skeleton(struct restrictfs *obj);

static inline struct restrictfs *
restrictfs__open_opts(const struct bpf_object_open_opts *opts)
{
	struct restrictfs *obj;
	int err;

	obj = (struct restrictfs *)calloc(1, sizeof(*obj));
	if (!obj) {
		errno = ENOMEM;
		return NULL;
	}

	err = restrictfs__create_skeleton(obj);
	if (err)
		goto err_out;

	err = bpf_object__open_skeleton(obj->skeleton, opts);
	if (err)
		goto err_out;

	return obj;
err_out:
	restrictfs__destroy(obj);
	errno = -err;
	return NULL;
}

static inline struct restrictfs *
restrictfs__open(void)
{
	return restrictfs__open_opts(NULL);
}

static inline int
restrictfs__load(struct restrictfs *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct restrictfs *
restrictfs__open_and_load(void)
{
	struct restrictfs *obj;
	int err;

	obj = restrictfs__open();
	if (!obj)
		return NULL;
	err = restrictfs__load(obj);
	if (err) {
		restrictfs__destroy(obj);
		errno = -err;
		return NULL;
	}
	return obj;
}

static inline int
restrictfs__attach(struct restrictfs *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
restrictfs__detach(struct restrictfs *obj)
{
	bpf_object__detach_skeleton(obj->skeleton);
}

static inline const void *restrictfs__elf_bytes(size_t *sz);

static inline int
restrictfs__create_skeleton(struct restrictfs *obj)
{
	struct bpf_object_skeleton *s;
	struct bpf_map_skeleton *map __attribute__((unused));
	int err;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)	{
		err = -ENOMEM;
		goto err;
	}

	s->sz = sizeof(*s);
	s->name = "restrictfs";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 3;
	s->map_skel_sz = 24;
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt,
			sizeof(*s->maps) > 24 ? sizeof(*s->maps) : 24);
	if (!s->maps) {
		err = -ENOMEM;
		goto err;
	}

	map = (struct bpf_map_skeleton *)((char *)s->maps + 0 * s->map_skel_sz);
	map->name = "inner_map";
	map->map = &obj->maps.inner_map;

	map = (struct bpf_map_skeleton *)((char *)s->maps + 1 * s->map_skel_sz);
	map->name = "cgroup_hash";
	map->map = &obj->maps.cgroup_hash;

	map = (struct bpf_map_skeleton *)((char *)s->maps + 2 * s->map_skel_sz);
	map->name = "restrict.rodata";
	map->map = &obj->maps.rodata;

	/* programs */
	s->prog_cnt = 1;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs) {
		err = -ENOMEM;
		goto err;
	}

	s->progs[0].name = "restrict_filesystems";
	s->progs[0].prog = &obj->progs.restrict_filesystems;
	s->progs[0].link = &obj->links.restrict_filesystems;

	s->data = restrictfs__elf_bytes(&s->data_sz);

	obj->skeleton = s;
	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return err;
}

static inline const void *restrictfs__elf_bytes(size_t *sz)
{
	static const char data[] __attribute__((__aligned__(8))) = "\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x88\x20\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x1e\0\
\x01\0\x79\x17\0\0\0\0\0\0\x79\x16\x08\0\0\0\0\0\xb7\x01\0\0\0\0\0\0\x63\x1a\
\xf0\xff\0\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\x18\0\0\0\x85\
\0\0\0\x06\0\0\0\xbf\x61\0\0\0\0\0\0\x67\x01\0\0\x20\0\0\0\x77\x01\0\0\x20\0\0\
\0\x55\x01\x32\0\0\0\0\0\xb7\x01\0\0\0\0\0\0\x0f\x17\0\0\0\0\0\0\xbf\xa6\0\0\0\
\0\0\0\x07\x06\0\0\xf8\xff\xff\xff\xbf\x61\0\0\0\0\0\0\xb7\x02\0\0\x08\0\0\0\
\xbf\x73\0\0\0\0\0\0\x85\0\0\0\x71\0\0\0\xb7\x01\0\0\0\0\0\0\x79\xa3\xf8\xff\0\
\0\0\0\x0f\x13\0\0\0\0\0\0\xbf\x61\0\0\0\0\0\0\xb7\x02\0\0\x08\0\0\0\x85\0\0\0\
\x71\0\0\0\xb7\x01\0\0\0\0\0\0\x79\xa3\xf8\xff\0\0\0\0\x0f\x13\0\0\0\0\0\0\xbf\
\xa1\0\0\0\0\0\0\x07\x01\0\0\xf4\xff\xff\xff\xb7\x02\0\0\x04\0\0\0\x85\0\0\0\
\x71\0\0\0\x85\0\0\0\x50\0\0\0\x7b\x0a\xf8\xff\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\
\x02\0\0\xf8\xff\xff\xff\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\
\0\xbf\x07\0\0\0\0\0\0\xb7\x06\0\0\0\0\0\0\x15\x07\x13\0\0\0\0\0\xbf\xa2\0\0\0\
\0\0\0\x07\x02\0\0\xf0\xff\xff\xff\xbf\x71\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\x15\
\0\x0e\0\0\0\0\0\x61\x06\0\0\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xf4\xff\
\xff\xff\xbf\x71\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\x15\x06\x04\0\0\0\0\0\x18\x06\
\0\0\xff\xff\xff\xff\0\0\0\0\0\0\0\0\x15\0\x05\0\0\0\0\0\x05\0\x03\0\0\0\0\0\
\x18\x06\0\0\xff\xff\xff\xff\0\0\0\0\0\0\0\0\x55\0\x01\0\0\0\0\0\xb7\x06\0\0\0\
\0\0\0\xbf\x60\0\0\0\0\0\0\x95\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x47\x50\x4c\0\x4c\x53\x4d\x20\x70\x72\x6f\x67\x72\x61\x6d\x20\
\x69\x73\x20\x72\x75\x6e\x6e\x69\x6e\x67\x0a\0\x3e\0\0\0\x05\0\x08\0\x05\0\0\0\
\x14\0\0\0\x1a\0\0\0\x20\0\0\0\x26\0\0\0\x2e\0\0\0\x04\0\x18\x01\x51\0\x04\x18\
\x78\x01\x56\0\x04\x18\x70\x01\x57\0\x04\xc8\x02\xe8\x03\x01\x57\0\x04\xf8\x02\
\xa8\x03\x01\x50\0\x01\x11\x01\x25\x25\x13\x05\x03\x25\x72\x17\x10\x17\x1b\x25\
\x11\x1b\x12\x06\x73\x17\x74\x17\x8c\x01\x17\0\0\x02\x34\0\x03\x25\x49\x13\x3f\
\x19\x3a\x0b\x3b\x0b\x02\x18\0\0\x03\x13\x01\x03\x25\x0b\x0b\x3a\x0b\x3b\x0b\0\
\0\x04\x0d\0\x03\x25\x49\x13\x3a\x0b\x3b\x0b\x38\x0b\0\0\x05\x0f\0\x49\x13\0\0\
\x06\x01\x01\x49\x13\0\0\x07\x21\0\x49\x13\x37\x0b\0\0\x08\x24\0\x03\x25\x3e\
\x0b\x0b\x0b\0\0\x09\x24\0\x03\x25\x0b\x0b\x3e\x0b\0\0\x0a\x21\0\x49\x13\x37\
\x05\0\0\x0b\x21\0\x49\x13\0\0\x0c\x16\0\x49\x13\x03\x25\x3a\x0b\x3b\x0b\0\0\
\x0d\x34\0\x03\x25\x49\x13\x3a\x0b\x3b\x0b\x02\x18\0\0\x0e\x26\0\x49\x13\0\0\
\x0f\x2e\x01\0\0\x10\x34\0\x03\x25\x49\x13\x3a\x0b\x3b\x0b\0\0\x11\x15\x01\x49\
\x13\x27\x19\0\0\x12\x05\0\x49\x13\0\0\x13\x18\0\0\0\x14\x34\0\x03\x25\x49\x13\
\x3a\x0b\x3b\x05\0\0\x15\x0f\0\0\0\x16\x26\0\0\0\x17\x15\0\x49\x13\x27\x19\0\0\
\x18\x2e\x01\x03\x25\x3a\x0b\x3b\x0b\x27\x19\x49\x13\x20\x21\x01\0\0\x19\x05\0\
\x03\x25\x3a\x0b\x3b\x0b\x49\x13\0\0\x1a\x34\0\x03\x25\x3a\x0b\x3b\x0b\x49\x13\
\0\0\x1b\x0b\x01\0\0\x1c\x2e\x01\x11\x1b\x12\x06\x40\x18\x7a\x19\x03\x25\x3a\
\x0b\x3b\x0b\x27\x19\x49\x13\x3f\x19\0\0\x1d\x05\0\x02\x22\x03\x25\x3a\x0b\x3b\
\x0b\x49\x13\0\0\x1e\x1d\x01\x31\x13\x55\x23\x58\x0b\x59\x0b\x57\x0b\0\0\x1f\
\x05\0\x02\x22\x31\x13\0\0\x20\x34\0\x02\x18\x31\x13\0\0\x21\x34\0\x02\x22\x31\
\x13\0\0\x22\x0b\x01\x55\x23\0\0\0\x1b\x03\0\0\x05\0\x01\x08\0\0\0\0\x01\0\x1d\
\0\x01\x08\0\0\0\0\0\0\0\x02\x04\0\x02\0\0\x08\0\0\0\x0c\0\0\0\x0c\0\0\0\x02\
\x03\x36\0\0\0\0\x3a\x02\xa1\0\x03\x03\x18\0\x35\x04\x04\x60\0\0\0\0\x36\0\x04\
\x07\x79\0\0\0\0\x37\x08\x04\x08\x8b\0\0\0\0\x38\x10\x04\x09\x9c\0\0\0\0\x39\
\x18\0\x05\x65\0\0\0\x06\x71\0\0\0\x07\x75\0\0\0\x0d\0\x08\x05\x05\x04\x09\x06\
\x08\x07\x05\x7e\0\0\0\x06\x71\0\0\0\x0a\x75\0\0\0\0\x08\0\x05\x90\0\0\0\x06\
\x71\0\0\0\x07\x75\0\0\0\x04\0\x06\xa7\0\0\0\x0b\x75\0\0\0\0\x05\xac\0\0\0\x03\
\x0e\x20\0\x2e\x04\x04\xd6\0\0\0\0\x2f\0\x04\x07\xe7\0\0\0\0\x30\x08\x04\x0a\
\xf8\0\0\0\0\x31\x10\x04\x0b\xfd\0\0\0\0\x32\x18\0\x05\xdb\0\0\0\x06\x71\0\0\0\
\x07\x75\0\0\0\x02\0\x05\xec\0\0\0\x06\x71\0\0\0\x07\x75\0\0\0\x01\0\x05\x71\0\
\0\0\x05\x02\x01\0\0\x0c\x0a\x01\0\0\x0d\x01\x1f\x08\x0c\x07\x08\x0d\x0f\x19\
\x01\0\0\0\x67\x02\xa1\x01\x06\x25\x01\0\0\x07\x75\0\0\0\x04\0\x0e\x2a\x01\0\0\
\x08\x10\x06\x01\x02\x0e\xac\0\0\0\0\x33\x02\xa1\x02\x0f\x0d\x11\x46\x01\0\0\0\
\x47\x02\xa1\x03\0\x06\x25\x01\0\0\x07\x75\0\0\0\x18\0\x10\x12\x5a\x01\0\0\x02\
\xb1\x0e\x5f\x01\0\0\x05\x64\x01\0\0\x11\x75\x01\0\0\x12\x79\x01\0\0\x12\x7e\
\x01\0\0\x13\0\x08\x13\x05\x08\x05\x25\x01\0\0\x0c\x86\x01\0\0\x15\x01\x1b\x08\
\x14\x07\x04\x14\x16\x93\x01\0\0\x02\xfb\x0a\x0e\x98\x01\0\0\x05\x9d\x01\0\0\
\x11\x75\x01\0\0\x12\xb2\x01\0\0\x12\x7e\x01\0\0\x12\xb3\x01\0\0\0\x15\x05\xb8\
\x01\0\0\x16\x14\x17\xc2\x01\0\0\x02\x50\x08\x0e\xc7\x01\0\0\x05\xcc\x01\0\0\
\x17\x02\x01\0\0\x10\x18\xd9\x01\0\0\x02\x38\x0e\xde\x01\0\0\x05\xe3\x01\0\0\
\x11\xb2\x01\0\0\x12\xb2\x01\0\0\x12\xb3\x01\0\0\0\x05\xf8\x01\0\0\x03\x1f\x08\
\0\x2a\x04\x19\x07\x02\0\0\0\x2b\0\0\x05\x0c\x02\0\0\x03\x1e\x08\0\x26\x04\x1a\
\x1b\x02\0\0\0\x27\0\0\x05\x20\x02\0\0\x03\x1d\x08\0\x22\x04\x1b\x2f\x02\0\0\0\
\x23\0\0\x08\x1c\x07\x08\x18\x20\0\x40\x71\0\0\0\x19\x21\0\x40\x96\x02\0\0\x19\
\x1f\0\x40\xf3\x01\0\0\x19\x22\0\x40\x71\0\0\0\x1a\x23\0\x44\x9b\x02\0\0\x1a\
\x26\0\x44\x9b\x02\0\0\x1a\x27\0\x43\xab\x02\0\0\x1a\x2a\0\x44\xbb\x02\0\0\x1a\
\x2b\0\x44\xbb\x02\0\0\x1a\x2c\0\x42\x2f\x02\0\0\x1a\x0b\0\x44\xbb\x02\0\0\x1b\
\x1a\x2d\0\x4c\xb3\x01\0\0\0\0\x05\x0a\x01\0\0\x0c\xa3\x02\0\0\x25\x04\x1a\x0c\
\x86\x01\0\0\x24\x03\x2a\x0c\xb3\x02\0\0\x29\x04\x1b\x0c\x0a\x01\0\0\x28\x03\
\x30\x05\x9b\x02\0\0\x1c\x04\0\x02\0\0\x01\x5a\x2e\0\x40\x71\0\0\0\x1d\0\x21\0\
\x40\x96\x02\0\0\x1e\x33\x02\0\0\0\0\x40\x05\x1f\x02\x43\x02\0\0\x1f\x01\x4b\
\x02\0\0\x20\x02\x91\0\x53\x02\0\0\x20\x02\x91\x04\x5b\x02\0\0\x20\x02\x91\x08\
\x63\x02\0\0\x21\x03\x6b\x02\0\0\x21\x04\x73\x02\0\0\x22\x01\x20\x02\x91\x08\
\x8c\x02\0\0\0\0\0\0\x23\0\0\0\x05\0\x08\0\x02\0\0\0\x08\0\0\0\x10\0\0\0\x04\
\x18\x40\x04\x58\xe8\x03\0\x04\x80\x01\xf0\x01\x04\xf8\x01\x88\x02\0\xc0\0\0\0\
\x05\0\0\0\0\0\0\0\x27\0\0\0\x39\0\0\0\x84\0\0\0\x90\0\0\0\x95\0\0\0\x99\0\0\0\
\xad\0\0\0\xb9\0\0\0\xc2\0\0\0\xc9\0\0\0\xcd\0\0\0\xd3\0\0\0\xe6\0\0\0\xec\0\0\
\0\xf6\0\0\0\xff\0\0\0\x04\x01\0\0\x0c\x01\0\0\x1d\x01\0\0\x22\x01\0\0\x2f\x01\
\0\0\x35\x01\0\0\x4b\x01\0\0\x65\x01\0\0\x79\x01\0\0\x81\x01\0\0\x86\x01\0\0\
\x8e\x01\0\0\x9c\x01\0\0\xa8\x01\0\0\xae\x01\0\0\xb3\x01\0\0\xcc\x01\0\0\xd0\
\x01\0\0\xd4\x01\0\0\xd9\x01\0\0\xe4\x01\0\0\xed\x01\0\0\xfa\x01\0\0\x04\x02\0\
\0\x0f\x02\0\0\x18\x02\0\0\x22\x02\0\0\x2b\x02\0\0\x3c\x02\0\0\x40\x02\0\0\x55\
\x62\x75\x6e\x74\x75\x20\x63\x6c\x61\x6e\x67\x20\x76\x65\x72\x73\x69\x6f\x6e\
\x20\x31\x38\x2e\x31\x2e\x33\x20\x28\x31\x75\x62\x75\x6e\x74\x75\x31\x29\0\x72\
\x65\x73\x74\x72\x69\x63\x74\x66\x73\x2e\x6b\x65\x72\x6e\x2e\x63\0\x2f\x68\x6f\
\x6d\x65\x2f\x75\x70\x67\x61\x75\x74\x61\x6d\x76\x74\x2f\x43\x4c\x69\x6f\x6e\
\x50\x72\x6f\x6a\x65\x63\x74\x73\x2f\x4b\x65\x72\x6e\x65\x6c\x57\x69\x74\x68\
\x42\x70\x66\x50\x72\x6f\x67\x72\x61\x6d\x73\x2f\x62\x70\x66\x2d\x70\x72\x6f\
\x67\x73\x2f\x65\x6e\x66\x6f\x72\x63\x65\x6d\x65\x6e\x74\0\x63\x67\x72\x6f\x75\
\x70\x5f\x68\x61\x73\x68\0\x74\x79\x70\x65\0\x69\x6e\x74\0\x5f\x5f\x41\x52\x52\
\x41\x59\x5f\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x6d\x61\x78\x5f\x65\
\x6e\x74\x72\x69\x65\x73\0\x6b\x65\x79\x5f\x73\x69\x7a\x65\0\x76\x61\x6c\x75\
\x65\x73\0\x6b\x65\x79\0\x76\x61\x6c\x75\x65\0\x75\x6e\x73\x69\x67\x6e\x65\x64\
\x20\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\x5f\x5f\x75\x36\x34\0\x69\x6e\x6e\
\x65\x72\x5f\x6d\x61\x70\0\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x63\x68\x61\x72\0\
\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x62\x70\x66\x5f\x74\x72\x61\x63\x65\x5f\x70\x72\
\x69\x6e\x74\x6b\0\x6c\x6f\x6e\x67\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\
\x6e\x74\0\x5f\x5f\x75\x33\x32\0\x62\x70\x66\x5f\x70\x72\x6f\x62\x65\x5f\x72\
\x65\x61\x64\x5f\x6b\x65\x72\x6e\x65\x6c\0\x62\x70\x66\x5f\x67\x65\x74\x5f\x63\
\x75\x72\x72\x65\x6e\x74\x5f\x63\x67\x72\x6f\x75\x70\x5f\x69\x64\0\x62\x70\x66\
\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\x6d\0\x66\x5f\x69\
\x6e\x6f\x64\x65\0\x69\x5f\x73\x62\0\x73\x5f\x6d\x61\x67\x69\x63\0\x75\x6e\x73\
\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\0\x73\x75\x70\x65\x72\x5f\x62\x6c\x6f\
\x63\x6b\0\x69\x6e\x6f\x64\x65\0\x66\x69\x6c\x65\0\x5f\x5f\x5f\x5f\x72\x65\x73\
\x74\x72\x69\x63\x74\x5f\x66\x69\x6c\x65\x73\x79\x73\x74\x65\x6d\x73\0\x63\x74\
\x78\0\x72\x65\x74\0\x7a\x65\x72\x6f\0\x5f\x5f\x75\x69\x6e\x74\x33\x32\x5f\x74\
\0\x75\x69\x6e\x74\x33\x32\x5f\x74\0\x6d\x61\x67\x69\x63\x5f\x6e\x75\x6d\x62\
\x65\x72\0\x63\x67\x72\x6f\x75\x70\x5f\x69\x64\0\x5f\x5f\x75\x69\x6e\x74\x36\
\x34\x5f\x74\0\x75\x69\x6e\x74\x36\x34\x5f\x74\0\x6d\x61\x67\x69\x63\x5f\x6d\
\x61\x70\0\x69\x73\x5f\x61\x6c\x6c\x6f\x77\0\x72\x61\x77\x5f\x6d\x61\x67\x69\
\x63\x5f\x6e\x75\x6d\x62\x65\x72\0\x5f\x5f\x74\0\x72\x65\x73\x74\x72\x69\x63\
\x74\x5f\x66\x69\x6c\x65\x73\x79\x73\x74\x65\x6d\x73\0\x2c\0\0\0\x05\0\x08\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x9f\xeb\x01\0\x18\0\0\0\0\0\0\0\x20\x03\0\0\x20\x03\0\0\x15\x04\0\0\0\0\0\0\0\
\0\0\x02\x03\0\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\0\0\0\0\0\0\0\x03\
\0\0\0\0\x02\0\0\0\x04\0\0\0\x02\0\0\0\x05\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\
\0\0\0\0\0\0\0\x02\x06\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x01\
\0\0\0\0\0\0\0\0\0\0\x02\x02\0\0\0\0\0\0\0\0\0\0\x02\x09\0\0\0\x19\0\0\0\0\0\0\
\x08\x0a\0\0\0\x1f\0\0\0\0\0\0\x01\x08\0\0\0\x40\0\0\0\x32\0\0\0\x04\0\0\x04\
\x20\0\0\0\x3c\0\0\0\x01\0\0\0\0\0\0\0\x41\0\0\0\x05\0\0\0\x40\0\0\0\x4d\0\0\0\
\x07\0\0\0\x80\0\0\0\x51\0\0\0\x08\0\0\0\xc0\0\0\0\x32\0\0\0\0\0\0\x0e\x0b\0\0\
\0\x01\0\0\0\0\0\0\0\0\0\0\x02\x0e\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\
\x04\0\0\0\x0d\0\0\0\0\0\0\0\0\0\0\x02\x10\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\
\0\0\0\x04\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\x02\x12\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\
\0\x02\0\0\0\x04\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\x02\x0b\0\0\0\0\0\0\0\0\0\0\x03\
\0\0\0\0\x13\0\0\0\x04\0\0\0\0\0\0\0\x57\0\0\0\x04\0\0\x04\x18\0\0\0\x3c\0\0\0\
\x0d\0\0\0\0\0\0\0\x41\0\0\0\x0f\0\0\0\x40\0\0\0\x63\0\0\0\x11\0\0\0\x80\0\0\0\
\x6c\0\0\0\x14\0\0\0\xc0\0\0\0\x57\0\0\0\0\0\0\x0e\x15\0\0\0\x01\0\0\0\0\0\0\0\
\0\0\0\x02\x0a\0\0\0\0\0\0\0\x01\0\0\x0d\x02\0\0\0\x73\0\0\0\x17\0\0\0\x77\0\0\
\0\x01\0\0\x0c\x18\0\0\0\xc4\x01\0\0\x01\0\0\x04\x08\0\0\0\xc9\x01\0\0\x1b\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x02\x1c\0\0\0\x1e\x02\0\0\x01\0\0\x04\x08\0\0\0\x24\
\x02\0\0\x1d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02\x1e\0\0\0\x29\x02\0\0\x01\0\0\x04\
\x08\0\0\0\x35\x02\0\0\x1f\0\0\0\0\0\0\0\x3d\x02\0\0\0\0\0\x01\x08\0\0\0\x40\0\
\0\0\0\0\0\0\0\0\0\x0a\x21\0\0\0\xd0\x03\0\0\0\0\0\x01\x01\0\0\0\x08\0\0\x01\0\
\0\0\0\0\0\0\x03\0\0\0\0\x20\0\0\0\x04\0\0\0\x04\0\0\0\xd5\x03\0\0\0\0\0\x0e\
\x22\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x20\0\0\0\x04\0\0\0\x18\0\0\0\xde\
\x03\0\0\0\0\0\x0e\x24\0\0\0\0\0\0\0\xff\x03\0\0\x02\0\0\x0f\0\0\0\0\x0c\0\0\0\
\0\0\0\0\x20\0\0\0\x16\0\0\0\0\0\0\0\x20\0\0\0\x05\x04\0\0\x01\0\0\x0f\0\0\0\0\
\x25\0\0\0\0\0\0\0\x18\0\0\0\x0d\x04\0\0\x01\0\0\x0f\0\0\0\0\x23\0\0\0\0\0\0\0\
\x04\0\0\0\0\x69\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\x53\x49\x5a\x45\x5f\
\x54\x59\x50\x45\x5f\x5f\0\x5f\x5f\x75\x36\x34\0\x75\x6e\x73\x69\x67\x6e\x65\
\x64\x20\x6c\x6f\x6e\x67\x20\x6c\x6f\x6e\x67\0\x69\x6e\x6e\x65\x72\x5f\x6d\x61\
\x70\0\x74\x79\x70\x65\0\x6d\x61\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x6b\x65\
\x79\0\x76\x61\x6c\x75\x65\0\x63\x67\x72\x6f\x75\x70\x5f\x68\x61\x73\x68\0\x6b\
\x65\x79\x5f\x73\x69\x7a\x65\0\x76\x61\x6c\x75\x65\x73\0\x63\x74\x78\0\x72\x65\
\x73\x74\x72\x69\x63\x74\x5f\x66\x69\x6c\x65\x73\x79\x73\x74\x65\x6d\x73\0\x6c\
\x73\x6d\x2f\x66\x69\x6c\x65\x5f\x6f\x70\x65\x6e\0\x2f\x68\x6f\x6d\x65\x2f\x75\
\x70\x67\x61\x75\x74\x61\x6d\x76\x74\x2f\x43\x4c\x69\x6f\x6e\x50\x72\x6f\x6a\
\x65\x63\x74\x73\x2f\x4b\x65\x72\x6e\x65\x6c\x57\x69\x74\x68\x42\x70\x66\x50\
\x72\x6f\x67\x72\x61\x6d\x73\x2f\x62\x70\x66\x2d\x70\x72\x6f\x67\x73\x2f\x65\
\x6e\x66\x6f\x72\x63\x65\x6d\x65\x6e\x74\x2f\x72\x65\x73\x74\x72\x69\x63\x74\
\x66\x73\x2e\x6b\x65\x72\x6e\x2e\x63\0\x69\x6e\x74\x20\x42\x50\x46\x5f\x50\x52\
\x4f\x47\x28\x72\x65\x73\x74\x72\x69\x63\x74\x5f\x66\x69\x6c\x65\x73\x79\x73\
\x74\x65\x6d\x73\x2c\x20\x73\x74\x72\x75\x63\x74\x20\x66\x69\x6c\x65\x20\x2a\
\x66\x69\x6c\x65\x2c\x20\x69\x6e\x74\x20\x72\x65\x74\x29\0\x20\x20\x20\x20\x20\
\x20\x20\x20\x75\x69\x6e\x74\x33\x32\x5f\x74\x20\x2a\x76\x61\x6c\x75\x65\x2c\
\x20\x2a\x6d\x61\x67\x69\x63\x5f\x6d\x61\x70\x2c\x20\x6d\x61\x67\x69\x63\x5f\
\x6e\x75\x6d\x62\x65\x72\x2c\x20\x7a\x65\x72\x6f\x20\x3d\x20\x30\x2c\x20\x2a\
\x69\x73\x5f\x61\x6c\x6c\x6f\x77\x3b\0\x20\x20\x20\x20\x20\x20\x20\x20\x62\x70\
\x66\x5f\x70\x72\x69\x6e\x74\x6b\x28\x22\x4c\x53\x4d\x20\x70\x72\x6f\x67\x72\
\x61\x6d\x20\x69\x73\x20\x72\x75\x6e\x6e\x69\x6e\x67\x5c\x6e\x22\x29\x3b\0\x20\
\x20\x20\x20\x20\x20\x20\x20\x69\x66\x20\x28\x72\x65\x74\x20\x21\x3d\x20\x30\
\x29\0\x66\x69\x6c\x65\0\x66\x5f\x69\x6e\x6f\x64\x65\0\x30\x3a\x30\0\x20\x20\
\x20\x20\x20\x20\x20\x20\x42\x50\x46\x5f\x43\x4f\x52\x45\x5f\x52\x45\x41\x44\
\x5f\x49\x4e\x54\x4f\x28\x26\x6d\x61\x67\x69\x63\x5f\x6e\x75\x6d\x62\x65\x72\
\x2c\x20\x66\x69\x6c\x65\x2c\x20\x66\x5f\x69\x6e\x6f\x64\x65\x2c\x20\x69\x5f\
\x73\x62\x2c\x20\x73\x5f\x6d\x61\x67\x69\x63\x29\x3b\0\x69\x6e\x6f\x64\x65\0\
\x69\x5f\x73\x62\0\x73\x75\x70\x65\x72\x5f\x62\x6c\x6f\x63\x6b\0\x73\x5f\x6d\
\x61\x67\x69\x63\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x6c\x6f\x6e\x67\0\x20\
\x20\x20\x20\x20\x20\x20\x20\x63\x67\x72\x6f\x75\x70\x5f\x69\x64\x20\x3d\x20\
\x62\x70\x66\x5f\x67\x65\x74\x5f\x63\x75\x72\x72\x65\x6e\x74\x5f\x63\x67\x72\
\x6f\x75\x70\x5f\x69\x64\x28\x29\x3b\0\x20\x20\x20\x20\x20\x20\x20\x20\x6d\x61\
\x67\x69\x63\x5f\x6d\x61\x70\x20\x3d\x20\x62\x70\x66\x5f\x6d\x61\x70\x5f\x6c\
\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\x6d\x28\x26\x63\x67\x72\x6f\x75\x70\x5f\
\x68\x61\x73\x68\x2c\x20\x26\x63\x67\x72\x6f\x75\x70\x5f\x69\x64\x29\x3b\0\x20\
\x20\x20\x20\x20\x20\x20\x20\x69\x66\x20\x28\x21\x6d\x61\x67\x69\x63\x5f\x6d\
\x61\x70\x29\0\x20\x20\x20\x20\x20\x20\x20\x20\x69\x66\x20\x28\x28\x69\x73\x5f\
\x61\x6c\x6c\x6f\x77\x20\x3d\x20\x62\x70\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\
\x6b\x75\x70\x5f\x65\x6c\x65\x6d\x28\x6d\x61\x67\x69\x63\x5f\x6d\x61\x70\x2c\
\x20\x26\x7a\x65\x72\x6f\x29\x29\x20\x3d\x3d\x20\x4e\x55\x4c\x4c\x29\x20\x7b\0\
\x20\x20\x20\x20\x20\x20\x20\x20\x69\x66\x20\x28\x2a\x69\x73\x5f\x61\x6c\x6c\
\x6f\x77\x29\x20\x7b\0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
\x20\x20\x69\x66\x20\x28\x62\x70\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\
\x70\x5f\x65\x6c\x65\x6d\x28\x6d\x61\x67\x69\x63\x5f\x6d\x61\x70\x2c\x20\x26\
\x6d\x61\x67\x69\x63\x5f\x6e\x75\x6d\x62\x65\x72\x29\x20\x3d\x3d\x20\x4e\x55\
\x4c\x4c\x29\0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
\x69\x66\x20\x28\x62\x70\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\
\x65\x6c\x65\x6d\x28\x6d\x61\x67\x69\x63\x5f\x6d\x61\x70\x2c\x20\x26\x6d\x61\
\x67\x69\x63\x5f\x6e\x75\x6d\x62\x65\x72\x29\x20\x21\x3d\x20\x4e\x55\x4c\x4c\
\x29\0\x63\x68\x61\x72\0\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x5f\x5f\x5f\x5f\x72\
\x65\x73\x74\x72\x69\x63\x74\x5f\x66\x69\x6c\x65\x73\x79\x73\x74\x65\x6d\x73\
\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x2e\x6d\x61\x70\x73\0\x2e\x72\x6f\x64\x61\
\x74\x61\0\x6c\x69\x63\x65\x6e\x73\x65\0\0\0\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\
\x14\0\0\0\x14\0\0\0\x6c\x01\0\0\x80\x01\0\0\x3c\0\0\0\x08\0\0\0\x8c\0\0\0\x01\
\0\0\0\0\0\0\0\x19\0\0\0\x10\0\0\0\x8c\0\0\0\x16\0\0\0\0\0\0\0\x9a\0\0\0\xf7\0\
\0\0\x05\0\x01\0\x18\0\0\0\x9a\0\0\0\x36\x01\0\0\x34\x10\x01\0\x20\0\0\0\x9a\0\
\0\0\x7e\x01\0\0\x09\x1c\x01\0\x40\0\0\0\x9a\0\0\0\xf7\0\0\0\x05\0\x01\0\x58\0\
\0\0\x9a\0\0\0\xae\x01\0\0\x0d\x24\x01\0\x78\0\0\0\x9a\0\0\0\0\0\0\0\0\0\0\0\
\x80\0\0\0\x9a\0\0\0\xd5\x01\0\0\x09\x30\x01\0\xf0\0\0\0\x9a\0\0\0\0\0\0\0\0\0\
\0\0\xf8\0\0\0\x9a\0\0\0\xd5\x01\0\0\x09\x30\x01\0\x08\x01\0\0\x9a\0\0\0\x4b\
\x02\0\0\x15\x38\x01\0\x10\x01\0\0\x9a\0\0\0\x4b\x02\0\0\x13\x38\x01\0\x20\x01\
\0\0\x9a\0\0\0\0\0\0\0\0\0\0\0\x28\x01\0\0\x9a\0\0\0\x7c\x02\0\0\x15\x40\x01\0\
\x50\x01\0\0\x9a\0\0\0\xbf\x02\0\0\x0d\x44\x01\0\x60\x01\0\0\x9a\0\0\0\xd7\x02\
\0\0\x19\x50\x01\0\x78\x01\0\0\x9a\0\0\0\xd7\x02\0\0\x0d\x50\x01\0\x80\x01\0\0\
\x9a\0\0\0\x21\x03\0\0\x0d\x68\x01\0\x98\x01\0\0\x9a\0\0\0\0\0\0\0\0\0\0\0\xa8\
\x01\0\0\x9a\0\0\0\x21\x03\0\0\x0d\x68\x01\0\xc0\x01\0\0\x9a\0\0\0\x3a\x03\0\0\
\x15\x70\x01\0\xe0\x01\0\0\x9a\0\0\0\x85\x03\0\0\x15\x80\x01\0\xf0\x01\0\0\x9a\
\0\0\0\xf7\0\0\0\x05\0\x01\0\x10\0\0\0\x8c\0\0\0\x03\0\0\0\x60\0\0\0\x1a\0\0\0\
\xd1\x01\0\0\0\0\0\0\xa0\0\0\0\x1c\0\0\0\xd1\x01\0\0\0\0\0\0\xd0\0\0\0\x1e\0\0\
\0\xd1\x01\0\0\0\0\0\0\0\0\0\0\x0c\0\0\0\xff\xff\xff\xff\x04\0\x08\0\x08\x7c\
\x0b\0\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\x59\x01\0\0\x05\0\
\x08\0\x97\0\0\0\x08\x01\x01\xfb\x0e\x0d\0\x01\x01\x01\x01\0\0\0\x01\0\0\x01\
\x01\x01\x1f\x04\0\0\0\0\x4b\0\0\0\x6f\0\0\0\x89\0\0\0\x03\x01\x1f\x02\x0f\x05\
\x1e\x05\x9b\0\0\0\0\xc8\xd7\x76\x9b\xe3\x13\x30\x43\xb8\xef\x9f\x7c\x3c\x1f\
\x79\xef\xad\0\0\0\x01\xb8\x10\xf2\x70\x73\x3e\x10\x63\x19\xb6\x7e\xf5\x12\xc6\
\x24\x6e\xb8\0\0\0\x02\xc4\x54\x1a\xc9\xeb\x57\x75\xba\x77\x80\x51\xc9\x40\xb0\
\x3a\x18\xca\0\0\0\x03\xe1\x86\x5d\x9f\xe2\x9f\xe1\xb5\xce\xd5\x50\xb7\xba\x45\
\x8f\x9e\xd2\0\0\0\x03\x25\x6f\xca\xbb\xef\xa2\x7c\xa8\xcf\x5e\x6d\x37\x52\x5e\
\x6e\x16\x04\0\x05\x05\x0a\0\x09\x02\0\0\0\0\0\0\0\0\x03\x3f\x01\x06\x03\x40\
\x2e\x05\x34\x06\x03\xc4\0\x20\x05\x09\x23\x05\x05\x03\x79\x4a\x05\x0d\x03\x09\
\x3c\x06\x03\xb7\x7f\x20\x05\x09\x06\x03\xcc\0\x4a\x06\x03\xb4\x7f\x4a\x03\xcc\
\0\x20\x03\xb4\x7f\x58\x03\xcc\0\x20\x05\0\x03\xb4\x7f\x3c\x05\x09\x03\xcc\0\
\x20\x05\x15\x06\x30\x05\x13\x06\x20\x05\0\x03\xb2\x7f\x2e\x05\x15\x06\x03\xd0\
\0\x20\x06\x03\xb0\x7f\x4a\x05\x0d\x06\x03\xd1\0\x20\x06\x03\xaf\x7f\x20\x05\
\x19\x06\x03\xd4\0\x20\x05\x0d\x06\x3c\x06\x26\x05\0\x06\x03\xa6\x7f\x3c\x05\
\x0d\x03\xda\0\x2e\x03\xa6\x7f\x20\x05\x15\x06\x03\xdc\0\x2e\x06\x03\xa4\x7f\
\x2e\x06\x03\xe0\0\x2e\x06\x03\xa0\x7f\x20\x05\x05\x06\x03\xc0\0\x20\x02\x02\0\
\x01\x01\x2f\x68\x6f\x6d\x65\x2f\x75\x70\x67\x61\x75\x74\x61\x6d\x76\x74\x2f\
\x43\x4c\x69\x6f\x6e\x50\x72\x6f\x6a\x65\x63\x74\x73\x2f\x4b\x65\x72\x6e\x65\
\x6c\x57\x69\x74\x68\x42\x70\x66\x50\x72\x6f\x67\x72\x61\x6d\x73\x2f\x62\x70\
\x66\x2d\x70\x72\x6f\x67\x73\x2f\x65\x6e\x66\x6f\x72\x63\x65\x6d\x65\x6e\x74\0\
\x2e\x2e\x2f\x2e\x2e\x2f\x6c\x69\x6e\x75\x78\x2f\x75\x73\x72\x2f\x69\x6e\x63\
\x6c\x75\x64\x65\x2f\x61\x73\x6d\x2d\x67\x65\x6e\x65\x72\x69\x63\0\x2e\x2e\x2f\
\x2e\x2e\x2f\x6c\x69\x6e\x75\x78\x2f\x74\x6f\x6f\x6c\x73\x2f\x6c\x69\x62\x2f\
\x62\x70\x66\0\x2f\x75\x73\x72\x2f\x69\x6e\x63\x6c\x75\x64\x65\x2f\x62\x69\x74\
\x73\0\x72\x65\x73\x74\x72\x69\x63\x74\x66\x73\x2e\x6b\x65\x72\x6e\x2e\x63\0\
\x69\x6e\x74\x2d\x6c\x6c\x36\x34\x2e\x68\0\x62\x70\x66\x5f\x68\x65\x6c\x70\x65\
\x72\x5f\x64\x65\x66\x73\x2e\x68\0\x74\x79\x70\x65\x73\x2e\x68\0\x73\x74\x64\
\x69\x6e\x74\x2d\x75\x69\x6e\x74\x6e\x2e\x68\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\x34\x01\0\0\x04\0\xf1\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x22\0\0\0\x01\0\x08\0\0\0\
\0\0\0\0\0\0\x18\0\0\0\0\0\0\0\x67\x01\0\0\0\0\x03\0\xf0\x01\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x75\x01\0\0\0\0\x03\0\xd0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x6e\x01\0\
\0\0\0\x03\0\xe8\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x0a\x01\0\0\x01\0\x07\0\0\0\0\
\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\x03\0\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x03\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x09\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0a\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x03\0\x0d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x0e\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x10\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x03\0\x11\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x17\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x19\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\x03\0\x1b\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x84\0\0\0\x12\0\x03\0\0\
\0\0\0\0\0\0\0\0\x02\0\0\0\0\0\0\xf0\0\0\0\x11\0\x05\0\x20\0\0\0\0\0\0\0\x20\0\
\0\0\0\0\0\0\xc4\0\0\0\x11\0\x05\0\0\0\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x20\0\0\0\
\0\0\0\0\x01\0\0\0\x09\0\0\0\x28\x01\0\0\0\0\0\0\x01\0\0\0\x14\0\0\0\x38\0\0\0\
\0\0\0\0\x02\0\0\0\x15\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\x0b\0\0\0\x11\0\0\0\0\
\0\0\0\x03\0\0\0\x0d\0\0\0\x15\0\0\0\0\0\0\0\x03\0\0\0\x11\0\0\0\x1f\0\0\0\0\0\
\0\0\x03\0\0\0\x0f\0\0\0\x23\0\0\0\0\0\0\0\x03\0\0\0\x0c\0\0\0\x27\0\0\0\0\0\0\
\0\x03\0\0\0\x0a\0\0\0\x08\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x0c\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x10\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x14\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x18\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x1c\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x20\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x24\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x28\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x2c\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x30\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x34\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x38\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x3c\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x40\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x44\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x48\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x4c\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x50\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x54\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x58\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x5c\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x60\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x64\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x68\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x6c\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x70\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x74\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x78\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x7c\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x80\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x84\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x88\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x8c\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x90\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x94\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\x98\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x9c\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\xa0\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\xa4\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\xa8\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\xac\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\xb0\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\xb4\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\xb8\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\xbc\0\0\0\0\0\0\0\
\x03\0\0\0\x0e\0\0\0\xc0\0\0\0\0\0\0\0\x03\0\0\0\x0e\0\0\0\x08\0\0\0\0\0\0\0\
\x02\0\0\0\x14\0\0\0\x10\0\0\0\0\0\0\0\x02\0\0\0\x08\0\0\0\x18\0\0\0\0\0\0\0\
\x02\0\0\0\x15\0\0\0\x20\0\0\0\0\0\0\0\x02\0\0\0\x09\0\0\0\x28\0\0\0\0\0\0\0\
\x02\0\0\0\x02\0\0\0\xf4\x02\0\0\0\0\0\0\x04\0\0\0\x15\0\0\0\0\x03\0\0\0\0\0\0\
\x04\0\0\0\x14\0\0\0\x18\x03\0\0\0\0\0\0\x03\0\0\0\x09\0\0\0\x30\x03\0\0\0\0\0\
\0\x03\0\0\0\x08\0\0\0\x2c\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x40\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x50\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x60\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x70\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x80\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x90\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xa0\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\xb0\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xc0\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\xd0\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xe0\0\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\xf0\0\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\0\x01\0\0\0\0\0\0\
\x04\0\0\0\x02\0\0\0\x10\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x20\x01\0\0\0\0\0\
\0\x04\0\0\0\x02\0\0\0\x30\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x40\x01\0\0\0\0\
\0\0\x04\0\0\0\x02\0\0\0\x50\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x60\x01\0\0\0\
\0\0\0\x04\0\0\0\x02\0\0\0\x70\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x80\x01\0\0\
\0\0\0\0\x04\0\0\0\x02\0\0\0\x90\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xac\x01\0\
\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xbc\x01\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\xcc\x01\
\0\0\0\0\0\0\x04\0\0\0\x02\0\0\0\x14\0\0\0\0\0\0\0\x03\0\0\0\x10\0\0\0\x18\0\0\
\0\0\0\0\0\x02\0\0\0\x02\0\0\0\x22\0\0\0\0\0\0\0\x03\0\0\0\x12\0\0\0\x26\0\0\0\
\0\0\0\0\x03\0\0\0\x12\0\0\0\x2a\0\0\0\0\0\0\0\x03\0\0\0\x12\0\0\0\x2e\0\0\0\0\
\0\0\0\x03\0\0\0\x12\0\0\0\x3a\0\0\0\0\0\0\0\x03\0\0\0\x12\0\0\0\x4f\0\0\0\0\0\
\0\0\x03\0\0\0\x12\0\0\0\x64\0\0\0\0\0\0\0\x03\0\0\0\x12\0\0\0\x79\0\0\0\0\0\0\
\0\x03\0\0\0\x12\0\0\0\x8e\0\0\0\0\0\0\0\x03\0\0\0\x12\0\0\0\xab\0\0\0\0\0\0\0\
\x02\0\0\0\x02\0\0\0\x13\x15\x14\x07\x03\0\x2e\x64\x65\x62\x75\x67\x5f\x61\x62\
\x62\x72\x65\x76\0\x2e\x74\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\x2e\
\x65\x78\x74\0\x5f\x5f\x5f\x5f\x72\x65\x73\x74\x72\x69\x63\x74\x5f\x66\x69\x6c\
\x65\x73\x79\x73\x74\x65\x6d\x73\x2e\x5f\x5f\x5f\x5f\x66\x6d\x74\0\x2e\x64\x65\
\x62\x75\x67\x5f\x72\x6e\x67\x6c\x69\x73\x74\x73\0\x2e\x64\x65\x62\x75\x67\x5f\
\x6c\x6f\x63\x6c\x69\x73\x74\x73\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\
\x73\x74\x72\x5f\x6f\x66\x66\x73\x65\x74\x73\0\x2e\x72\x65\x6c\x2e\x6d\x61\x70\
\x73\0\x72\x65\x73\x74\x72\x69\x63\x74\x5f\x66\x69\x6c\x65\x73\x79\x73\x74\x65\
\x6d\x73\0\x2e\x64\x65\x62\x75\x67\x5f\x73\x74\x72\0\x2e\x64\x65\x62\x75\x67\
\x5f\x6c\x69\x6e\x65\x5f\x73\x74\x72\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\
\x5f\x61\x64\x64\x72\0\x69\x6e\x6e\x65\x72\x5f\x6d\x61\x70\0\x2e\x72\x65\x6c\
\x2e\x64\x65\x62\x75\x67\x5f\x69\x6e\x66\x6f\0\x2e\x72\x65\x6c\x6c\x73\x6d\x2f\
\x66\x69\x6c\x65\x5f\x6f\x70\x65\x6e\0\x63\x67\x72\x6f\x75\x70\x5f\x68\x61\x73\
\x68\0\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\x5f\x6c\x69\x63\
\x65\x6e\x73\x65\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x6c\x69\x6e\x65\
\0\x2e\x72\x65\x6c\x2e\x64\x65\x62\x75\x67\x5f\x66\x72\x61\x6d\x65\0\x72\x65\
\x73\x74\x72\x69\x63\x74\x66\x73\x2e\x6b\x65\x72\x6e\x2e\x63\0\x2e\x73\x74\x72\
\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\x62\0\x2e\x72\x6f\x64\x61\x74\x61\0\x2e\
\x72\x65\x6c\x2e\x42\x54\x46\0\x4c\x42\x42\x30\x5f\x37\0\x4c\x42\x42\x30\x5f\
\x36\0\x4c\x42\x42\x30\x5f\x35\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x46\x01\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x05\
\x1f\0\0\0\0\0\0\x7c\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x0f\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe2\0\0\0\
\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\x02\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xde\0\0\0\x09\0\0\0\x40\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x90\x18\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x1d\0\0\0\
\x03\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x7e\0\0\0\x01\0\0\0\x03\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x40\x02\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7a\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\xb0\x18\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x1d\0\0\0\x05\0\0\0\x08\0\0\0\
\0\0\0\0\x10\0\0\0\0\0\0\0\x0b\x01\0\0\x01\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x80\x02\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x56\x01\0\0\x01\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x84\x02\
\0\0\0\0\0\0\x18\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x53\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9c\x02\0\0\0\0\0\0\x42\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xde\x02\0\0\0\0\0\0\x7b\x01\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xd2\0\0\0\x01\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x59\x04\0\0\0\0\0\0\x1f\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xce\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\xc0\x18\0\0\0\0\0\0\x60\0\0\0\0\0\0\0\x1d\0\0\0\x0b\0\0\0\x08\0\0\
\0\0\0\0\0\x10\0\0\0\0\0\0\0\x43\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x78\x07\0\0\0\0\0\0\x27\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x67\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x9f\x07\0\0\0\
\0\0\0\xc4\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x63\
\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x20\x19\0\0\0\0\0\0\xf0\x02\
\0\0\0\0\0\0\x1d\0\0\0\x0e\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x99\0\0\0\
\x01\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x63\x08\0\0\0\0\0\0\x55\x02\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\xb8\0\0\0\x01\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb8\x0a\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb4\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x10\x1c\0\0\0\0\0\0\x50\0\0\0\0\0\0\0\x1d\0\0\0\x11\0\0\0\
\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x62\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\xe8\x0a\0\0\0\0\0\0\x4d\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x5e\x01\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x60\x1c\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x1d\0\0\0\x13\0\0\0\x08\0\0\0\0\0\0\0\
\x10\0\0\0\0\0\0\0\x19\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x38\x12\
\0\0\0\0\0\0\xdc\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\x15\0\0\0\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa0\x1c\0\0\0\0\0\0\
\xa0\x01\0\0\0\0\0\0\x1d\0\0\0\x15\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\
\x27\x01\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x18\x14\0\0\0\0\0\0\x28\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x23\x01\0\0\
\x09\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x1e\0\0\0\0\0\0\x20\0\0\0\0\0\
\0\0\x1d\0\0\0\x17\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x17\x01\0\0\x01\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x14\0\0\0\0\0\0\x5d\x01\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x13\x01\0\0\x09\0\0\0\x40\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x60\x1e\0\0\0\0\0\0\xa0\0\0\0\0\0\0\0\x1d\0\0\0\x19\
\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\xa4\0\0\0\x01\0\0\0\x30\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\x9d\x15\0\0\0\0\0\0\xe1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\
\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\xfc\0\0\0\x03\x4c\xff\x6f\0\0\0\x80\0\0\0\0\0\0\
\0\0\0\0\0\0\0\x1f\0\0\0\0\0\0\x05\0\0\0\0\0\0\0\x1d\0\0\0\0\0\0\0\x01\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x4e\x01\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x80\x16\0\0\0\0\0\0\x10\x02\0\0\0\0\0\0\x01\0\0\0\x13\0\0\0\x08\0\0\0\0\0\0\0\
\x18\0\0\0\0\0\0\0";

	*sz = sizeof(data) - 1;
	return (const void *)data;
}

#ifdef __cplusplus
struct restrictfs *restrictfs::open(const struct bpf_object_open_opts *opts) { return restrictfs__open_opts(opts); }
struct restrictfs *restrictfs::open_and_load() { return restrictfs__open_and_load(); }
int restrictfs::load(struct restrictfs *skel) { return restrictfs__load(skel); }
int restrictfs::attach(struct restrictfs *skel) { return restrictfs__attach(skel); }
void restrictfs::detach(struct restrictfs *skel) { restrictfs__detach(skel); }
void restrictfs::destroy(struct restrictfs *skel) { restrictfs__destroy(skel); }
const void *restrictfs::elf_bytes(size_t *sz) { return restrictfs__elf_bytes(sz); }
#endif /* __cplusplus */

__attribute__((unused)) static void
restrictfs__assert(struct restrictfs *s __attribute__((unused)))
{
#ifdef __cplusplus
#define _Static_assert static_assert
#endif
#ifdef __cplusplus
#undef _Static_assert
#endif
}

#endif /* __RESTRICTFS_SKEL_H__ */
