#ifndef PIPE_H
#define PIPE_H

struct vfs_node;

int pipe_create(int *read_fd, int *write_fd);
int pipe_ioctl(struct vfs_node *node, unsigned long request, void *arg);

#endif
