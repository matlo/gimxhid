/*
 Copyright (c) 2016 Mathieu Laurendeau <mat.lau@laposte.net>
 License: GPLv3
 */

#ifndef GUSBHID_H_
#define GUSBHID_H_

#include "ghid.h"

struct ghid_device;

struct ghid_device * gusbhid_open_ids(unsigned short vendor, unsigned short product);
struct ghid_device_info * gusbhid_enumerate(unsigned short vendor, unsigned short product);
void gusbhid_free_enumeration(struct ghid_device_info * hid_devs);
struct ghid_device * gusbhid_open_path(const char * path);
const s_hid_info * gusbhid_get_hid_info(struct ghid_device * device);
int gusbhid_close(struct ghid_device * device);
int gusbhid_poll(struct ghid_device * device);
int gusbhid_read_timeout(struct ghid_device * device, void * buf, unsigned int count, unsigned int timeout);
int gusbhid_register(struct ghid_device * device, void * user, const GHID_CALLBACKS * callbacks);
int gusbhid_write(struct ghid_device * device, const void * buf, unsigned int count);
int gusbhid_write_timeout(struct ghid_device * device, const void * buf, unsigned int count, unsigned int timeout);

#endif /* GUSBHID_H_ */
