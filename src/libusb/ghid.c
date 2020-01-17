/*
 Copyright (c) 2019 Mathieu Laurendeau <mat.lau@laposte.net>
 License: GPLv3
 */

#include <ghid.h>
#include "gusbhid.h"
#include <gimxlog/include/glog.h>

GLOG_INST(GLOG_NAME)

struct ghid_device * ghid_open_path(const char * device_path) {

    return gusbhid_open_path(device_path);
}

struct ghid_device * ghid_open_ids(unsigned short vendor, unsigned short product) {

  return gusbhid_open_ids(vendor, product);
}

struct ghid_device_info * ghid_enumerate(unsigned short vendor, unsigned short product) {

    return gusbhid_enumerate(vendor, product);
}

void ghid_free_enumeration(struct ghid_device_info * hid_devs) {

    gusbhid_free_enumeration(hid_devs);
}

const s_hid_info * ghid_get_hid_info(struct ghid_device * device) {

    return gusbhid_get_hid_info(device);
}

int ghid_read_timeout(struct ghid_device * device, void * buf, unsigned int count, unsigned int timeout) {

  return gusbhid_read_timeout(device, buf, count, timeout);
}

int ghid_register(struct ghid_device * device, void * user, const GHID_CALLBACKS * callbacks) {
    
    return gusbhid_register(device, user, callbacks);
}

int ghid_poll(struct ghid_device * device) {

    return gusbhid_poll(device);
}

int ghid_write_timeout(struct ghid_device * device, const void * buf, unsigned int count, unsigned int timeout) {

    return gusbhid_write_timeout(device, buf, count, timeout);
}

int ghid_write(struct ghid_device * device, const void * buf, unsigned int count) {

    return gusbhid_write(device, buf, count);
}

int ghid_close(struct ghid_device * device) {

    return gusbhid_close(device);
}

