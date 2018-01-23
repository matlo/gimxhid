/*
 Copyright (c) 2016 Mathieu Laurendeau <mat.lau@laposte.net>
 License: GPLv3
 */

#ifndef GHID_H_

#define GHID_H_

#include <gimxpoll/include/gpoll.h>
#include <gimxlog/include/glog.h>

typedef int (* GHID_READ_CALLBACK)(void * user, const void * buf, int status);
typedef int (* GHID_WRITE_CALLBACK)(void * user, int status);
typedef int (* GHID_CLOSE_CALLBACK)(void * user);
#ifndef WIN32
typedef GPOLL_REGISTER_FD GHID_REGISTER_SOURCE;
typedef GPOLL_REMOVE_FD GHID_REMOVE_SOURCE;
#else
typedef GPOLL_REGISTER_HANDLE GHID_REGISTER_SOURCE;
typedef GPOLL_REMOVE_HANDLE GHID_REMOVE_SOURCE;
#endif

typedef struct {
    GHID_READ_CALLBACK fp_read;       // called on data reception
    GHID_WRITE_CALLBACK fp_write;     // called on write completion
    GHID_CLOSE_CALLBACK fp_close;     // called on failure
    GHID_REGISTER_SOURCE fp_register; // to register the device to event sources
    GHID_REMOVE_SOURCE fp_remove;     // to remove the device from event sources
} GHID_CALLBACKS;

#ifdef __cplusplus
extern "C" {
#endif

struct ghid_device_info {
  unsigned short vendor_id;
  unsigned short product_id;
  unsigned short bcdDevice;
  int interface_number;
  char * path;
  struct ghid_device_info * next;
};

typedef struct {
    unsigned short vendor_id;
    unsigned short product_id;
    unsigned short bcdDevice;
#ifndef WIN32
    unsigned short version;
    unsigned char countryCode;
    unsigned char * reportDescriptor;
    unsigned short reportDescriptorLength;
    char * manufacturerString;
    char * productString;
#endif
} s_hid_info;

struct ghid_device;

int ghid_init();
int ghid_exit();
struct ghid_device * ghid_open_path(const char * device_path);
struct ghid_device * ghid_open_ids(unsigned short vendor, unsigned short product);
struct ghid_device_info * ghid_enumerate(unsigned short vendor, unsigned short product);
void ghid_free_enumeration(struct ghid_device_info * devs);
const s_hid_info * ghid_get_hid_info(struct ghid_device * device);
int ghid_close(struct ghid_device * device);
int ghid_read_timeout(struct ghid_device * device, void * buf, unsigned int count, unsigned int timeout);
int ghid_register(struct ghid_device * device, void * user, const GHID_CALLBACKS * callbacks);
int ghid_poll(struct ghid_device * device);
int ghid_write(struct ghid_device * device, const void * buf, unsigned int count);
int ghid_write_timeout(struct ghid_device * device, const void * buf, unsigned int count, unsigned int timeout);

GLOG_SET_LOG_LEVEL(ghid)

#ifdef __cplusplus
}
#endif

#endif /* GHID_H_ */
