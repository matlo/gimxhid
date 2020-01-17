/*
 Copyright (c) 2019 Mathieu Laurendeau <mat.lau@laposte.net>
 License: GPLv3
 */

#ifndef GHID_H_
#define GHID_H_

#include <gimxpoll/include/gpoll.h>

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

/*
 * \brief Structure representing a hid device.
 */
struct ghid_device;

/*
 * \brief Open a hid device.
 *
 * \param device_path  the path of the hid device to open.
 *
 * \return the identifier of the opened device (to be used in further operations), \
 * or -1 in case of failure (e.g. bad path, device already opened).
 */
struct ghid_device * ghid_open_path(const char * device_path);

/*
 * \brief Open a hid device.
 *
 * \param vendor   the vendor id of the hid device to open.
 * \param product  the product id of the hid device to open.
 *
 * \return the identifier of the opened device (to be used in further operations), \
 * or -1 in case of failure (e.g. no device found).
 */
struct ghid_device * ghid_open_ids(unsigned short vendor, unsigned short product);

/*
 * \brief Enumerate hid devices.
 *
 * \param vendor  the vendor id to look for
 * \param product the product id to look for (ignored if vendor is 0)
 *
 * \return the hid devices
 */
struct ghid_device_info * ghid_enumerate(unsigned short vendor, unsigned short product);

/*
 * \brief Free the memory allocated by ghid_enumerate.
 *
 * \param hid_devs  the hid devices returned by hidasync_enumerate
 */
void ghid_free_enumeration(struct ghid_device_info * devs);

/*
 * \brief Get info for a hid device.
 *
 * \param device  the identifier of the hid device
 *
 * \return the hid info
 */
const s_hid_info * ghid_get_hid_info(struct ghid_device * device);

/*
 * \brief Close a hid device.
 *
 * \param device  the identifier of the hid device to close.
 *
 * \return 0 in case of success, or -1 in case of failure (i.e. bad device identifier).
 */
int ghid_close(struct ghid_device * device);

/*
 * \brief Read from a hid device, with a timeout. Use this function in a synchronous context.
 *
 * \param device  the identifier of the hid device
 * \param buf     the buffer where to store the data
 * \param count   the maximum number of bytes to read
 * \param timeout the maximum time to wait, in milliseconds
 *
 * \return the number of bytes actually read
 */
int ghid_read_timeout(struct ghid_device * device, void * buf, unsigned int count, unsigned int timeout);

/*
 * \brief Register the device as an event source, and set the external callbacks. \
 * This function triggers an asynchronous context.
 *
 * \param device      the hid device
 * \param user        the user to pass to the external callback
 * \param callbacks   the device callbacks
 *
 * \return 0 in case of success, or -1 in case of error
 */
int ghid_register(struct ghid_device * device, void * user, const GHID_CALLBACKS * callbacks);

/*
 * \brief Read from a hid device, asynchronously.
 *
 * \param device the hid device
 *
 * \return 0 in case of success, or -1 in case of error
 */
int ghid_poll(struct ghid_device * device);

/*
 * \brief Send data to a hid device. Use this function in an asynchronous context.
 *
 * \param device  the identifier of the hid device
 * \param buf     the buffer containing the data to send
 * \param count   the maximum number of bytes to send
 *
 * \return -1 in case of error, 0 in case of pending write, or the number of bytes written
 */
int ghid_write(struct ghid_device * device, const void * buf, unsigned int count);

/*
 * \brief Write to a hid device, with a timeout. Use this function in a synchronous context.
 *
 * \param device  the identifier of the hid device
 * \param buf     the buffer containing the data to write
 * \param count   the number of bytes in buf
 * \param timeout the maximum time to wait for the completion, in milliseconds
 *
 * \return the number of bytes actually written (0 in case of timeout, -1 in case of error)
 */
int ghid_write_timeout(struct ghid_device * device, const void * buf, unsigned int count, unsigned int timeout);

#ifdef __cplusplus
}
#endif

#endif /* GHID_H_ */
