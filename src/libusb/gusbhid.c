/*
 Copyright (c) 2019 Mathieu Laurendeau <mat.lau@laposte.net>
 License: GPLv3
 */

#include "gusbhid.h"
#include <gimxcommon/include/gerror.h>
#include <gimxcommon/include/glist.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <libusb-1.0/libusb.h>

#include <gimxlog/include/glog.h>

GLOG_GET(GLOG_NAME)

#define POLLIN      0x001
#define POLLOUT     0x004

#define OUT_TIMEOUT 20 // ms

typedef struct {
  int configuration;
  struct {
    int number;
    int alternateSetting;
  } interface;
  struct {
    struct {
      unsigned char address;
      unsigned short size;
    } in;
    struct {
      unsigned char address;
      unsigned short size;
    } out;
  } endpoints;
  s_hid_info hidInfo;
} s_config;

struct ghid_device {
  libusb_context * ctx;
  char * path;
  libusb_device_handle * devh;
  s_config config;
  GHID_CALLBACKS callbacks;
  void * user;
  struct libusb_transfer ** transfers;
  unsigned int transfers_nb;
  int closing; // do not process completed transfers when closing
  GLIST_LINK(struct ghid_device);
};

static GLIST_INST(struct ghid_device, usbhid_devices);

#if !defined(LIBUSB_API_VERSION) && !defined(LIBUSBX_API_VERSION)
static const char * LIBUSB_CALL libusb_strerror(enum libusb_error errcode)
{
  return libusb_error_name(errcode);
}
#endif

#define PRINT_ERROR_LIBUSB(libusbfunc,ret) \
    do { \
        if (GLOG_LEVEL(GLOG_NAME,ERROR)) { \
            fprintf(stderr, "%s:%d %s: %s failed with error: %s\n", __FILE__, __LINE__, __func__, libusbfunc, libusb_strerror(ret)); \
        } \
    } while (0)

static int add_transfer(struct libusb_transfer * transfer) {
  struct ghid_device * device = (struct ghid_device *) transfer->user_data;
  unsigned int i;
  for (i = 0; i < device->transfers_nb; ++i) {
    if (device->transfers[i] == transfer) {
      return 0;
    }
  }
  void * ptr = realloc(device->transfers, (device->transfers_nb + 1) * sizeof(*device->transfers));
  if (ptr) {
    device->transfers = ptr;
    device->transfers[device->transfers_nb] = transfer;
    device->transfers_nb++;
    return 0;
  } else {
    PRINT_ERROR_ALLOC_FAILED("realloc");
    return -1;
  }
}

static void remove_transfer(struct libusb_transfer * transfer) {
  struct ghid_device * device = (struct ghid_device *) transfer->user_data;
  unsigned int i;
  for (i = 0; i < device->transfers_nb; ++i) {
    if (device->transfers[i] == transfer) {
      memmove(device->transfers + i, device->transfers + i + 1, (device->transfers_nb - i - 1) * sizeof(*device->transfers));
      device->transfers_nb--;
      void * ptr = realloc(device->transfers, device->transfers_nb * sizeof(*device->transfers));
      if (ptr || !device->transfers_nb) {
        device->transfers = ptr;
      } else {
        PRINT_ERROR_ALLOC_FAILED("realloc");
      }
      free(transfer->buffer);
      libusb_free_transfer(transfer);
      break;
    }
  }
}

static char * make_path(libusb_device * dev, int interface_number, int interface_alt_setting) {
  uint8_t path[1 + 7] = { };
  int pathLen = sizeof(path) / sizeof(*path);
  static char str[(sizeof(path) / sizeof(*path) + 2) * 3];
  path[0] = libusb_get_bus_number(dev);
  int ret = libusb_get_port_numbers(dev, path + 1, pathLen - 1);
  if (ret < 0) {
    PRINT_ERROR_LIBUSB("libusb_get_port_numbers", ret);
    return NULL;
  }
  int i;
  for (i = 0; i < ret + 1; ++i) {
    snprintf(str + i * 3, sizeof(str) - i * 3, "%02x:", path[i]);
  }
  snprintf(str + i * 3, sizeof(str) - i * 3, "%02x:%02x", interface_number, interface_alt_setting);
  return str;
}

static struct ghid_device * add_device(const char * path, s_config * config, int print) {

  struct ghid_device * current = GLIST_BEGIN(usbhid_devices);
  while (current != GLIST_END(usbhid_devices)) {
    if(current->path && !strcmp(current->path, path)) {
      if(print) {
        PRINT_ERROR_OTHER("device already opened");
      }
      return NULL;
    }
    current = current->next;
  }
  struct ghid_device * device = calloc(1, sizeof(struct ghid_device));
  if (device == NULL) {
    PRINT_ERROR_ALLOC_FAILED("calloc");
    return NULL;
  }
  device->path = strdup(path);
  if (device->path == NULL) {
      PRINT_ERROR_OTHER("can't duplicate path");
      free(device);
      return NULL;
  }
  device->config = *config;
  GLIST_ADD(usbhid_devices, device);
  return device;
}

static int submit_transfer(struct libusb_transfer * transfer) {
  /*
   * Don't submit the transfer if it can't be added in the 'transfers' table.
   * Otherwise it would not be possible to cleanly cancel it.
   */
  int ret = add_transfer(transfer);

  if (ret != -1) {
    ret = libusb_submit_transfer(transfer);
    if (ret != LIBUSB_SUCCESS) {
      PRINT_ERROR_LIBUSB("libusb_submit_transfer", ret);
      remove_transfer(transfer);
      return -1;
    }
  }
  return ret;
}

static void usb_callback(struct libusb_transfer* transfer);

int gusbhid_poll(struct ghid_device * device) {

  unsigned int address = device->config.endpoints.in.address;
  unsigned int size = device->config.endpoints.in.size;

  unsigned char * buf = calloc(size, sizeof(char));
  if (buf == NULL) {

    PRINT_ERROR_ALLOC_FAILED("calloc");
    return -1;
  }

  struct libusb_transfer * transfer = libusb_alloc_transfer(0);
  if (transfer == NULL) {

    PRINT_ERROR_ALLOC_FAILED("libusb_alloc_transfer");
    free(buf);
    return -1;
  }

  libusb_fill_interrupt_transfer(transfer, device->devh, address, buf, size,
      (libusb_transfer_cb_fn) usb_callback, device, 0);

  return submit_transfer(transfer);
}

static void usb_callback(struct libusb_transfer* transfer) {

  struct ghid_device * device = (struct ghid_device *) transfer->user_data;

  if(device->closing == 1 || transfer->status == LIBUSB_TRANSFER_CANCELLED) {
    remove_transfer(transfer);
    return;
  }

  if (transfer->type == LIBUSB_TRANSFER_TYPE_INTERRUPT) {
    if (transfer->status == LIBUSB_TRANSFER_COMPLETED) {
      if (transfer->endpoint == device->config.endpoints.in.address) {
        device->callbacks.fp_read(device->user, transfer->buffer,
            transfer->actual_length);
      } else if (transfer->endpoint == device->config.endpoints.out.address) {
        device->callbacks.fp_write(device->user, transfer->actual_length);
      }
    } else {
      if (transfer->endpoint == device->config.endpoints.out.address
          || transfer->status != LIBUSB_TRANSFER_TIMED_OUT) {
        if (GLOG_LEVEL(GLOG_NAME,ERROR)) {
          fprintf(stderr, "libusb_transfer failed with status %s (endpoint=0x%02x)\n", libusb_error_name(transfer->status), transfer->endpoint);
        }
      }
      if (transfer->endpoint == device->config.endpoints.in.address) {
        device->callbacks.fp_read(device->user, NULL, -1);
      } else if (transfer->endpoint == device->config.endpoints.out.address) {
        device->callbacks.fp_write(device->user, -1);
      }
    }
  }

  remove_transfer(transfer);
}

int gusbhid_write_timeout(struct ghid_device * device, const void * buf, unsigned int count, unsigned int timeout) {

  if (device->config.endpoints.out.address == 0x00) {

    PRINT_ERROR_OTHER("the device has no HID OUT endpoint");
    return -1;
  }

  int transfered;

  int length = count;

  if (((unsigned char *) buf)[0] == 0x00) {
    --length;
    ++buf;
  }

  if (length > device->config.endpoints.out.size) {

    PRINT_ERROR_OTHER("incorrect write size");
    return -1;
  }

  int ret = libusb_interrupt_transfer(device->devh, device->config.endpoints.out.address,
      (void *) buf, length, &transfered, timeout);
  if (ret != LIBUSB_SUCCESS && ret != LIBUSB_ERROR_TIMEOUT) {

    PRINT_ERROR_LIBUSB("libusb_interrupt_transfer", ret);
    return -1;
  }

  return count;
}

int gusbhid_read_timeout(struct ghid_device * device, void * buf, unsigned int count, unsigned int timeout) {

  if (device->config.endpoints.in.address == 0x00) {

    PRINT_ERROR_OTHER("the device has no HID IN endpoint");
    return -1;
  }

  int transfered = 0;

  if (count > device->config.endpoints.in.size) {
    count = device->config.endpoints.in.size;
  }

  int ret = libusb_interrupt_transfer(device->devh, device->config.endpoints.in.address,
      (void *) buf, count, &transfered, timeout);
  if (ret != LIBUSB_SUCCESS && ret != LIBUSB_ERROR_TIMEOUT) {
    PRINT_ERROR_LIBUSB("libusb_interrupt_transfer", ret);
    return -1;
  }

  return transfered;
}

#ifdef WIN32
#define PACKED __attribute__((gcc_struct, packed))
#else
#define PACKED __attribute__((packed))
#endif

typedef struct
PACKED
{
  unsigned char bLength;
  unsigned char bDescriptorType;
  unsigned short bcdHID;
  unsigned char bCountryCode;
  unsigned char bNumDescriptors;
  unsigned char bReportDescriptorType;
  unsigned short wReportDescriptorLength;
} s_hid_descriptor;

static s_hid_info probe_hid(const unsigned char * extra, unsigned int extra_length) {

  s_hid_info hidInfo = { 0 };

  unsigned int pos;
  for (pos = 0; pos < extra_length && extra[pos]; pos += extra[pos]) {

    if (extra[pos] < sizeof(s_hid_descriptor)) {
      continue;
    }

    s_hid_descriptor * hidDescriptor = (s_hid_descriptor *) (extra + pos);

    if (hidDescriptor->bDescriptorType == LIBUSB_DT_HID && hidDescriptor->bReportDescriptorType == LIBUSB_DT_REPORT) {
      hidInfo.version = hidDescriptor->bcdHID;
      hidInfo.countryCode = hidDescriptor->bCountryCode;
      hidInfo.reportDescriptorLength = hidDescriptor->wReportDescriptorLength;
      return hidInfo;
    }
  }

  return hidInfo;
}

/*
 * Look for an interface that is from the HID class and that has at least one interrupt endpoint.
 * Return the following properties:
 * - bConfigurationValue
 * - bInterfaceNumber
 * - bAlternateSetting
 * - interrupt in endpoint: bEndpointAddress, wMaxPacketSize
 * - interrupt out endpoint: bEndpointAddress, wMaxPacketSize
 * - hid info (version, country, report descriptor)
 */
static s_config * probe_device(libusb_device * dev, struct libusb_device_descriptor * desc, unsigned int * config_nb) {

  s_config * configs = NULL;
  *config_nb = 0;

  int cfg;
  for (cfg = 0; cfg < desc->bNumConfigurations; ++cfg) {
    struct libusb_config_descriptor * configuration;
    int ret = libusb_get_config_descriptor(dev, cfg, &configuration);
    if (ret != LIBUSB_SUCCESS) {
      PRINT_ERROR_LIBUSB("libusb_get_config_descriptor", ret);
      break;
    }
    int itf;
    for (itf = 0; itf < configuration->bNumInterfaces; ++itf) {
      int alt;
      const struct libusb_interface * interface = configuration->interface + itf;
      for (alt = 0; alt < interface->num_altsetting; ++alt) {
        const struct libusb_interface_descriptor * interfaceDesc = interface->altsetting + alt;
        if (interfaceDesc->bInterfaceClass == LIBUSB_CLASS_HID) {
          void * ptr = realloc(configs, (*config_nb + 1) * sizeof(*configs));
          if (ptr == NULL) {
              PRINT_ERROR_ALLOC_FAILED("realloc");
              break;
          }
          configs = (s_config *) ptr;
          memset(configs + *config_nb, 0x00, sizeof(*configs));
          configs[*config_nb].configuration = configuration->bConfigurationValue;
          configs[*config_nb].interface.number = itf;
          configs[*config_nb].interface.alternateSetting = alt;
          configs[*config_nb].hidInfo = probe_hid(interfaceDesc->extra, interfaceDesc->extra_length);
          configs[*config_nb].hidInfo.vendor_id = desc->idVendor;
          configs[*config_nb].hidInfo.product_id = desc->idProduct;
          configs[*config_nb].hidInfo.bcdDevice = desc->bcdDevice;
          int ep;
          for (ep = 0; ep < interfaceDesc->bNumEndpoints; ++ep) {
            const struct libusb_endpoint_descriptor * endpoint = interfaceDesc->endpoint + ep;
            if ((endpoint->bmAttributes & 0b00000011) == LIBUSB_TRANSFER_TYPE_INTERRUPT) {
              if ((endpoint->bEndpointAddress & 0b10000000) == LIBUSB_ENDPOINT_IN) {
                if (configs[*config_nb].endpoints.in.address == 0) {
                  configs[*config_nb].endpoints.in.address = endpoint->bEndpointAddress;
                  configs[*config_nb].endpoints.in.size = endpoint->wMaxPacketSize;
                }
              } else {
                if (configs[*config_nb].endpoints.out.address == 0) {
                  configs[*config_nb].endpoints.out.address = endpoint->bEndpointAddress;
                  configs[*config_nb].endpoints.out.size = endpoint->wMaxPacketSize;
                }
              }
            }
          }
          ++(*config_nb);
        }
      }
    }
    libusb_free_config_descriptor(configuration);
  }

  return configs;
}

/*
 * This is a wrapper around libusb_get_string_descriptor_ascii.
 * If libusb_get_string_descriptor_ascii returns a timeout, it is called again.
 * libusb_get_string_descriptor_ascii can be called up to 5 times, thus the execution of this function can take up to 5s.
 */
static int get_string_descriptor_ascii(libusb_device_handle *dev, uint8_t desc_index, unsigned char *data, int length) {

  int ret;
  int i;
  for (i = 0; i < 5; ++i) {
    ret = libusb_get_string_descriptor_ascii(dev, desc_index, data, length);
    if (ret < 0) {
      if (ret != LIBUSB_ERROR_TIMEOUT) {
        PRINT_ERROR_LIBUSB("libusb_get_string_descriptor_ascii", ret);
        break;
      }
    } else {
      break;
    }
  }
  if (i == 5) {
    PRINT_ERROR_LIBUSB("libusb_get_string_descriptor_ascii", LIBUSB_ERROR_TIMEOUT);
  }
  return ret;
}

static int claim_device(struct ghid_device * device, libusb_device * dev, struct libusb_device_descriptor * desc) {

  int ret = libusb_open(dev, &device->devh);
  if (ret != LIBUSB_SUCCESS) {
    PRINT_ERROR_LIBUSB("libusb_open", ret);
    return -1;
  }

#if defined(LIBUSB_API_VERSION) || defined(LIBUSBX_API_VERSION)
  libusb_set_auto_detach_kernel_driver(device->devh, 1);
#else
#ifndef WIN32
  ret = libusb_kernel_driver_active(device->devh, 0);
  if(ret == 1)
  {
    ret = libusb_detach_kernel_driver(device->devh, 0);
    if(ret != LIBUSB_SUCCESS)
    {
      PRINT_ERROR_LIBUSB("libusb_detach_kernel_driver", ret);
      return -1;
    }
  }
  else if(ret != LIBUSB_SUCCESS)
  {
    PRINT_ERROR_LIBUSB("libusb_kernel_driver_active", ret);
    return -1;
  }
#endif
#endif
  int configuration;

  ret = libusb_get_configuration(device->devh, &configuration);
  if (ret != LIBUSB_SUCCESS) {
    PRINT_ERROR_LIBUSB("libusb_get_configuration", ret);
    return -1;
  }

  if (configuration != device->config.configuration) {
    //warning: this is a blocking function
    ret = libusb_set_configuration(device->devh, device->config.configuration);
    if (ret != LIBUSB_SUCCESS) {
      PRINT_ERROR_LIBUSB("libusb_set_configuration", ret);
      return -1;
    }
  }

  ret = libusb_claim_interface(device->devh, device->config.interface.number);
  if (ret != LIBUSB_SUCCESS) {
    PRINT_ERROR_LIBUSB("libusb_claim_interface", ret);
    return -1;
  }

  //warning: this is a blocking function
  ret = libusb_set_interface_alt_setting(device->devh, device->config.interface.number,
      device->config.interface.alternateSetting);
  if (ret != LIBUSB_SUCCESS) {
    PRINT_ERROR_LIBUSB("libusb_set_interface_alt_setting", ret);
    return -1;
  }

  s_hid_info * hidInfo = &device->config.hidInfo;
  if (hidInfo->reportDescriptorLength > 0) {
    hidInfo->reportDescriptor = calloc(hidInfo->reportDescriptorLength, sizeof(unsigned char));
    if (hidInfo->reportDescriptor == NULL) {
      PRINT_ERROR_ALLOC_FAILED("calloc");
      return -1;
    }
    ret = libusb_control_transfer(device->devh, LIBUSB_ENDPOINT_IN | LIBUSB_RECIPIENT_INTERFACE,
        LIBUSB_REQUEST_GET_DESCRIPTOR, (LIBUSB_DT_REPORT << 8) | 0, device->config.interface.number, hidInfo->reportDescriptor,
        hidInfo->reportDescriptorLength, 1000);
    if (ret < 0) {
      PRINT_ERROR_LIBUSB("libusb_control_transfer", ret);
      return -1;
    } else {
      hidInfo->reportDescriptorLength = ret;
    }
  }

  if (desc->iManufacturer != 0) {
    char manufacturerString[126] = "";
    ret = get_string_descriptor_ascii(device->devh, desc->iManufacturer,
        (unsigned char *) manufacturerString, sizeof(manufacturerString));
    // LIBUSB_ERROR_PIPE means device sent a STALL packet
    // device can have iManufacturer set but no descriptor
    if (ret < 0 && ret != LIBUSB_ERROR_PIPE) {
      return -1;
    }
    if (ret > 0) {
      hidInfo->manufacturerString = strdup(manufacturerString);
    }
  }

  if (desc->iProduct != 0) {
    char productString[126] = "";
    ret = get_string_descriptor_ascii(device->devh, desc->iProduct, (unsigned char *) productString,
        sizeof(productString));
    // LIBUSB_ERROR_PIPE means device sent a STALL packet
    // device can have iProduct set but no descriptor
    if (ret < 0 && ret != LIBUSB_ERROR_PIPE) {
      return -1;
    }
    if (ret > 0) {
      hidInfo->productString = strdup(productString);
    }
  }

  return 0;
}

struct ghid_device_info * gusbhid_enumerate(unsigned short vendor, unsigned short product) {

  struct ghid_device_info * devs = NULL;
  struct ghid_device_info * last = NULL;

  int ret = -1;

  static libusb_device** usb_devs = NULL;
  static ssize_t cnt = 0;
  int dev_i;

  libusb_context * ctx = NULL;

  ret = libusb_init(&ctx);
  if (ret != LIBUSB_SUCCESS) {
      PRINT_ERROR_LIBUSB("libusb_init", ret);
      return NULL;
  }
#if defined(WIN32) && (LIBUSB_API_VERSION >= 0x01000106)
  libusb_set_option(ctx, LIBUSB_OPTION_USE_USBDK);
#endif

  cnt = libusb_get_device_list(ctx, &usb_devs);
  if (cnt < 0) {
    PRINT_ERROR_LIBUSB("libusb_get_device_list", cnt);
    libusb_exit(ctx);
    return NULL;
  }

  for (dev_i = 0; dev_i < cnt; ++dev_i) {
    struct libusb_device_descriptor desc;
    ret = libusb_get_device_descriptor(usb_devs[dev_i], &desc);
    if (!ret) {
      if (vendor) {
        if (desc.idVendor != vendor) {
          continue;
        }
        if (product) {
          if (desc.idProduct != product) {
            continue;
          }
        }
      }

      unsigned int config_nb;
      s_config * configs = probe_device(usb_devs[dev_i], &desc, &config_nb);

      unsigned int config_i;
      for (config_i = 0; config_i < config_nb; ++config_i) {

          const char * spath = make_path(usb_devs[dev_i], configs[config_i].interface.number, configs[config_i].interface.alternateSetting);
          if (spath == NULL) {
            continue;
          }

          char * path = strdup(spath);
          if (path == NULL) {
            PRINT_ERROR_OTHER("strdup failed");
            continue;
          }

          void * ptr = malloc(sizeof(*devs));
          if (ptr == NULL) {
            PRINT_ERROR_ALLOC_FAILED("malloc");
            free(path);
            continue;
          }

          struct ghid_device_info * dev = ptr;

          dev->vendor_id = desc.idVendor;
          dev->product_id = desc.idProduct;
          dev->bcdDevice = desc.bcdDevice;
          dev->interface_number = configs[config_i].interface.number;
          dev->path = path;
          dev->next = NULL;

          if (devs == NULL) {
              devs = dev;
          } else {
              last->next = dev;
          }

          last = dev;
      }

      free(configs);
    }
  }

  libusb_free_device_list(usb_devs, 1);

  libusb_exit(ctx);

  return devs;
}

void gusbhid_free_enumeration(struct ghid_device_info * devs) {

    struct ghid_device_info * current = devs;
    while (current != NULL) {
        struct ghid_device_info * next = current->next;
        free(current->path);
        free(current);
        current = next;
    }
}

struct ghid_device * gusbhid_open_ids(unsigned short vendor, unsigned short product) {

  int ret = -1;

  static libusb_device** devs = NULL;
  static ssize_t cnt = 0;
  int dev_i;

  libusb_context * ctx = NULL;

  ret = libusb_init(&ctx);
  if (ret != LIBUSB_SUCCESS) {
      PRINT_ERROR_LIBUSB("libusb_init", ret);
      return NULL;
  }
#if defined(WIN32) && (LIBUSB_API_VERSION >= 0x01000106)
  libusb_set_option(ctx, LIBUSB_OPTION_USE_USBDK);
#endif

  cnt = libusb_get_device_list(ctx, &devs);
  if (cnt < 0) {
    PRINT_ERROR_LIBUSB("libusb_get_device_list", cnt);
    libusb_exit(ctx);
    return NULL;
  }

  for (dev_i = 0; dev_i < cnt; ++dev_i) {
    struct libusb_device_descriptor desc;
    ret = libusb_get_device_descriptor(devs[dev_i], &desc);
    if (!ret) {
      if (desc.idVendor == vendor && desc.idProduct == product) {

        unsigned int config_nb;
        s_config * configs = probe_device(devs[dev_i], &desc, &config_nb);

        unsigned int config_i;
        for (config_i = 0; config_i < config_nb; ++config_i) {

            const char * spath = make_path(devs[dev_i], configs[config_i].interface.number, configs[config_i].interface.alternateSetting);
            if (spath == NULL) {
              continue;
            }

            struct ghid_device * device = add_device(spath, configs + config_i, 0);
            if (device == NULL) {
              continue;
            }

            if (claim_device(device, devs[dev_i], &desc) != -1) {
              libusb_free_device_list(devs, 1);
              free(configs);
              device->ctx = ctx;
              return device;
            } else {
              gusbhid_close(device);
            }
        }

        free(configs);
      }
    }
  }

  libusb_free_device_list(devs, 1);

  libusb_exit(ctx);

  return NULL;
}

struct ghid_device * gusbhid_open_path(const char * path) {

  int ret = -1;

  static libusb_device** devs = NULL;
  static ssize_t cnt = 0;
  int dev_i;

  if (path == NULL) {
    PRINT_ERROR_OTHER("path is NULL");
    return NULL;
  }

  libusb_context * ctx = NULL;

  ret = libusb_init(&ctx);
  if (ret != LIBUSB_SUCCESS) {
      PRINT_ERROR_LIBUSB("libusb_init", ret);
      return NULL;
  }
#if defined(WIN32) && (LIBUSB_API_VERSION >= 0x01000106)
  libusb_set_option(ctx, LIBUSB_OPTION_USE_USBDK);
#endif

  cnt = libusb_get_device_list(ctx, &devs);
  if (cnt < 0) {
    PRINT_ERROR_LIBUSB("libusb_get_device_list", cnt);
    return NULL;
  }

  for (dev_i = 0; dev_i < cnt; ++dev_i) {
    struct libusb_device_descriptor desc;
    ret = libusb_get_device_descriptor(devs[dev_i], &desc);
    if (!ret) {
      unsigned int config_nb;
      s_config * configs = probe_device(devs[dev_i], &desc, &config_nb);
      unsigned int config_i;
      for (config_i = 0; config_i < config_nb; ++config_i) {
          const char * spath = make_path(devs[dev_i], configs[config_i].interface.number, configs[config_i].interface.alternateSetting);
          if (spath == NULL || strcmp(spath, path)) {
            continue;
          }

          struct ghid_device * device = add_device(path, configs + config_i, 0);
          if (device == NULL) {
            continue;
          }

          if (claim_device(device, devs[dev_i], &desc) != -1) {
            libusb_free_device_list(devs, 1);
            free(configs);
            device->ctx = ctx;
            return device;
          } else {
            gusbhid_close(device);
          }
      }
      free(configs);
    }
  }

  libusb_free_device_list(devs, 1);

  libusb_exit(ctx);

  return NULL;
}

const s_hid_info * gusbhid_get_hid_info(struct ghid_device * device) {

  return &device->config.hidInfo;
}

static int handle_events(void * user) {

  struct ghid_device * device = (struct ghid_device *) user;

  return libusb_handle_events_timeout_completed(device->ctx, &((struct timeval){ 0, 0 }), NULL);
}

static int close_callback(void * user) {

  struct ghid_device * device = (struct ghid_device *) user;

  return device->callbacks.fp_close(device->user);
}

static inline int pollfd_register(struct ghid_device * device, int fd, short events) {

    GPOLL_CALLBACKS callbacks = {
            .fp_read = (events & POLLIN) ? handle_events : NULL,
            .fp_write = (events & POLLOUT) ? handle_events : NULL,
            .fp_close = close_callback
    };

    return device->callbacks.fp_register(fd, device, &callbacks);
}

static void pollfd_added_cb (int fd, short events, void * user_data) {

  struct ghid_device * device = (struct ghid_device *) user_data;

  pollfd_register(device, fd, events);
}

static inline void pollfd_remove (struct ghid_device * device, int fd) {

  device->callbacks.fp_remove(fd);
}

static void pollfd_removed_cb (int fd, void * user_data) {

  struct ghid_device * device = (struct ghid_device *) user_data;

  pollfd_remove(device, fd);
}

static int set_notifiers(struct ghid_device * device, libusb_context * ctx) {

    int ret = 0;
    libusb_set_pollfd_notifiers(ctx, pollfd_added_cb, pollfd_removed_cb, device);
    const struct libusb_pollfd ** pollfds = libusb_get_pollfds(ctx);
    int i;
    for (i = 0; pollfds[i] != NULL && ret != -1; ++i) {
      ret = pollfd_register(device, pollfds[i]->fd, pollfds[i]->events);
    }
    free(pollfds);

    if (ret == -1) {
        // roll-back
        for (i = i - 1; i >= 0; --i) {
            pollfd_remove(device, pollfds[i]->fd);
        }
        libusb_set_pollfd_notifiers(ctx, NULL, NULL, NULL);
        return -1;
    }

    return 0;
}

int gusbhid_register(struct ghid_device * device, void * user, const GHID_CALLBACKS * callbacks) {

  if (callbacks->fp_read != NULL && device->config.endpoints.in.address == 0x00) {

    PRINT_ERROR_OTHER("the device has no HID IN endpoint");
    return -1;
  }

  if (callbacks->fp_register == NULL) {

    PRINT_ERROR_OTHER("fp_register is NULL");
    return -1;
  }

  if (callbacks->fp_remove == NULL) {

    PRINT_ERROR_OTHER("fp_remove is NULL");
    return -1;
  }

  // Checking the presence of a HID OUT endpoint is done in the gusbhid_write* functions.

  device->callbacks = *callbacks;

  if (set_notifiers(device, device->ctx) < 0) {
      memset(&device->callbacks, 0x00, sizeof(device->callbacks));
      return -1;
  }

  device->user = user;

  return 0;
}

/*
 * Cancel all pending transfers for a given device.
 */
static void cancel_transfers(struct ghid_device * device) {
  unsigned int i;
  for (i = 0; i < device->transfers_nb; ++i) {

    libusb_cancel_transfer(device->transfers[i]);
  }

  while (device->transfers_nb > 0) {

    if (libusb_handle_events(device->ctx) != LIBUSB_SUCCESS) {

      break;
    }
  }
}

int gusbhid_close(struct ghid_device * device) {

  device->closing = 1;

  if (device->devh) {

    cancel_transfers(device);

    libusb_release_interface(device->devh, device->config.interface.number); //warning: this is a blocking function
#if !defined(LIBUSB_API_VERSION) && !defined(LIBUSBX_API_VERSION)
#ifndef WIN32
        libusb_attach_kernel_driver(device->devh, 0);
#endif
#endif
    libusb_close(device->devh);
  }

  if (device->ctx != NULL) {
      libusb_exit(device->ctx);
  }

  free(device->path);
  free(device->config.hidInfo.reportDescriptor);
  free(device->config.hidInfo.manufacturerString);
  free(device->config.hidInfo.productString);

  GLIST_REMOVE(usbhid_devices, device);

  free(device);

  return 1;
}

int gusbhid_write(struct ghid_device * device, const void * buf, unsigned int count) {

  if (device->config.endpoints.out.address == 0x00) {

    PRINT_ERROR_OTHER("the device has no HID OUT endpoint");
    return -1;
  }

  if (device->callbacks.fp_write == NULL) {

    PRINT_ERROR_OTHER("missing write callback");
    return -1;
  }

  if (((unsigned char *) buf)[0] == 0x00) {
    --count;
    ++buf;
  }

  if (count > device->config.endpoints.out.size) {

    PRINT_ERROR_OTHER("incorrect write size");
    return -1;
  }

  unsigned char * buffer = malloc(count * sizeof(unsigned char));
  if (buffer == NULL) {

    PRINT_ERROR_ALLOC_FAILED("calloc");
    return -1;
  }

  memcpy(buffer, buf, count);

  struct libusb_transfer * transfer = libusb_alloc_transfer(0);
  if (transfer == NULL) {

    PRINT_ERROR_ALLOC_FAILED("libusb_alloc_transfer");
    free(buffer);
    return -1;
  }

  libusb_fill_interrupt_transfer(transfer, device->devh, device->config.endpoints.out.address,
      buffer, count, (libusb_transfer_cb_fn) usb_callback, (void *) (unsigned long) device, OUT_TIMEOUT);

  return submit_transfer(transfer);
}

