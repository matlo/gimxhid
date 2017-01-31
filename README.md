# gimxhid

The gimxhid library is a HID access library very similar to the HIDAPI library, except that it supports asynchronous IO.  
It currently lacks MAC OS support and does not support requests over the control endpoint.  
It has a compilation dependency on gimxpoll headers, and on gimxcommon source code.  

Compilation:

```
git clone https://github.com/matlo/gimxpoll.git
git clone https://github.com/matlo/gimxcommon.git
git clone https://github.com/matlo/gimxhid.git
cd gimxhid
CPPFLAGS="-I../" make
```
