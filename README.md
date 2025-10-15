To create this, I did the following:
- De-compiled the leaked Odin4 binary with IDA 9.1 to a C++ reconstruction.
- Trained an AI on this code.
- Created an equivalent reconstruction of that code, ported to Python 3!

Quirks
- Reboot boots into download mode, you'll have to manually reboot it at this time after flashing
This is by design for multiple flashes.
- MD5 will only pass for AP, uncheck it for BL, etc.

 Windows note:
- The windows version DOES require Zadig to set the USB driver of your Samsung device to libusbK.
