<img width="1891" height="976" alt="image" src="https://github.com/user-attachments/assets/815e650c-27af-4991-bfc2-f101f62842a9" />


To create this, I did the following:
- De-compiled the leaked Odin4 binary with IDA 9.1 to a C++ reconstruction.
- Trained an AI on this code.
- Created an equivalent reconstruction of that code, ported to Python 3!

Quirks
- MD5 will only pass for AP, uncheck it if flashing BL, etc.

 Windows note:
- The windows version DOES require Zadig to set the USB driver of your Samsung device to libusbK.
