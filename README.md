# ✨ Sparkle-CDM ✨

This project provides a shared library implementing the OpenCDM interface. It
can be used by WebKitGTK and WPEWebKit to provide DRM streams playback through
EME and MSE.

A standalone [GStreamer decryptor](src/gst/decryptor.cpp) is also provided, to be used by native, non-Web,
applications. One potential use-case is playback of encrypted DASH streams. For 
demonstration purpose [a basic DASH player](examples/sample-player.c) is provided.

By itself the project only provides support for ClearKey decryption. This is not
advised for use in production though. However, as the framework is architectured
using a plugins system, it just loads plugins available at runtime and forwards
OpenCDM calls to the selected plugin.

A mock plugin is also provided, it is useful only for testing purposes. It
can be used as a skeleton for new plugins though. 

⚠️ 📢 We remind any user of this project that to use any DRM system, you should observe 
its license and have permission from the provider.
