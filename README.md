# ✨ Sparkle-CDM ✨

This project provides a shared library implementing the OpenCDM interface. It
can be used by WebKitGTK and WPEWebKit to provide DRM streams playback through
EME and MSE.

By itself the project doesn't support any specific DRM system, it just loads
plugins and forwards OpenCDM calls to the selected plugin at runtime.

A mock plugin is provided, it is useful only for testing purposes. It can be
used as a skeleton for new plugins though.
