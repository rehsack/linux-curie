obj-$(CONFIG_MXC_HDMI_CEC)                  = mxc_hdmi-cec.o
obj-$(CONFIG_MXC_HDMI_CEC_SHR)              = mxc_hdmi-cec.o

ifneq ($(CONFIG_MXC_HDMI_CEC),)
mxc_hdmi-cec-objs := mxc_hdmi-cec-uni.o
endif

ifneq ($(CONFIG_MXC_HDMI_CEC_SHR),)
mxc_hdmi-cec-objs := mxc_hdmi-cec-shr.o
endif
