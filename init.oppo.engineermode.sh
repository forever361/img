#!/system/bin/sh

#################################
if [ -f /cache/engineermode_masterclear_flag ]; then
    setprop persist.sys.allcommode true
    setprop persist.allcommode true
    setprop persist.sys.oppo.usbactive true
    setprop persist.sys.adb.engineermode 0
    setprop persist.sys.usb.config diag,adb
    rm /cache/engineermode_masterclear_flag
fi
##################################


