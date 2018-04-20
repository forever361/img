#!/system/bin/sh
DATE=`date +%F-%H`
CURTIME=`date +%F-%H-%M-%S`
ROOT_AUTOTRIGGER_PATH=/sdcard/oppo_log
ROOT_TRIGGER_PATH=/sdcard/oppo_log/trigger
DATA_LOG_PATH=/data/oppo_log
CACHE_PATH=/cache/admin
config="$1"

function Preprocess(){
    mkdir -p $ROOT_AUTOTRIGGER_PATH
    mkdir -p  $ROOT_TRIGGER_PATH
}

function log_observer(){
    autostop=`getprop persist.sys.autostoplog`
    if [ x"${autostop}" = x"1" ]; then
        boot_completed=`getprop sys.boot_completed`
        sleep 10
        while [ x${boot_completed} != x"1" ];do
            sleep 10
            boot_completed=`getprop sys.boot_completed`
        done

        space_full=false
        while [ ${space_full} == false ];do
            sleep 60
            full_date=`date +%F-%H-%M`
            FreeSize=`df /data | grep /data | $XKIT awk '{print $4}'`
            isM=`echo ${FreeSize} | $XKIT awk '{ print index($1,"M")}'`
            if [ ${isM} = "0" ]; then
                echo "$full_date left space ${FreeSize} more than 1G"
            else
                leftsize=`echo ${FreeSize} | $XKIT awk '{printf("%d",$1)}'`
                if [ $leftsize -le 300 ];then
                    space_full=true
                    echo "$full_date leftspace $FreeSize is less than 300M,stop log" >> ${DATA_LOG_PATH}/log_history.txt
                    setprop persist.sys.assert.panic false
                    setprop ctl.stop logcatsdcard
                    setprop ctl.stop logcatradio
                    setprop ctl.stop logcatevent
                    setprop ctl.stop logcatkernel
                    setprop ctl.stop tcpdumplog
                    setprop ctl.stop fingerprintlog
                    setprop ctl.stop fplogqess
                fi
            fi
        done
    fi
}

function backup_unboot_log(){
    i=1
    while [ true ];do
        if [ ! -d /cache/unboot_$i ];then
            is_folder_empty=`ls $CACHE_PATH/*`
            if [ "$is_folder_empty" = "" ];then
                echo "folder is empty"
            else
                mv /cache/admin /cache/unboot_$i
            fi
            break
        else
            i=`$XKIT expr $i + 1`
        fi
        if [ $i -gt 5 ];then
            break
        fi
    done
}

function initcache(){
    panicenable=`getprop persist.sys.assert.panic`
    boot_completed=`getprop sys.boot_completed`
    if [ x"${panicenable}" = x"true" ] && [ x"${boot_completed}" != x"1" ]; then
        if [ ! -d /dev/log ];then
            mkdir -p /dev/log
            chmod -R 755 /dev/log
        fi
        is_admin_empty=`ls $CACHE_PATH | wc -l`
        if [ "$is_admin_empty" != "0" ];then
            backup_unboot_log
        fi
        mkdir -p ${CACHE_PATH}
        mkdir -p ${CACHE_PATH}/apps
        mkdir -p ${CACHE_PATH}/kernel
        mkdir -p ${CACHE_PATH}/netlog
        mkdir -p ${CACHE_PATH}/fingerprint
        setprop sys.oppo.collectcache.start true
    fi
}

function logcatcache(){
    panicenable=`getprop persist.sys.assert.panic`
    argtrue='true'
    if [ "${panicenable}" = "${argtrue}" ]; then
    /system/bin/logcat -f ${CACHE_PATH}/apps/android_boot.txt -r10240 -n 5 -v threadtime
    fi
}
function radiocache(){
    radioenable=`getprop persist.sys.assert.panic`
    argtrue='true'
    if [ "${radioenable}" = "${argtrue}" ]; then
    /system/bin/logcat -b radio -f ${CACHE_PATH}/apps/radio_boot.txt -r4096 -n 3 -v threadtime
    fi
}
function eventcache(){
    panicenable=`getprop persist.sys.assert.panic`
    argtrue='true'
    if [ "${panicenable}" = "${argtrue}" ]; then
    /system/bin/logcat -b events -f ${CACHE_PATH}/apps/events_boot.txt -r4096 -n 10 -v threadtime
    fi
}
function kernelcache(){
  panicenable=`getprop persist.sys.assert.panic`
  argtrue='true'
  if [ "${panicenable}" = "${argtrue}" ]; then
  /system/xbin/klogd -f ${CACHE_PATH}/kernel/kinfo_boot0.txt -n -x -l 7
  fi
}
function tcpdumpcache(){
    tcpdmpenable=`getprop persist.sys.assert.panic`
    argtrue='true'
    if [ "${tcpdmpenable}" = "${argtrue}" ]; then
        system/xbin/tcpdump -i any -p -s 0 -W 2 -C 10 -w ${CACHE_PATH}/netlog/tcpdump_boot -Z root
    fi
}

function fingerprintcache(){
    cat /sys/kernel/debug/tzdbg/log > ${CACHE_PATH}/fingerprint/fingerprint_boot.txt
}

function fplogcache(){
    cat /sys/kernel/debug/tzdbg/qsee_log > ${CACHE_PATH}/fingerprint/qsee_boot.txt
}

function PreprocessLog(){
    panicenable=`getprop persist.sys.assert.panic`
    argtrue='true'
    if [ "${panicenable}" = "${argtrue}" ]; then
        boot_completed=`getprop sys.boot_completed`
        decrypt_delay=0
        while [ x${boot_completed} != x"1" ];do
            sleep 1
            decrypt_delay=`expr $decrypt_delay + 1`
            boot_completed=`getprop sys.boot_completed`
        done
        if [ ! -d /dev/log ];then
            mkdir -p /dev/log
            chmod -R 755 /dev/log
        fi
        LOGTIME=`date +%F-%H-%M`
        ROOT_SDCARD_LOG_PATH=${DATA_LOG_PATH}/${LOGTIME}
        ROOT_SDCARD_apps_LOG_PATH=${ROOT_SDCARD_LOG_PATH}/apps
        ROOT_SDCARD_kernel_LOG_PATH=${ROOT_SDCARD_LOG_PATH}/kernel
        ROOT_SDCARD_netlog_LOG_PATH=${ROOT_SDCARD_LOG_PATH}/netlog
        ROOT_SDCARD_FINGERPRINTERLOG_PATH=${ROOT_SDCARD_LOG_PATH}/fingerprint
        ASSERT_PATH=${ROOT_SDCARD_LOG_PATH}/oppo_assert
        TOMBSTONE_PATH=${ROOT_SDCARD_LOG_PATH}/tombstone
        ANR_PATH=${ROOT_SDCARD_LOG_PATH}/anr
        mkdir -p  ${ROOT_SDCARD_LOG_PATH}
        mkdir -p  ${ROOT_SDCARD_apps_LOG_PATH}
        mkdir -p  ${ROOT_SDCARD_kernel_LOG_PATH}
        mkdir -p  ${ROOT_SDCARD_netlog_LOG_PATH}
        mkdir -p  ${ROOT_SDCARD_FINGERPRINTERLOG_PATH}
        mkdir -p  ${ASSERT_PATH}
        mkdir -p  ${TOMBSTONE_PATH}
        mkdir -p  ${ANR_PATH}
        chmod -R 777 ${ROOT_SDCARD_LOG_PATH}
        echo ${LOGTIME} >> /data/oppo_log/log_history.txt
        echo ${LOGTIME} >> /data/oppo_log/transfer_list.txt
        decrypt=`getprop com.oppo.decrypt`
        if [ x"${decrypt}" != x"true" ]; then
            setprop ctl.stop logcatcache
            setprop ctl.stop radiocache
            setprop ctl.stop eventcache
            setprop ctl.stop kernelcache
            setprop ctl.stop fingerprintcache
            setprop ctl.stop fplogcache
            setprop ctl.stop tcpdumpcache
            mv ${CACHE_PATH}/* ${ROOT_SDCARD_LOG_PATH}/
            mv /cache/unboot_* ${ROOT_SDCARD_LOG_PATH}/
            setprop com.oppo.decrypt true
        fi
        setprop com.oppo.debug.time ${LOGTIME}
    fi
    setprop sys.oppo.collectlog.start true
    setprop sys.oppo.logkit.appslog ${ROOT_SDCARD_apps_LOG_PATH}
    setprop sys.oppo.logkit.kernellog ${ROOT_SDCARD_kernel_LOG_PATH}
    setprop sys.oppo.logkit.netlog ${ROOT_SDCARD_netlog_LOG_PATH}
    setprop sys.oppo.logkit.assertlog ${ASSERT_PATH}
    setprop sys.oppo.logkit.anrlog ${ANR_PATH}
    setprop sys.oppo.logkit.tombstonelog ${TOMBSTONE_PATH}
    setprop sys.oppo.logkit.fingerprintlog ${ROOT_SDCARD_FINGERPRINTERLOG_PATH}
}

function initLogPath(){
    FreeSize=`df /data | grep /data | $XKIT awk '{print $4}'`
    isM=`echo ${FreeSize} | $XKIT awk '{ print index($1,"M")}'`
if [ ${isM} = "0" ]; then
    androidSize=51200
    androidCount=`echo ${FreeSize} 30 50 ${androidSize} | $XKIT awk '{printf("%d",$1*$2*1024*1024/$3/$4)}'`
    radioSize=20480
    radioCount=`echo ${FreeSize} 1 50 ${radioSize} | $XKIT awk '{printf("%d",$1*$2*1024*1024/$3/$4)}'`
    eventSize=20480
    eventCount=`echo ${FreeSize} 1 50 ${eventSize} | $XKIT awk '{printf("%d",$1*$2*1024*1024/$3/$4)}'`
    tcpdumpSize=100
    tcpdumpCount=`echo ${FreeSize} 10 50 ${tcpdumpSize} | $XKIT awk '{printf("%d",$1*$2*1024/$3/$4)}'`
else
    androidSize=20480
    androidCount=`echo ${FreeSize} 30 50 ${androidSize} | $XKIT awk '{printf("%d",$1*$2*1024/$3/$4)}'`
    radioSize=10240
    radioCount=`echo ${FreeSize} 1 50 ${radioSize} | $XKIT awk '{printf("%d",$1*$2*1024/$3/$4)}'`
    eventSize=10240
    eventCount=`echo ${FreeSize} 1 50 ${eventSize} | $XKIT awk '{printf("%d",$1*$2*1024/$3/$4)}'`
    tcpdumpSize=50
    tcpdumpCount=`echo ${FreeSize} 10 50 ${tcpdumpSize} | $XKIT awk '{printf("%d",$1*$2/$3/$4)}'`
fi
    ROOT_SDCARD_apps_LOG_PATH=`getprop sys.oppo.logkit.appslog`
    ROOT_SDCARD_kernel_LOG_PATH=`getprop sys.oppo.logkit.kernellog`
    ROOT_SDCARD_netlog_LOG_PATH=`getprop sys.oppo.logkit.netlog`
    ASSERT_PATH=`getprop sys.oppo.logkit.assertlog`
    TOMBSTONE_PATH=`getprop sys.oppo.logkit.tombstonelog`
    ANR_PATH=`getprop sys.oppo.logkit.anrlog`
    ROOT_SDCARD_FINGERPRINTERLOG_PATH=`getprop sys.oppo.logkit.fingerprintlog`
}

function PreprocessOther(){
    mkdir -p  $ROOT_TRIGGER_PATH/${CURTIME}
    GRAB_PATH=$ROOT_TRIGGER_PATH/${CURTIME}
}

function Logcat(){
    panicenable=`getprop persist.sys.assert.panic`
    argtrue='true'
    if [ "${panicenable}" = "${argtrue}" ]; then
    /system/bin/logcat -f ${ROOT_SDCARD_apps_LOG_PATH}/android.txt -r${androidSize} -n ${androidCount}  -v threadtime  -A
    fi
}
function LogcatRadio(){
    radioenable=`getprop persist.sys.assert.panic`
    argtrue='true'
    if [ "${radioenable}" = "${argtrue}" ]; then
    /system/bin/logcat -b radio -f ${ROOT_SDCARD_apps_LOG_PATH}/radio.txt -r${radioSize} -n ${radioCount}  -v threadtime -A
    fi
}
function LogcatEvent(){
    panicenable=`getprop persist.sys.assert.panic`
    argtrue='true'
    if [ "${panicenable}" = "${argtrue}" ]; then
    /system/bin/logcat -b events -f ${ROOT_SDCARD_apps_LOG_PATH}/events.txt -r${eventSize} -n ${eventCount}  -v threadtime -A
    fi
}
function LogcatKernel(){
  panicenable=`getprop persist.sys.assert.panic`
  argtrue='true'
  if [ "${panicenable}" = "${argtrue}" ]; then
  /system/xbin/klogd -f - -n -x -l 7 | $XKIT tee - ${ROOT_SDCARD_kernel_LOG_PATH}/kinfo0.txt | $XKIT awk 'NR%400==0'
  fi
}
function tcpdumpLog(){
    tcpdmpenable=`getprop persist.sys.assert.panic`
    argtrue='true'
    if [ "${tcpdmpenable}" = "${argtrue}" ]; then
        system/xbin/tcpdump -i any -p -s 0 -W ${tcpdumpCount} -C ${tcpdumpSize} -w ${ROOT_SDCARD_netlog_LOG_PATH}/tcpdump -Z root
    fi
}
function grabNetlog(){

    /system/xbin/tcpdump -i any -p -s 0 -W 5 -C 10 -w /cache/admin/netlog/tcpdump.pcap -Z root

}

function LogcatFingerprint(){
    countfp=1
    while true
    do
        cat /sys/kernel/debug/tzdbg/log > ${ROOT_SDCARD_FINGERPRINTERLOG_PATH}/fingerprint_log${countfp}.txt
        if [ ! -s ${ROOT_SDCARD_FINGERPRINTERLOG_PATH}/fingerprint_log${countfp}.txt ];then
        rm ${ROOT_SDCARD_FINGERPRINTERLOG_PATH}/fingerprint_log${countfp}.txt;
        fi
        ((countfp++))
        sleep 1
    done
}

function LogcatFingerprintQsee(){
    countqsee=1
    while true
    do
        cat /sys/kernel/debug/tzdbg/qsee_log > ${ROOT_SDCARD_FINGERPRINTERLOG_PATH}/qsee_log${countqsee}.txt
        if [ ! -s ${ROOT_SDCARD_FINGERPRINTERLOG_PATH}/qsee_log${countqsee}.txt ];then
        rm ${ROOT_SDCARD_FINGERPRINTERLOG_PATH}/qsee_log${countqsee}.txt;
        fi
        ((countqsee++))
        sleep 1
    done
}

function screen_record(){
    ROOT_SDCARD_RECORD_LOG_PATH=${ROOT_AUTOTRIGGER_PATH}/screen_record
    mkdir -p  ${ROOT_SDCARD_RECORD_LOG_PATH}
    /system/bin/screenrecord  --time-limit 1800 --verbose ${ROOT_SDCARD_RECORD_LOG_PATH}/screen_record.mp4
}

function Dmesg(){
    mkdir -p  $ROOT_TRIGGER_PATH/${CURTIME}
    dmesg > $ROOT_TRIGGER_PATH/${CURTIME}/dmesg.txt;
}
function Dumpsys(){
    mkdir -p  $ROOT_TRIGGER_PATH/${CURTIME}_dumpsys
    dumpsys > $ROOT_TRIGGER_PATH/${CURTIME}_dumpsys/dumpsys.txt;
}
function Dumpstate(){
    mkdir -p  $ROOT_TRIGGER_PATH/${CURTIME}_dumpstate
    dumpstate > $ROOT_TRIGGER_PATH/${CURTIME}_dumpstate/dumpstate.txt
}
function Top(){
    mkdir -p  $ROOT_TRIGGER_PATH/${CURTIME}_top
    top -n 1 > $ROOT_TRIGGER_PATH/${CURTIME}_top/top.txt;
}
function Ps(){
    mkdir -p  $ROOT_TRIGGER_PATH/${CURTIME}_ps
    ps > $ROOT_TRIGGER_PATH/${CURTIME}_ps/ps.txt;
}

function Server(){
    mkdir -p  $ROOT_TRIGGER_PATH/${CURTIME}_servelist
    service list  > $ROOT_TRIGGER_PATH/${CURTIME}_servelist/serviceList.txt;
}

function DumpEnvironment(){
    rm  -rf /cache/environment
    umask 000
    mkdir -p /cache/environment
    ps > /cache/environment/ps.txt &
    mount > /cache/environment/mount.txt &
    getprop > /cache/environment/prop.txt &
    /system/bin/dmesg > /cache/environment/dmesg.txt &
    /system/bin/logcat -d -v threadtime > /cache/environment/android.txt &
    /system/bin/logcat -b radio -d -v threadtime > /cache/environment/radio.txt &
    /system/bin/logcat -b events -d -v threadtime > /cache/environment/events.txt &
    i=`ps | grep system_server | $XKIT awk '{printf $2}'`
    ls /proc/$i/fd -al > /cache/environment/system_server_fd.txt &
    ps -t $i > /cache/environment/system_server_thread.txt &
    cp -rf /data/system/packages.xml /cache/environment/packages.xml
    chmod +r /cache/environment/packages.xml
    cat /proc/meminfo > /cache/environment/proc_meminfo.txt &
    cat /d/ion/heaps/system > /cache/environment/iom_system_heaps.txt &
    wait
    setprop sys.dumpenvironment.finished 1
    umask 077
}

function CleanAll(){
    rm -rf /cache/admin
    rm -rf /sdcard/oppo_log/*-*
    rm -rf /sdcard/oppo_log/log_history.txt
    rm -rf /sdcard/oppo_log/*.hprof
    rm -rf /sdcard/oppo_log/*.gz
    rm -rf /sdcard/oppo_log/xlog
    rm -rf /data/oppo_log/*
    rm -rf /data/anr/*
    rm -rf /data/tombstones/*
    rm -rf /data/system/dropbox/*
    #can not delete the junk_logs path, kernel needed
    mkdir -p /data/oppo_log/junk_logs/kernel
    mkdir -p /data/oppo_log/junk_logs/ftrace
    mkdir -p /data/oppo_log/junk_logs
    chmod -R 777 /data/oppo_log/junk_logs
}

function tranfer(){
    mkdir -p /sdcard/oppo_log
    mkdir -p /sdcard/oppo_log/compress_log
    chmod -R 777 /data/oppo_log/*
    cat /data/oppo_log/log_history.txt >> /sdcard/oppo_log/log_history.txt
    mv /data/oppo_log/transfer_list.txt  /sdcard/oppo_log/transfer_list.txt
    rm -rf /data/oppo_log/log_history.txt
    mv /data/oppo_log/* /data/media/0/oppo_log/
    mv -f /sdcard/tencent/MicroMsg/xlog /sdcard/oppo_log/
    chcon -R u:object_r:media_rw_data_file:s0 /data/media/0/oppo_log/
    setprop sys.tranfer.finished 1
    #can not delete the junk_logs path, kernel needed
    mkdir -p /data/oppo_log/junk_logs/kernel
    mkdir -p /data/oppo_log/junk_logs/ftrace
    mkdir -p /data/oppo_log/junk_logs
    chmod -R 777 /data/oppo_log/junk_logs
}

function clearCurrentLog(){
    filelist=`cat /sdcard/oppo_log/transfer_list.txt | $XKIT awk '{print $1}'`
    for i in $filelist;do
        rm -rf /sdcard/oppo_log/$i
    done
    rm -rf /sdcard/oppo_log/screenshot
    rm -rf /sdcard/oppo_log/diag_logs
    rm -rf /sdcard/oppo_log/transfer_list.txt
    rm -rf /sdcard/oppo_log/description.txt
    rm -rf /sdcard/oppo_log/xlog
}

function moveScreenRecord(){
    fileName=`getprop sys.screenrecord.name`
    zip=.zip
    mp4=.mp4
    mv -f /data/media/0/oppo_log/${fileName}${zip} /data/media/0/oppo_log/compress_log/${fileName}${zip}
    mv -f /data/media/0/oppo_log/screen_record/screen_record.mp4 /data/media/0/oppo_log/compress_log/${fileName}${mp4}
}

function clearDataOppoLog(){
    rm -rf /data/oppo_log/*
    rm -rf /sdcard/oppo_log/diag_logs/[0-9]*
    setprop sys.clear.finished 1
}

function calculateLogSize(){
    LogSize1=0
    LogSize2=0
    if [ -d "${DATA_LOG_PATH}" ]; then
        LogSize1=`du -s -k ${DATA_LOG_PATH} | $XKIT awk '{print $1}'`
    fi
    if [ -d /sdcard/oppo_log/diag_logs ]; then
        LogSize2=`du -s -k /sdcard/oppo_log/diag_logs | $XKIT awk '{print $1}'`
    fi
    LogSize3=`expr $LogSize1 + $LogSize2`
    setprop sys.calcute.logsize ${LogSize3}
    setprop sys.calcute.finished 1
}

function tranferTombstone() {
    srcpath=`getprop sys.tombstone.file`
    subPath=`getprop com.oppo.debug.time`
    TOMBSTONE_TIME=`date +%F-%H-%M-%S`
    cp ${srcpath} /data/oppo_log/${subPath}/tombstone/tomb_${TOMBSTONE_TIME}
}

function tranferAnr() {
    srcpath=`getprop sys.anr.srcfile`
    subPath=`getprop com.oppo.debug.time`
    destfile=`getprop sys.anr.destfile`

    cp ${srcpath} /data/oppo_log/${subPath}/anr/${destfile}
}

function cppstore() {
    panicenable=`getprop persist.sys.assert.panic`
    argtrue='true'
    srcpstore=`ls /sys/fs/pstore`
    subPath=`getprop com.oppo.debug.time`

    if [ "${panicenable}" = "${argtrue}" ]; then

        if [ "${srcpstore}" != "" ]; then
        cp -r /sys/fs/pstore /data/oppo_log/${subPath}/pstore
        fi
    fi
}
function enabletcpdump(){
        mount -o rw,remount,barrier=1 /system
        chmod 6755 /system/xbin/tcpdump
        mount -o ro,remount,barrier=1 /system
}


#ifdef VENDOR_EDIT
#Yanzhen.Feng@Swdp.Android.OppoDebug.LayerDump, 2015/12/09, Add for SurfaceFlinger Layer dump
function layerdump(){
    mkdir -p ${ROOT_AUTOTRIGGER_PATH}
    LOGTIME=`date +%F-%H-%M-%S`
    ROOT_SDCARD_LAYERDUMP_PATH=${ROOT_AUTOTRIGGER_PATH}/LayerDump_${LOGTIME}
    cp -R /data/log ${ROOT_SDCARD_LAYERDUMP_PATH}
    rm -rf /data/log
}
#endif /* VENDOR_EDIT */
function junklogcat() {
    # echo 1 > sdcard/0.txt
    JUNKLOGPATH=/sdcard/oppo_log/junk_logs
    mkdir -p ${JUNKLOGPATH}
    # echo 1 > sdcard/1.txt
    # echo 1 > ${JUNKLOGPATH}/1.txt
    system/bin/logcat -f ${JUNKLOGPATH}/junklogcat.txt -v threadtime *:V
}
function junkdmesg() {
    JUNKLOGPATH=/sdcard/oppo_log/junk_logs
    mkdir -p ${JUNKLOGPATH}
    system/bin/dmesg > ${JUNKLOGPATH}/junkdmesg.txt
}
function junksystrace_start() {
    JUNKLOGPATH=/sdcard/oppo_log/junk_logs
    mkdir -p ${JUNKLOGPATH}
    # echo s_start > sdcard/s_start1.txt
    #setup
    setprop debug.atrace.tags.enableflags 0x86E
    # stop;start
    adb shell "echo 16384 > /sys/kernel/debug/tracing/buffer_size_kb"

    echo nop > /sys/kernel/debug/tracing/current_tracer
    echo 'sched_switch sched_wakeup sched_wakeup_new sched_migrate_task binder workqueue irq cpu_frequency mtk_events' > /sys/kernel/debug/tracing/set_event
#just in case tracing_enabled is disabled by user or other debugging tool
    echo 1 > /sys/kernel/debug/tracing/tracing_enabled >nul 2>&1
    echo 0 > /sys/kernel/debug/tracing/tracing_on
#erase previous recorded trace
    echo > /sys/kernel/debug/tracing/trace
    echo press any key to start capturing...
    echo 1 > /sys/kernel/debug/tracing/tracing_on
    echo "Start recordng ftrace data"
    echo s_start > sdcard/s_start2.txt
}
function junksystrace_stop() {
    JUNKLOGPATH=/sdcard/oppo_log/junk_logs
    mkdir -p ${JUNKLOGPATH}
    echo s_stop > sdcard/s_stop.txt
    echo 0 > /sys/kernel/debug/tracing/tracing_on
    echo "Recording stopped..."
    cp /sys/kernel/debug/tracing/trace ${JUNKLOGPATH}/junksystrace
    echo 1 > /sys/kernel/debug/tracing/tracing_on

}

#ifdef VENDOR_EDIT
#Zhihao.Li@MultiMedia.AudioServer.FrameWork, 2016/10/19, Add for clean pcm dump file.
function cleanpcmdump() {
    rm -rf /sdcard/oppo_log/pcm_dump/*
}
#endif /* VENDOR_EDIT */

#ifdef VENDOR_EDIT
#Jianping.Zheng@Swdp.Android.Stability.Crash, 2016/08/09, Add for logd memory leak workaround
function check_logd_memleak() {
    logd_mem=`ps  | grep -i /system/bin/logd | $XKIT awk '{print $5}'`
    #echo "logd_mem:"$logd_mem
    if [ "$logd_mem" != "" ]; then
        upper_limit=300000;
        if [ $logd_mem -gt $upper_limit ]; then
            #echo "logd_mem great than $upper_limit, restart logd"
            setprop persist.sys.assert.panic false
            setprop ctl.stop logcatsdcard
            setprop ctl.stop logcatradio
            setprop ctl.stop logcatevent
            setprop ctl.stop logcatkernel
            setprop ctl.stop tcpdumplog
            setprop ctl.stop fingerprintlog
            setprop ctl.stop fplogqess
            sleep 2
            setprop ctl.restart logd
            sleep 2
            setprop persist.sys.assert.panic true
        fi
    fi
}
#endif /* VENDOR_EDIT */

case "$config" in
    "ps")
        Preprocess
        Ps
        ;;
    "top")
        Preprocess
        Top
        ;;
    "server")
        Preprocess
        Server
        ;;
    "dump")
        Preprocess
        Dumpsys
        ;;
    "tranfer")
        Preprocess
        tranfer
        ;;
    "tranfer_tombstone")
        tranferTombstone
        ;;
    "logcache")
        CacheLog
        ;;
    "logpreprocess")
        PreprocessLog
        ;;
    "tranfer_anr")
        tranferAnr
        ;;
    "main")
        initLogPath
        Logcat
        ;;
    "radio")
        initLogPath
        LogcatRadio
        ;;
    "fingerprint")
        initLogPath
        LogcatFingerprint
        ;;
    "fpqess")
        initLogPath
        LogcatFingerprintQsee
        ;;
    "event")
        initLogPath
        LogcatEvent
        ;;
    "kernel")
        initLogPath
        LogcatKernel
        ;;
    "tcpdump")
        initLogPath
        enabletcpdump
        tcpdumpLog
        ;;
    "clean")
        CleanAll
        ;;
    "clearcurrentlog")
        clearCurrentLog
        ;;
    "calcutelogsize")
        calculateLogSize
        ;;
    "cleardataoppolog")
        clearDataOppoLog
        ;;
    "movescreenrecord")
        moveScreenRecord
        ;;
    "cppstore")
        initLogPath
        cppstore
        ;;
    "screen_record")
        initLogPath
        screen_record
        ;;
#ifdef VENDOR_EDIT
#Yanzhen.Feng@Swdp.Android.OppoDebug.LayerDump, 2015/12/09, Add for SurfaceFlinger Layer dump
    "layerdump")
        layerdump
        ;;
#endif /* VENDOR_EDIT */
    "dumpstate")
        Preprocess
        Dumpstate
        ;;
    "enabletcpdump")
        enabletcpdump
        ;;
    "dumpenvironment")
        DumpEnvironment
        ;;
    "initcache")
        initcache
        ;;
    "logcatcache")
        logcatcache
        ;;
    "radiocache")
        radiocache
        ;;
    "eventcache")
        eventcache
        ;;
    "kernelcache")
        kernelcache
        ;;
    "tcpdumpcache")
        tcpdumpcache
        ;;
    "fingerprintcache")
        fingerprintcache
        ;;
    "fplogcache")
        fplogcache
        ;;
    "log_observer")
        log_observer
        ;;
    "junklogcat")
        junklogcat
    ;;
    "junkdmesg")
        junkdmesg
    ;;
    "junkststart")
        junksystrace_start
    ;;
    "junkststop")
        junksystrace_stop
    ;;
#ifdef VENDOR_EDIT
#Zhihao.Li@MultiMedia.AudioServer.FrameWork, 2016/10/19, Add for clean pcm dump file.
    "cleanpcmdump")
        cleanpcmdump
    ;;
#endif /* VENDOR_EDIT */
#ifdef VENDOR_EDIT
#Jianping.Zheng@Swdp.Android.Stability.Crash, 2016/08/09, Add for logd memory leak workaround
    "check_logd_memleak")
        check_logd_memleak
        ;;
#endif /* VENDOR_EDIT *
       *)
    tranfer
      ;;
esac
