#!/bin/sh
#
# NVIDIA Daemon Installer
#
# Copyright (c) 2015 NVIDIA Corporation
#
# This is a installation script that attempts to create a UID for the
# NVIDIA Daemon and install one of the included scripts, which include:
#
#   + System V init (requires chkconfig found in PATH)
#   + systemd (requires systemctl found in PATH)
#   + Upstart (requires initctl found in PATH)
#
##############################################################################
# Common Functions
##############################################################################

verbose_output=0
default_sysv_path="/etc/init.d/$nv_daemon_name"

# nv_printf() - print message
#
# $1 - the message to print
nv_printf()
{
    [ "$verbose_output" = "0" ] || printf "$1"
}

# cleanup_cmd is a sequence of commands that will be executed in the case
# that nvgdError is called. The purpose of these commands is to cleanup any
# work that has been performed.
cleanup_cmd=""

# nvgdError() - exits the script with an error message for post-install.
#
# $1 - the error message to print
nvgdError()
{
    printf "\nError: $1.\n" >&2
    if [ "$uninstall" = "0" ]; then
        nv_printf "Aborting. Cleaning up... "
        errors=$( { eval $cleanup_cmd >/dev/null; } 2>&1 )
        if [ "$?" != "0" ]; then
            nv_printf "failed:\n"
            nv_printf "$errors\n" >&2
        else
            nv_printf "done.\n"
        fi
        exit 1
    else
        nv_printf "Uninstallation may be incomplete.\n"
    fi
}

# nvgdCommand() - wraps the given command with some formatting, and detects
# error conditions.
#
# $1 - a description about the command being executed
# $2 - the command to execute
# $3 - the cleanup command to reverse the effects of $2, should later commands
#      fail
nvgdCommand()
{
    nv_printf "${1}... "
    errors=$( { eval $2 >/dev/null; } 2>&1 )
    [ "$?" = "0" ] || { nv_printf "failed.\n"; \
        nvgdError "'$2' failed with\n'$errors'"; }
    nv_printf "done.\n"

    # If there's a cleanup command associated with this command, push it onto
    # the front so the cleanup gets executed in reverse order.
    if [ -n "$3" ]; then
        if [ -n "$cleanup_cmd" ]; then
            cleanup_cmd="$3 && $cleanup_cmd"
        else
            cleanup_cmd="$3"
        fi
    fi
}

# checkInstallPath() - checks the given path and if it exists, assigns it to
# the potential_path variable.
#
# $1 - the path to check
#
# Returns 1 if the directory cannot be used as the install path, 0 otherwise.
checkInstallPath()
{
    nv_printf "  $1 directory exists?  "
    if [ -d "$1" ]; then
        nv_printf "Yes\n"
        potential_path=$1
        return 0
    else
        nv_printf "No\n"
        return 1
    fi
}

pid_file="/var/run/$nv_daemon_name/$nv_daemon_name.pid"

# isNvgdRunning() - checks to see whether the daemon is already running.
isNvgdRunning()
{
    if [ -f "$pid_file" ]; then
        # PID file exists - is it running or stale?
        if ps -p `cat $pid_file` > /dev/null 2>&1; then
            # Process is running
            return 0
        else
            # Process info is stale
            return 1
        fi
    fi

    # No PID file exists, the daemon isn't running
    return 1
}

# set_ld_lib_path() - sets LD_LIBRARY_PATH in scripts
#
# $1 - $nv_daemon_name
# $2 - script name of detected environment
set_ld_lib_path()
{
    daemon_name=$1
    if [ "$daemon_name" = "nvidia-gridd" ]; then
        script_name=$2
        system_lib_path=$(sed -rn '/\/nvidia\/gridd\/libFlxCore/s%^[0-9]*: *(.*)/libFlxCore.*%\1%p' /var/lib/nvidia/log | sort -u)
        if [ -n "$system_lib_path" ]; then
            sed -i 's%LD_LIBRARY_PATH=/usr/lib/nvidia/gridd%LD_LIBRARY_PATH='$system_lib_path'%g' $script_name
        fi
    fi
}

dbus_conf_file="/etc/dbus-1/system.d/nvidia-grid.conf"

# write_dbus_conf() - write D-Bus conf file with required interface policy
write_dbus_conf()
{
cat << EOF > $dbus_conf_file
<busconfig>
<type>system</type>
<policy context="default">
<allow own="nvidia.grid.server"/>
<allow own="nvidia.grid.client"/>
<allow send_requested_reply="true"/>
<allow receive_requested_reply="true"/>
</policy>
</busconfig>
EOF
}

##############################################################################
# SysV Functions
##############################################################################

sysv_script=$nv_daemon_name

# checkSysV() - checks for the requirements for installing in a SysV
# environment, and sets the associated configuration paths accordingly.
#
# $1 - the installation path to use instead of checking for defaults
#
# $sysv_supported = 1 if the script can install in a SysV environment
# $potential_path = the path to install the SysV init script to
checkSysV()
{
    sysv_supported=1

    nv_printf "\nChecking for SysV requirements...\n"
    if [ -n "$1" ]; then
        checkInstallPath $1 || sysv_supported=0
    else
        checkInstallPath "/etc/init.d" || \
        checkInstallPath "/etc/rc.d/init.d" || \
        checkInstallPath "/etc/rc.d" || \
        sysv_supported=0
    fi

    nv_printf "  chkconfig found in PATH?  "
    $(which chkconfig >/dev/null 2>&1)
    if [ "$?" = "0" ]; then
        nv_printf "Yes\n"
    else
        nv_printf "No\n"
        sysv_supported=0
    fi

    if [ "$sysv_supported" = "1" ]; then
        nv_printf "SysV installation/uninstallation supported\n"
    else
        nv_printf "SysV installation/uninstallation not supported\n"
    fi
}

# installSysVScript() - performs installation steps required to install the
# SysV init script.
#
# $1 - directory to install the init script in
# $2 - if set, start the daemon after installation
installSysVScript()
{
    if isNvgdRunning; then
        if [ -f "$1/$sysv_script" ]; then
            # we can use the init script to stop it
            nvgdCommand "Attempting to stop $sysv_script" \
                        "'$1/$sysv_script' stop" \
                        ""
        else
            # something else is running the daemon, kill it
            nvgdCommand "Killing $sysv_script" \
                        "kill -9 `cat $pid_file`" \
                        ""
        fi
    fi

    if [ -f "$1/$sysv_script" ]; then
        nvgdCommand "Backing up existing '$1/$sysv_script'" \
                    "mv '$1/$sysv_script' '$1/${sysv_script}.bk'" \
                    "mv '$1/${sysv_script}.bk' '$1/$sysv_script'"
    fi

    nvgdCommand "Installing System V script $sysv_script" \
                "cp '$current_path/sysv/$sysv_script' '$1/$sysv_script'" \
                "rm -f '$1/$sysv_script'"

    set_ld_lib_path "$nv_daemon_name" "$1/$sysv_script"

    nvgdCommand "Enabling $sysv_script" \
                "chmod 0755 '$1/$sysv_script' && chkconfig --level 2345 $sysv_script on" \
                "chkconfig --del $sysv_script"

    if [ "$nv_daemon_name" = "nvidia-gridd" ]; then
        write_dbus_conf
    fi

    if [ "$2" = "1" ]; then
        nvgdCommand "Starting $sysv_script" \
                    "'$1/$sysv_script' start" \
                    "'$1/$sysv_script' stop"
    fi
}

# stopSysVScript() - performs steps required to stop the SysV int script.
#
# $1 - directory to stop the init script from
stopSysVScript()
{
    if isNvgdRunning; then
        nvgdCommand "Stopping $sysv_script" \
                    "$1/$sysv_script stop" ""
        printf "\n$nv_daemon_name $target successfully stopped.\n"
    fi
}

# startSysVScript() - performs steps required to start the SysV int script.
#
# $1 - directory to start the init script from
startSysVScript()
{
    [ -f "$1/$sysv_script" ] || nvgdError "'$1/$sysv_script' does not exist"

    if isNvgdRunning; then
        nv_printf "$nv_daemon_name is already running"
    else
        nvgdCommand "Starting $sysv_script" \
                    "$1/$sysv_script start" \
                    "$1/$sysv_script stop"
        printf "$nv_daemon_name $target successfully started."
    fi
}

# uninstallSysVScript() - performs uninstallation steps required to
# uninstall the SysV int script.
#
# $1 - directory to uninstall the init script from
uninstallSysVScript()
{
    [ -f "$1/$sysv_script" ] || nvgdError "'$1/$sysv_script' does not exist"

    stopSysVScript $1

    nvgdCommand "Disabling $sysv_script" \
                "chkconfig --del $sysv_script" ""
    nvgdCommand "Uninstalling $sysv_script script" \
                "rm -f '$1/$sysv_script'" ""

    if [ "$nv_daemon_name" = "nvidia-gridd" ] && [ -f "$dbus_conf_file" ]; then
        nvgdCommand "" "rm -f $dbus_conf_file" ""
    fi
}

##############################################################################
# systemd Functions
##############################################################################

systemd_service="$nv_daemon_name.service"

# checkSystemd() - checks for the requirements for installing in a systemd
# environment, and sets the associated configuration paths accordingly.
#
# $1 - the installation path to use instead of checking for defaults
#
# $systemd_supported = 1 if the script can install in a systemd environment
# $potential_path = the path to install the systemd service file to
checkSystemd()
{
    systemd_supported=1

    nv_printf "\nChecking for systemd requirements...\n"
    if [ -n "$1" ]; then
        checkInstallPath $1 || systemd_supported=0
    else
        checkInstallPath "/usr/lib/systemd/system" || \
        checkInstallPath "/etc/systemd/system" || \
        systemd_supported=0
    fi

    nv_printf "  systemctl found in PATH?  "
    $(which systemctl >/dev/null 2>&1)
    if [ "$?" = "0" ]; then
        nv_printf "Yes\n"
    else
        nv_printf "No\n"
        systemd_supported=0
    fi

    if [ "$systemd_supported" = "1" ]; then
        nv_printf "systemd installation/uninstallation supported\n"
    else
        nv_printf "systemd installation/uninstallation not supported\n"
    fi
}

# installSystemdService() - performs installation steps required to install
# the systemd service.
#
# $1 - directory to install the service file in
# $2 - if set, start the daemon after installation
installSystemdService()
{
    if isNvgdRunning; then
        systemctl status $systemd_service > /dev/null 2>&1
        if [ "$?" = "0" ]; then
            # systemd is running the daemon, stop it
            nvgdCommand "Stopping $systemd_service" \
                        "systemctl stop $systemd_service" \
                        ""
        else
            # something else is running the daemon, kill it
            nvgdCommand "Killing $nv_daemon_name" \
                        "kill -9 `cat $pid_file`" \
                        ""
        fi
    fi

    if [ -f "$1/$systemd_service" ]; then
        nvgdCommand "Backing up existing '$1/$systemd_service'" \
                    "mv '$1/$systemd_service' '$1/${systemd_service}.bk'" \
                    "mv '$1/${systemd_service}.bk' '$1/$systemd_service'"
    fi

    nvgdCommand "Installing sample systemd service $systemd_service" \
                "cp '$current_path/systemd/$systemd_service' '$1/$systemd_service'" \
                "rm -f '$1/$systemd_service'"

    set_ld_lib_path "$nv_daemon_name" "$1/$systemd_service"

    nvgdCommand "Enabling $systemd_service" \
                "systemctl reenable $systemd_service" \
                "systemctl disable $systemd_service"

    if [ "$nv_daemon_name" = "nvidia-gridd" ]; then
        write_dbus_conf
    fi

    if [ "$2" = "1" ]; then
        nvgdCommand "Starting $systemd_service" \
                    "systemctl start $systemd_service" \
                    "systemctl stop $systemd_service"
    fi

    if [ "$nv_daemon_name" = "nvidia-gridd" ]; then
        nvgdCommand "Redirecting $nv_daemon_name to support sysv for service command" \
                    "echo -e '#!/bin/sh \nsystemctl \$1 $nv_daemon_name' > $default_sysv_path" ""

        nvgdCommand "Giving executable permissions to $default_sysv_path" \
                    "chmod 755 $default_sysv_path" ""
    fi
}

# stopSystemdService() - performs steps required to stop the systemd service.
#
# $1 - directory to stop the service file from
stopSystemdService()
{
    if isNvgdRunning; then
        nvgdCommand "Stopping $systemd_service" \
                    "systemctl stop $systemd_service" ""
        printf "\n$nv_daemon_name $target successfully stopped.\n"
    fi
}

# startSystemdService() - performs steps required to start the systemd service.
#
# $1 - directory to start the service file from
startSystemdService()
{
    [ -f "$1/$systemd_service" ] || nvgdError "'$1/$systemd_service' does not exist"

    if isNvgdRunning; then
        nv_printf "$nv_daemon_name is already running"
    else
        nvgdCommand "Starting $systemd_service" \
                    "systemctl start $systemd_service" \
                    "systemctl stop $systemd_service"
        printf "\n$nv_daemon_name $target successfully started.\n"
    fi
}

# uninstallSystemdService() - performs uninstallation steps required to
# uninstall the systemd service.
#
# $1 - directory to uninstall the service file from
uninstallSystemdService()
{
    [ -f "$1/$systemd_service" ] || nvgdError "'$1/$systemd_service' does not exist"

    stopSystemdService $1

    nvgdCommand "Disabling $systemd_service" \
                "systemctl disable $systemd_service" ""
    nvgdCommand "Uninstalling $systemd_service" \
                "rm -f '$1/$systemd_service'" ""

    if [ "$nv_daemon_name" = "nvidia-gridd" ] && [ -f "$default_sysv_path" ]; then
        nvgdCommand "Removing $default_sysv_path" \
                    "rm -f $default_sysv_path" ""
    fi

    if [ "$nv_daemon_name" = "nvidia-gridd" ] && [ -f "$dbus_conf_file" ]; then
        nvgdCommand "" "rm -f $dbus_conf_file" ""
    fi
}

##############################################################################
# Upstart Functions
##############################################################################

upstart_service="$nv_daemon_name.conf"

# checkUpstart() - checks for the requirements for installing in an Upstart
# environment, and sets the associated configuration paths accordingly.
#
# $1 - the installation path to use instead of checking for defaults
#
# $upstart_supported = 1 if the script can install in an Upstart environment
# $potential_path = the path to install the Upstart service file to
checkUpstart()
{
    upstart_supported=1

    nv_printf "\nChecking for Upstart requirements...\n"
    if [ -n "$1" ]; then
        checkInstallPath $1 || upstart_supported=0
    else
        checkInstallPath "/etc/init" || upstart_supported=0
    fi

    nv_printf "  initctl found in PATH?  "
    $(which initctl >/dev/null 2>&1)
    if [ "$?" = "0" ]; then
        nv_printf "Yes\n"
    else
        nv_printf "No\n"
        upstart_supported=0
    fi

    if [ "$upstart_supported" = "1" ]; then
        nv_printf "Upstart installation/uninstallation supported\n"
    else
        nv_printf "Upstart installation/uninstallation not supported\n"
    fi
}

# installUpstartService() - performs installation steps required to install
# the Upstart service.
#
# $1 - directory to install the service file in
# $2 - if set, start the daemon after installation
installUpstartService()
{
    if isNvgdRunning; then
        initctl status $nv_daemon_name | grep "start" > /dev/null 2>&1
        if [ "$?" = "0" ]; then
            # Upstart is running the service, attempt to stop it
            nvgdCommand "Stopping $upstart_service" \
                        "initctl stop $nv_daemon_name" \
                        ""
        else
            # something else is running the daemon, kill it
            nvgdCommand "Killing $nv_daemon_name" \
                        "kill -9 `cat $pid_file`" \
                        ""
        fi
    fi

    if [ -f "$1/$upstart_service" ]; then
        nvgdCommand "Backing up existing '$1/$upstart_service'" \
                    "mv '$1/$upstart_service' '$1/${upstart_service}.bk'" \
                    "mv '$1/${upstart_service}.bk' '$1/$upstart_service'"
    fi

    nvgdCommand "Installing $upstart_service" \
                "cp '$current_path/upstart/$upstart_service' '$1/$upstart_service'" \
                "rm -f '$1/$upstart_service'"

    set_ld_lib_path "$nv_daemon_name" "$1/$upstart_service"

    if [ "$nv_daemon_name" = "nvidia-gridd" ]; then
        write_dbus_conf
    fi

    if [ "$2" = "1" ]; then
        nvgdCommand "Starting $upstart_service" \
                    "initctl start $nv_daemon_name" \
                    "initctl stop $nv_daemon_name"
    fi

    if [ "$nv_daemon_name" = "nvidia-gridd" ]; then
        nvgdCommand "Redirecting $nv_daemon_name to support sysv for service command" \
                    "echo -e '#!/bin/sh \ninitctl \$1 $nv_daemon_name' > $default_sysv_path" ""

        nvgdCommand "Giving executable permissions to $default_sysv_path" \
                    "chmod 755 $default_sysv_path" ""
    fi
}

# stopUpstartService() - performs steps required to stop the Upstart service.
#
# $1 - directory to stop the service file from
stopUpstartService()
{
    if isNvgdRunning; then
        nvgdCommand "Stopping $upstart_service" \
                    "initctl stop $nv_daemon_name" ""
        printf "\n$nv_daemon_name $target successfully stopped.\n"
    fi
}

# startUpstartService() - performs steps required to start the Upstart service.
#
# $1 - directory to start the service file from
startUpstartService()
{
    [ -f "$1/$upstart_service" ] || nvgdError "'$1/$upstart_service' does not exist"

    if isNvgdRunning; then
        nv_printf "$nv_daemon_name is already running"
    else
        nvgdCommand "Starting $upstart_service" \
                    "initctl start $nv_daemon_name" \
                    "initctl stop $nv_daemon_name"
        printf "\n$nv_daemon_name $target successfully started.\n"
    fi
}

# uninstallUpstartService() - performs uninstallation steps required to
# uninstall the Upstart service.
#
# $1 - directory to uninstall the service file from
uninstallUpstartService()
{
    [ -f "$1/$upstart_service" ] || nvgdError "'$1/$upstart_service' does not exist"

    stopUpstartService $1

    nvgdCommand "Uninstalling $upstart_service" \
                "rm -f '$1/$upstart_service'" ""

    if [ "$nv_daemon_name" = "nvidia-gridd" ] && [ -f "$default_sysv_path" ]; then
        nvgdCommand "Removing $default_sysv_path" \
                    "rm -f $default_sysv_path" ""
    fi

    if [ "$nv_daemon_name" = "nvidia-gridd" ] && [ -f "$dbus_conf_file" ]; then
        nvgdCommand "" "rm -f $dbus_conf_file" ""
    fi
}
