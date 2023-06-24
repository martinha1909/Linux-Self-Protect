#!/bin/bash

SP_CONFIG_DIR=/opt/self_protect
CLIENT_DIR=CLI_Interface/CLI_Interface.cpp
CLIENT_INCLUDE_DIR=CLI_Interface/include/CLI_Interface.hpp
CLIENT_HELPER_DIR=CLI_Interface/cli_helper.c
CLIENT_HELPER_INCLUDE_DIR=CLI_Interface/include/cli_helper.h
CLIENT_BIN_DIR=$SP_CONFIG_DIR/bin/sp_client
CONFIG_LIST_FILE=$SP_CONFIG_DIR/config_list
SYSD_MONITOR_EXEC=/usr/bin/sysd_service_monitor
SYSD_CLIENT_EXEC=/usr/bin/sysd_client
QUERY_HISTORY_CLIENT_EXEC=$SP_CONFIG_DIR/bin/attempts_history

build_object_files() {
    if [ ! -d $SP_CONFIG_DIR/bin/ ]; then
        mkdir $SP_CONFIG_DIR/bin/
    fi

    g++ -o $CLIENT_BIN_DIR $CLIENT_HELPER_DIR $CLIENT_DIR

    sudo chmod a-wx $CLIENT_BIN_DIR
    sudo chmod a+r $CLIENT_BIN_DIR

    cp ../bin/sp_bin_upload /usr/bin/sp_bin_upload
    sudo chmod u+x /usr/bin/sp_bin_upload

    gcc -o ../bin/allow_process ../bin/allow_process.c
    cp ../bin/allow_process ../bin/deny_process
}

build_dependencies_dir() {
    # create /opt/self_protect dir
    if [ ! -d $SP_CONFIG_DIR ]; then
        mkdir $SP_CONFIG_DIR
    fi
    if [ ! -f $CONFIG_LIST_FILE ]; then
        sudo touch $CONFIG_LIST_FILE
    fi

    sudo chmod a+rw $CONFIG_LIST_FILE
}

build_dependencies_package() {
    sudo apt update
    sudo apt install ubuntu-gnome-desktop
    sudo apt-get install dbus-x11
    sudo apt-get install curl
    sudo apt-get install libcurl4-openssl-dev
    sudo apt-get install libssl-dev
    sudo apt-get install auditd
}

if [ "$( id -u )" -ne 0 ]
then
    echo 'sh: ./build.sh: Permission denied' >&2
    echo 'Try sudo ./build.sh' >&2
    exit 1
fi

build_dependencies_dir
build_dependencies_package

if [ -f "/usr/bin/self_protect" ]
then
    sudo chattr -i /usr/bin/self_protect
fi

if [ -f $SYSD_MONITOR_EXEC ]; then
    sudo chattr -i $SYSD_MONITOR_EXEC
fi

if [ -f $SYSD_CLIENT_EXEC ]; then
    sudo chattr -i $SYSD_CLIENT_EXEC
fi

make
sudo chattr +i /usr/bin/self_protect
make sysd_monitor
sudo chattr +i $SYSD_MONITOR_EXEC
make sysd_monitor_client
sudo chattr +i $SYSD_CLIENT_EXEC
build_object_files
sudo make query_history_client
sudo chmod a+rx $QUERY_HISTORY_CLIENT_EXEC
sudo chmod a-w $QUERY_HISTORY_CLIENT_EXEC
sudo chmod u+w $QUERY_HISTORY_CLIENT_EXEC
make clean
