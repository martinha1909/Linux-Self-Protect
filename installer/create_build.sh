#!/bin/bash

if [ -f selfprotect_1.0_all.deb ]; then
    rm selfprotect_1.0_x86-64.deb
    echo "removed stale installer package"
fi

if [ -f /usr/bin/self_protect ]; then
    echo "latest self_protect binary updated"
    sudo cp /usr/bin/self_protect selfprotect_1.0_x86-64/usr/bin
fi

if [ -f /usr/bin/sysd_service_monitor ]; then
    echo "latest sysd_service_monitor binary updated"
    sudo cp /usr/bin/sysd_service_monitor selfprotect_1.0_x86-64/usr/bin
fi

if [ -f /opt/self_protect/bin/sp_client ]; then
    echo "Latest client binary sp_client updated"
    sudo cp /opt/self_protect/bin/sp_client selfprotect_1.0_x86-64/opt/self_protect/bin/sp_client
fi

if [ -f /opt/self_protect/bin/attempts_history ]; then
    echo "Latest client binary attempts_history updated"
    sudo cp /opt/self_protect/bin/attempts_history selfprotect_1.0_x86-64/opt/self_protect/bin/attempts_history
fi

if [ -f /usr/bin/sysd_client ]; then
    echo "Latest client binary sysd_client updated"
    sudo cp /usr/bin/sysd_client selfprotect_1.0_x86-64/usr/bin/sysd_client
fi

if [ -f /usr/bin/sp_bin_upload ]; then
    echo "Latest client binary sp_bin_upload updated"
    sudo cp /usr/bin/sp_bin_upload selfprotect_1.0_x86-64/usr/bin/sp_bin_upload
fi

sudo dpkg-deb --build selfprotect_1.0_x86-64
echo "New installer package built"
echo "To install: sudo dpkg -i selfprotect_1.0_x86-64.deb"

