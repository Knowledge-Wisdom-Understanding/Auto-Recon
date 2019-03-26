#!/usr/bin/env bash

# TODO, Make Banner

cwd=$(pwd)

create_imgs_dir(){
    
    find_imgs(){
        find $cwd/ -name '*.jpg' -exec mv {} $cwd/imgs/ \;
        find $cwd/ -name '*.jpeg' -exec mv {} $cwd/imgs/ \;
        find $cwd/ -name '*.img' -exec mv {} $cwd/imgs/ \;
        find $cwd/ -name '*.gif' -exec mv {} $cwd/imgs/ \;
        find $cwd/ -name '*.png' -exec mv {} $cwd/imgs/ \;
    }
    
    if [ -d imgs ]; then
        echo "imgs directory exists"
        echo "moving images to imgs folder"
        find_imgs
    else
        echo "creating imgs directory"
        mkdir -p imgs
        echo "moving images to imgs folder"
        find_imgs
    fi
}

run_steg_tools() {
    exif_tool() {
        for i in imgs/*; do
            printf "\e[93m#################################################################################################### \e[0m\n"
            exiftool $i
            printf "\e[93m#################################################################################################### \e[0m\n"
        done
    } > exifout.log
    binwalker() {
        for i in imgs/*; do
            printf "\e[93m#################################################################################################### \e[0m\n"
            echo "$i "
            printf "\e[93m#################################################################################################### \e[0m\n"
            binwalk $i
            printf "\e[93m#################################################################################################### \e[0m\n"
            printf "\n"
        done
    } > bwalkout.log
    stringer() {
        for i in imgs/*; do
            printf "\e[93m#################################################################################################### \e[0m\n"
            echo "$i "
            printf "\e[93m#################################################################################################### \e[0m\n"
            strings -n 8 $i | sort -u
            printf "\e[93m#################################################################################################### \e[0m\n"
        done
    } > stringsout.log
    steghider() {
        for i in imgs/*; do
            printf "\e[93m#################################################################################################### \e[0m\n"
            echo "$i "
            steghide extract -sf $i -p password
            printf "\e[93m#################################################################################################### \e[0m\n"
        done
    }
    
    
    exif_tool
    binwalker
    stringer
    steghider
    
    cat exifout.log >> steg_report.log
    cat bwalkout.log >> steg_report.log
    cat stringsout.log >> steg_report.log
    
    create_steg_report_dir(){
        if [ -d steg_report ]; then
            find $cwd/ -name '*.log' -exec mv {} $cwd/steg_report/ \;
        else
            mkdir -p steg_report
            find $cwd/ -name '*.log' -exec mv {} $cwd/steg_report/ \;
        fi
    }
    create_steg_report_dir
    
    
}

traperr() {
    echo "ERROR: ${BASH_SOURCE[1]} at about ${BASH_LINENO[0]}"
}

set -o errtrace
trap traperr ERR


create_imgs_dir
run_steg_tools