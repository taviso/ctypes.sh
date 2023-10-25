#!/bin/bash

# This is a port of the GTK 4 Hello World to bash.
#
# https://docs.gtk.org/gtk4/getting_started.html
source ctypes.sh

# declare some numeric constants used by GTK
declare -ri GTK_ORIENTATION_HORIZONTAL=0
declare -ri GTK_ALIGN_CENTER=3
declare -ri G_APPLICATION_FLAGS_NONE=0
declare -ri G_CONNECT_AFTER=$((1 << 0))
declare -ri G_CONNECT_SWAPPED=$((1 << 1))

# void print_hello(GtkApplication *app, gpointer user_data)
function print_hello ()
{
    echo "Hello World"
}

# void activate(GtkApplication *app, gpointer user_data)
function activate ()
{
    local app=$2
    local user_data=$3
    local window
    local button
    local button_box

    dlsym -n gtk_window_destroy gtk_window_destroy

    dlcall -n window -r pointer gtk_application_window_new $app
    dlcall gtk_window_set_title $window "Window"
    dlcall gtk_window_set_default_size $window 200 200

    dlcall -n button_box -r pointer gtk_box_new $GTK_ORIENTATION_HORIZONTAL 0
    dlcall gtk_widget_set_halign $button_box $GTK_ALIGN_CENTER
    dlcall gtk_widget_set_valign $button_box $GTK_ALIGN_CENTER
    dlcall gtk_window_set_child $window $button_box

    dlcall -n button -r pointer gtk_button_new_with_label "Hello World"
    dlcall g_signal_connect_data $button "clicked" $print_hello $NULL $NULL 0
    dlcall g_signal_connect_data $button "clicked" $gtk_window_destroy $window $NULL $G_CONNECT_SWAPPED
    dlcall gtk_box_append $button_box $button

    dlcall gtk_widget_show $window
}

declare app     # GtkApplication *app
declare status  # int status

# Generate function pointers that can be called from native code.
callback -n print_hello print_hello void pointer pointer
callback -n activate activate void pointer pointer

# Prevent threading issues.
taskset -p 1 $$ &> /dev/null

# Make libgtk-4 symbols available
dlopen libgtk-4.so.1

dlcall -n app -r pointer gtk_application_new "org.gtk.example" $G_APPLICATION_FLAGS_NONE
dlcall -r ulong g_signal_connect_data $app "activate" $activate $NULL $NULL 0
dlcall -n status -r int g_application_run $app 0 $NULL
dlcall g_object_unref $app

exit ${status##*:}
