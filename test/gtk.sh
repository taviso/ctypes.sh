#!/bin/bash

# This is a port of the GTK+3 Hello World to bash.
#
# https://developer.gnome.org/gtk3/stable/gtk-getting-started.html
source ../ctypes.sh

# declare some numeric constants used by GTK+
declare -ri GTK_ORIENTATION_HORIZONTAL=0
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

    dlsym -g -n gtk_widget_destroy gtk_widget_destroy

    dlcall -g -n window -r pointer gtk_application_window_new $app
    dlcall -g gtk_window_set_title $window "Window"
    dlcall -g gtk_window_set_default_size $window 200 200
    
    dlcall -g -n button_box -r pointer gtk_button_box_new $GTK_ORIENTATION_HORIZONTAL
    dlcall -g gtk_container_add $window $button_box
    
    dlcall -g -n button -r pointer gtk_button_new_with_label "Hello World"
    dlcall -g g_signal_connect_data $button "clicked" $print_hello $NULL $NULL 0
    dlcall -g g_signal_connect_data $button "clicked" $gtk_widget_destroy $window $NULL $G_CONNECT_SWAPPED
    dlcall -g gtk_container_add $button_box $button

    dlcall -g gtk_widget_show_all $window
}

declare app     # GtkApplication *app
declare status  # int status

# Generate function pointers that can be called from native code.
callback -n print_hello print_hello void pointer pointer
callback -n activate activate void pointer pointer

# Make libgtk-3 symbols available at global scope, this makes it possible to
# call dlcall with -g instead of ${DLHANDLE[libgtk-3.so.0]}.
dlopen -g libgtk-3.so.0

dlcall -g -n app -r pointer gtk_application_new "org.gtk.example" $G_APPLICATION_FLAGS_NONE
dlcall -g -r ulong g_signal_connect_data $app "activate" $activate $NULL $NULL 0
dlcall -g -n status -r int g_application_run $app 0 $NULL
dlcall -g g_object_unref $app

exit ${status##*:}
