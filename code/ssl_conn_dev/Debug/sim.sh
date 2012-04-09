#!/bin/bash

gnome-terminal -e ./server --title=SERVER --geometry=100x20+30+0 &
sleep 1
gnome-terminal -e ./client --title=CLIENT --geometry=100x20+0+400 &




