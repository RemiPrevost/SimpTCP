#!/bin/sh

cd ~/Bureau/3A/BE_RESEAU/stcp-daras-rprevos/branches/src
make

gnome-terminal --tab -e "/bin/bash -c './server 15556; exec /bin/bash -i'"
gnome-terminal --tab -e "/bin/bash -c './client localhost 15556; exec /bin/bash -i'"
