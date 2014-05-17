httptracker
===========
As an experiment with libpcap, this little tool outputs the hosts visited on port 80 and 8080

Compilaation
------------
1. You'd need the libpcap-dev file to compile this.
2. Running make inside the project folder will get you the executeable.

Running
-------
You need super user privileges to get access to the interfaces and to run in promiscuous mode.

Help
----
Usage: ./httptracker -m -v -s -h -a -d -l -n count -i intf_name.

-m - exclude packets from your machine on the interface(s) specified.

-v - verbose output (print all of application layer data).
-s - print src IP address of packets.
-l - exclude any loopback interface when sniffing on all intefaces.
-h - print this help message and exit.
-a - list all intetrfaces available that this program can capture on and exit(depends on user privileges).
-d - print debug messages.
-n count - number of packets to capture before quitting (-1 (default) equals infinity).
-i intf_name - capture HTTP traffic on the intf_name interface.