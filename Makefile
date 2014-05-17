all:
		gcc -Wall -o httptracker httptracker.c -lpcap
sn:
		gcc -Wall -o sniffex sniffex.c -lpcap
clean:
		rm httptracker, proto_h.h.gch
