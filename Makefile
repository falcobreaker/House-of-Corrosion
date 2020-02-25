all:
	gcc -Wl,-z,now,-z,relro main.c -o chall -O2 -fstack-protector -pie
