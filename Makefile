all: compdetect_client compdetect_server compdetect

compdetect_client:
	gcc -g compdetect_common.c compdetect_client.c -o compdetect_client

compdetect_server:
	gcc -g compdetect_common.c compdetect_server.c -o compdetect_server

compdetect:
	gcc -g compdetect_common.c compdetect.c -o compdetect -lpthread


clean:
	rm -fr compdetect compdetect_client compdetect_server
