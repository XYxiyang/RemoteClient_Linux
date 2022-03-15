all:client_base.cpp  clientmsg.cpp ../common/common.cpp
	g++ -c client_base.cpp
	g++ -c clientmsg.cpp
	g++ -c ../common/common.cpp
	g++ common.o clientmsg.o client_base.o -o ts
.PHONY:clean
clean:
	rm -rf ts
	rm -rf clientmsg.o
	rm -rf common.o
	rm -rf client_base.o
	rm -rf ts_count.xls
	rm -rf ts.log