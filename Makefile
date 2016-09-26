
all: runpriv

runpriv: runpriv.cpp
	g++ -g runpriv.cpp -o runpriv
