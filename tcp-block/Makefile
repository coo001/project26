LDLIBS=-lpcap -pthread
TARGET=tcp-block

all: $(TARGET)

$(TARGET): main.o tcpBlock.o tcphdr.o ethhdr.o iphdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f  *.o $(TARGET)
