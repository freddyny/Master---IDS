all: malicious-udp-client udp-client udp-server malicious-udp-client-sinkhole
APPS=servreg-hack
APPS += powertrace
CONTIKI=../../contiki
CFLAGS+= -DPROJECT_CONF_H=\"project-conf.h\"

CONTIKI_WITH_IPV6 = 1
include $(CONTIKI)/Makefile.include
