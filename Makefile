.PHONY: default deploy watch

ieee-oui.txt:
	wget -O lib/ieee-oui.txt http://standards-oui.ieee.org/oui.txt

default: lib/ieee-oui.txt

DEPLOY_CMD = scp -r lib server.py Makefile pieth:raspi-mon

deploy:
	$(DEPLOY_CMD)

watch:
	watch -n 1 $(DEPLOY_CMD)
