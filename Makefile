.PHONY: demo-php-app demo-wordpress php-debug-image wordpress-debug-image

all: demo-php-app
	make -C demo-php-app up

php-debug-image:
	make -C php-debug-image

wordpress-debug-image: php-debug-image
	make -C wordpress-debug-image

demo-php-app: php-debug-image
	make -C demo-php-app

demo-wordpress: wordpress-debug-image
	make -C demo-wordpress

vagrant:
	vagrant up

src/bcc:
	mkdir -p src
	cd src && git clone https://github.com/iovisor/bcc.git

build-bcc: src/bcc
	docker build -t bcc-debian -f src/bcc/Dockerfile.debian src/bcc
	docker run -v `pwd`/debs:/debs bcc-debian sh -c "cp *.deb /debs"

debs: build-bcc

install-bcc: debs
	sudo dpkg -i debs/*.deb
