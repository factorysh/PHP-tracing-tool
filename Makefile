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
