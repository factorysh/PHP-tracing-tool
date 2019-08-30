build:
	docker build . -t wordpress-debug

bin:
	mkdir -p bin

bin/wp-cli.phar: bin
	curl -o bin/wp-cli.phar https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar

