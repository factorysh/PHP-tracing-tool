## Vagrant Demo Instructions

Setup the vagrant machine and go in

	cd vagrant-buster && vagrant up
	vagrant ssh
	cd /vagrant/php_tool

Launch the demo PHP and nginx containers

	make

Instrumenting the code with php_tool

	sudo ./php_tool.py PID [PID ...]

Usage

	sudo ./php_tool.py
