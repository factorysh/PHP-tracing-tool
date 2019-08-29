## Vagrant Demo Instructions

Setup the vagrant machine

	make vagrant

Go in the machine

	vagrant ssh

Install BCC and all the components

	make install-bcc

Launch the demo!

	make

## TEST FIX

Setup vagrant buster

	cd vagrant-buster && vagrant up
	vagrant ssh

Install BCC

	cd /vagrant/php_tool
	make install-bcc-local

Demo

	make
