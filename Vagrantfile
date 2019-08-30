# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "debian/buster64"
  config.vm.network "private_network", ip: "192.168.33.10"
  config.vm.provider "virtualbox" do |v|
    v.memory = 1024
  end
  config.vm.synced_folder ".", "/vagrant", disabled: true
  config.vm.synced_folder "./", "/vagrant/php_tool/", owner: "vagrant", group: "vagrant", type: "rsync", rsync__exclude: %w(src)
  config.vm.provision "shell", inline: <<-SHELL
  sudo su
  apt-get update -y
  apt-get install -y --no-install-recommends \
    python \
    python3 \
    php \
    python-pip \
    python3-pip \
    python3-bpfcc \
    python-bpfcc \
    bpfcc-tools \
    sysvinit-utils \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg2 \
    git \
    software-properties-common

  curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
  add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/debian $(lsb_release -cs) stable"
  apt-get update -y
  apt-get install -y --no-install-recommends \
    docker-ce \
    docker-ce-cli \
    docker-compose \
    containerd.io

  usermod -aG docker vagrant
  docker info

  SHELL
end
