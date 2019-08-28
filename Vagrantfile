# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "debian/stretch64"
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
    python-pip \
    python3-pip \
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
    containerd.io

  curl --silent -L https://github.com/docker/compose/releases/download/1.25.0-rc2/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose

  usermod -aG docker vagrant
  docker info

  SHELL
end
