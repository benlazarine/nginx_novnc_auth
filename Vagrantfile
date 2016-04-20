# -*- mode: ruby -*-
# vi: set ft=ruby :
$script = <<SCRIPT

sudo service apache2 stop
sudo usermod -a -G www-data vagrant

# appears to be needed to avoid '404 Not Found' errors on
# some packages like `gcc/libstdc++-4.8-dev_4.8.4`
#
sudo add-apt-repository ppa:nginx/development
sudo apt-get update
# sudo apt-get upgrade

sudo apt-get -V install nginx-extras
nginx -V 2>&1 | grep -qF -- --with-http_auth_request_module && echo ":)" || echo ":("
sudo apt-get install libyaml-dev  # Probably not necessary.
sudo apt-get install -y git-core

sudo apt-get install -y python python-dev python-pip
python --version
pip -V
sudo pip install -U pip virtualenv

SCRIPT

Vagrant.configure(2) do |config|
  # NOTE: Use this if you find `npm install` is hanging
  # config.vm.provider :virtualbox do |vb|
  #   vb.customize ['modifyvm', :id, '--natdnshostresolver1', 'on']
  # end
  config.vm.define "nginx_nvnc_auth-dev" do |vm2|
    vm2.vm.box = "ubuntu/trusty64"
    vm2.vm.network "private_network", ip: "192.168.72.19"
    config.vm.synced_folder ".", "/vagrant",
        owner: "www-data", group: "www-data"
    vm2.vm.provision "shell", inline: $script, privileged: false
    vm2.vm.provider "virtualbox" do |v2|
      v2.memory = 4096*2
      #v2.cpus = 2
      v2.cpus = 4
    end
  end

#  config.vm.provision "fix-no-tty", type: "shell" do |s|
#    s.privileged = false
#    s.inline = "sudo sed -i '/tty/!s/mesg n/tty -s \\&\\& mesg n/' /root/.profile"
#  end

  if Vagrant.has_plugin?("vagrant-cachier")
    config.cache.scope = :box
  end

#  if Vagrant.has_plugin?("vagrant-proxyconf")
#    config.proxy.http     = "http://10.0.10.1:8123/"
#    config.proxy.https    = "http://10.0.10.1:8123/"
#    config.proxy.no_proxy = "localhost,127.0.0.1,`facter ipaddress_eth1`,10.0.10.1"
#    config.vm.provision :shell, :inline => $git_use_https
#  end
end
