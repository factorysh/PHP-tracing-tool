## Vagrant Demo Instructions

git clone https://github.com/iovisor/bcc.git

cd bcc

docker build -t bcc-debian -f Dockerfile.debian .

docker run -v `pwd`/debs:/debs bcc-debian sh -c "mv *.deb /debs"

vagrant up
