all: build install

build:
	@-ansible-galaxy collection build -f

install:
	@-ansible-galaxy collection install dilerous-powerprotect-1.0.0.tar.gz -f
