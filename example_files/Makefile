PWD := $(shell pwd)

all:
	docker run --rm -e PLUGIN_PLAYBOOK="playbook.yml" -e PLUGIN_INVENTORY="hosts" -e PLUGIN_GALAXY="requirements.yml" -e PLUGIN_REQUIREMENTS="requirements.txt" -v $(PWD):$(PWD) -w $(PWD) plugins/ansible
