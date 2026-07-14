NFS := l3fwd acl maglev nat

.PHONY: all clean $(NFS)
all: $(NFS)

$(NFS):
	$(MAKE) -C $@

clean:
	for d in $(NFS); do $(MAKE) -C $$d clean; done
