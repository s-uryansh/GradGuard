# Deception engine with 3 escalating levels:

- Warning: Rewrites `/.dockerenv` to say `PLATFORM=baremetal`, patches `/proc/1/cgroup` to look like a bare metal init scope.
- High: Adds all of the above, plus mounts a fake `/proc/cpuinfo` showing a real Intel i7 laptop CPU with no hypervisor flags, adds fake users to `/etc/passwd`, adds fake internal hostnames to `/etc/hosts`.
- Critical: All of the above, plus injects a random sleep into `.bashrc` to make automated tools think the system is under load.


All happens via `docker exec` while attacker sees nothing in their terminal