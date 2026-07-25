#include <tunables/global>

profile dohwa-ci-candidate-v1 flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  file,
  deny capability,
  deny network,
  deny mount,
  deny umount,
  deny pivot_root,
  deny ptrace,

  deny /work/.apparmor-probe rwklx,
  deny /proc/sys/** wklx,
  deny /sys/** wklx,
  deny /run/** wklx,
  deny /var/run/** wklx,
  deny /workspace/** rwklx,
}
