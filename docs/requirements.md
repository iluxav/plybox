# Host requirements and compatibility

plybox currently targets **Linux x86_64 with usable unprivileged user
namespaces**. A recent distribution name alone does not establish that the
host permits its launch sequence. Restricted containers and hardened hosts
can reject it before any workload starts.

Evidence checked on 2026-11-07: the local test machine is Omarchy 4.5 / Arch,
Linux `7.2.15-1-omarchy`, x86_64, util-linux `2.42.4`, with bundled gVisor
`release-20261102.0`. Ubuntu 24.04 with its AppArmor restriction on is
verified in CI (below). The other distributions are **researched, not
tested on those systems**. Upstream documentation
describes prerequisites; it does not certify this plybox build.

Local command verification passed the exact outer `unshare` flags, an
embedded-gVisor Python image, direct bind-mode output, placeholder-secret
HTTPS calls to a local fixture, an in-box loopback service, and the
`systemd-run scope` cgroup backend. Namespace staging, resume, apply and
discard were also exercised in isolated scratch state. No administrator
changes, real credentials or paid API calls were used.

## Default gVisor tier

You need:

- **Linux x86_64.** The bundled payload and plybox's syscall policy currently
  target this architecture. Upstream gVisor also supports ARM64, but that
  does not make this plybox binary an ARM64 build. See the committed
  [runtime manifest](../third_party/gvisor/manifest.json) and
  [syscall policy](../src/seccomp.rs).
- **Linux 5.6 or newer**, documented by gVisor at the bundled
  `release-20261102.0` tag. This is the pinned runtime's stated requirement,
  not a measured plybox minimum on every intervening kernel.
  [Pinned gVisor installation requirements](https://github.com/google/gvisor/blob/release-20261102.0/g3doc/user_guide/install.md)
- **util-linux `unshare` on PATH**, supporting `--user`,
  `--map-current-user`, `--keep-caps`, and `--net`. These options are already
  present in upstream util-linux 2.37.4; check the actual executable on
  minimal or customized systems.
  [util-linux 2.37.4 source](https://raw.githubusercontent.com/util-linux/util-linux/v2.37.4/sys-utils/unshare.c)
- **Permission to create nested user namespaces and network, mount, PID,
  IPC and UTS namespaces.** The kernel must provide these features and the
  enclosing security policy must permit them. Namespace limits apply to
  both the user creating a namespace and its ancestors.
  [Linux user namespaces](https://man7.org/linux/man-pages/man7/user_namespaces.7.html),
  [kernel namespace limits](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/user.html)
- **A private, writable state directory on a filesystem that allows
  execution.** The bundled executables are extracted under
  `$XDG_STATE_HOME/plybox/runtimes/`, or
  `~/.local/state/plybox/runtimes/` by default. A `noexec` mount can prevent
  startup even when extraction and checksum verification succeed. The
  state directory must be owned by the invoking user and not writable by
  others; runtime directories must be mode 0700. See
  [cache validation](../src/embedded.rs) and
  [Linux exec errors](https://man7.org/linux/man-pages/man2/execve.2.html).

The bundled runtime uses gVisor's default **systrap** platform. It uses
seccomp traps and needs neither `/dev/kvm` nor nested hardware
virtualization. A full KVM/cloud VM is therefore a suitable *kind* of host
if its guest Linux satisfies the requirements above. This is distinct from
selecting gVisor's optional KVM platform.
[gVisor platforms](https://gvisor.dev/docs/user_guide/platforms/),
[systrap architecture](https://gvisor.dev/docs/architecture_guide/platforms/)

The actual launch chain is:

```text
plybox
  [systemd-run --user --scope ... --]
  unshare --user --map-current-user --keep-caps --net --
  <cached-runsc> --rootless --network=none --host-uds=open
                 --ignore-cgroups --overlay2=root:memory ... run ...
```

The optional wrapper enforces requested resource limits. `unshare` retains
the caller's numeric UID/GID and namespace-local capabilities for runtime
setup; the OCI workload receives empty capability sets. The OCI bundle
requests a further user namespace and the other namespaces above. There
is no Docker daemon, subordinate-ID allocation, or `newuidmap` setup in
this launch path. See [runtime invocation](../src/gvisor.rs),
[resource wrapper](../src/limits.rs), and the
[util-linux option definitions](https://man7.org/linux/man-pages/man1/unshare.1.html).

## Check the actual host

Run these as the account that will run plybox:

```sh
uname -m
uname -r
unshare --version
unshare --user --map-current-user --keep-caps --net -- /bin/true
plybox run -- /bin/true
```

The final command must exit successfully. The standalone `unshare` command
is a diagnostic for the outer namespace operation, not a complete gVisor
test. With a per-plybox AppArmor exception it can legitimately fail while
`plybox run` succeeds, because the standalone invocation has a different
AppArmor label. A test containing only `unshare --user` is too weak for this
launcher: it omits the network namespace and the capabilities needed by
runtime setup. [Ubuntu's capability restriction](https://ubuntu.com/blog/whats-new-in-security-for-ubuntu-24-04-lts)

For `Operation not permitted` / `Permission denied`, collect these values
before changing anything:

```sh
sysctl user.max_user_namespaces user.max_net_namespaces
sysctl kernel.unprivileged_userns_clone
sysctl kernel.apparmor_restrict_unprivileged_userns
sysctl kernel.apparmor_restrict_unprivileged_unconfined
cat /proc/self/attr/current
systemd-detect-virt
```

Some sysctls or the AppArmor attribute are absent on some kernels; absence
alone does not establish a failure. A zero namespace limit, an explicitly
disabled userns facility, an outer seccomp filter, and an AppArmor denial
need different remedies. Kernel namespace limits are not per-executable
allowlists, so there is no per-plybox exception to a host-wide zero limit.
[Kernel namespace limits](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/user.html)

## Distribution notes

Every row below except Ubuntu 24.04 is **researched / unverified for plybox**. Run the smoke
commands on the actual image, as its administrator may have changed the
defaults.

| Host | Evidence and practical expectation |
| --- | --- |
| Ubuntu 23.10 | The AppArmor userns restriction was introduced as opt-in. The later 24.04 release notes explicitly confirm it was not enabled by default in 23.10; the original announcement's plan to enable it later is not evidence that this happened. Read the live sysctl. [Announcement](https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces), [24.04 release notes](https://documentation.ubuntu.com/release-notes/24.04/#unprivileged-user-namespace-restrictions) |
| Ubuntu 24.04 and later | **Verified in CI (24.04.5).** The restriction is on by default; plybox explains it and needs the [AppArmor profile](#ubuntu-2404-and-later). Later releases add or change profiles: run the smoke commands. [24.04 security changes](https://ubuntu.com/blog/whats-new-in-security-for-ubuntu-24-04-lts), [26.04 profile changes](https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/#new-apparmor-sandboxing-profiles) |
| Debian 12 / 13 | Their release kernel series are 6.1 / 6.12. Debian enables unprivileged user namespaces by default starting with Debian 11, as also documented by the package maintainer in Debian 13. These are plausible hosts without a default userns exception, subject to local hardening. [Debian 12](https://www.debian.org/releases/bookworm/amd64/release-notes/ch-whats-new.en.html), [Debian 13](https://www.debian.org/releases/trixie/release-notes/whats-new.en.html), [Debian namespace default](https://sources.debian.org/src/charliecloud/0.38-3/debian/README.Debian) |
| RHEL 9 | Its 5.14 kernel series exceeds the pinned runtime's stated floor. The official rootless-container procedure installs Podman and creates an account, without enabling userns through a sysctl. This supports an **inference** that the documented standard installation permits userns; it does not establish the effective quota on every pristine/minimal image or validate this launch chain. SELinux defaults to enforcing. [RHEL kernels](https://access.redhat.com/articles/red-hat-enterprise-linux-release-dates), [rootless setup, §1.6](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/building_running_and_managing_containers/index), [SELinux default](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/epub/using_selinux/red_hat_enterprise_linux-9-using_selinux-en-us.epub) |
| Rocky Linux 9 | Official documentation explicitly states that unprivileged user namespaces and cgroup v2 are enabled by default. It checks for a positive `user.max_user_namespaces`, showing `31790` as an example, not a required plybox value. This is stronger default-permission evidence, but still not a plybox/runsc test. Its 5.14 kernel series exceeds the stated floor; SELinux defaults to enforcing. [Namespace defaults](https://docs.rockylinux.org/guides/containers/rootless_podman_advanced/), [kernel releases](https://docs.rockylinux.org/releases/), [SELinux default](https://docs.rockylinux.org/guides/security/learning_selinux/) |
| AlmaLinux 9 | Its 5.14 kernel series exceeds the stated floor. The distro's x86_64 kernel configuration enables `CONFIG_USER_NS`, `CONFIG_NET_NS`, `CONFIG_PID_NS`, `CONFIG_IPC_NS` and `CONFIG_UTS_NS`. The policy package creates a new SELinux configuration in enforcing/targeted mode. **The effective default namespace quota on an unmodified installation was not established**: compile-time support alone does not prove runtime permission. Check the actual image. [Kernel releases](https://wiki.almalinux.org/release-notes/), [kernel configuration](https://git.almalinux.org/rpms/kernel/src/branch/a9/SOURCES/kernel-x86_64-rhel.config), [SELinux package defaults](https://git.almalinux.org/rpms/selinux-policy/src/branch/c9/SPECS/selinux-policy.spec) |
| Amazon Linux 2023 | AWS documents a 6.1 kernel baseline with newer streams, cgroup v2, and SELinux enabled in permissive mode by default. **Default permission for this userns launch sequence remains unestablished**: the inspected AWS guides do not specify the effective `user.max_user_namespaces` or certify rootless runsc. Do not infer namespace compatibility from the kernel version or SELinux mode; test the actual x86_64 AMI, especially a hardened derivative. [Kernel baseline](https://docs.aws.amazon.com/linux/al2023/ug/compare-with-al2-kernel.html), [cgroup v2](https://docs.aws.amazon.com/linux/al2023/ug/cgroupv2.html), [SELinux default](https://docs.aws.amazon.com/linux/al2023/ug/selinux.html) |

### Restricted images and SELinux

Security profiles can intentionally set `user.max_user_namespaces=0`.
Red Hat documents this conflict with container workloads and directs
administrators to adjust the specific setting when their policy permits
containers. That is separate from a distribution's ordinary defaults.
[Red Hat compliance considerations](https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/2.7/secure-con_compliance_profile_considerations)

If the only blocker is a zero user-namespace quota and the administrator
chooses to permit namespaces, Rocky documents `31790` as an enabling value.
A temporary change limited to that one setting is:

```sh
sudo sysctl -w user.max_user_namespaces=31790
```

Then rerun both smoke commands as the normal user. This changes the quota
for all users in that namespace; it is **not a per-plybox exception or a
proven minimum**. For persistence, review and update the existing sysctl
policy that set zero, rather than layering conflicting overrides. If the
zero limit must remain, there is no per-binary bypass; use a separately
provisioned VM. Other zero namespace quotas need their own investigation.
[Rocky's documented remedy](https://docs.rockylinux.org/guides/containers/rootless_podman_advanced/),
[kernel quota scope](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/user.html)

For an enforcing SELinux host, collect `getenforce`, `id -Z`, and the AVC
denials (`sudo ausearch -m AVC,USER_AVC -ts recent`). A confirmed incorrect
label on the installed binary can be checked with
`matchpathcon -V /usr/local/bin/plybox` and restored with
`sudo restorecon -v /usr/local/bin/plybox`. This only repairs that file's
label; it does not grant missing runtime permissions. No generic plybox
SELinux module or boolean has been validated here. A confined user or
service requires policy review based on the actual denials; disabling
SELinux or blindly importing `audit2allow` output is not the prescribed
fix. These administrative examples were not executed during this research.
[RHEL SELinux troubleshooting](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/epub/using_selinux/red_hat_enterprise_linux-9-using_selinux-en-us.epub)

## Ubuntu 24.04 and later

**Verified** on GitHub's `ubuntu-24.04` runner (Ubuntu 24.04.5 LTS, kernel
7.0.0-1017-azure, AppArmor 4.0.1) with the restriction left on, in every
push to `main` by the [Ubuntu AppArmor workflow](../.github/workflows/ubuntu-apparmor.yml).

Ubuntu 24.04 turns on `kernel.apparmor_restrict_unprivileged_userns`: an
unconfined program may create a user namespace but gets no capabilities
in it, so the gVisor launch cannot set up its network namespace. plybox
checks for this before starting a box and stops with:

```text
plybox: this host blocks the user namespaces gVisor needs: Ubuntu's AppArmor restriction is on (sysctl kernel.apparmor_restrict_unprivileged_userns = 1).
  An administrator can allow plybox alone with an AppArmor profile: https://github.com/iluxav/plybox/blob/main/docs/requirements.md#ubuntu-2404-and-later
```

The fix is an AppArmor profile that allows user namespaces for plybox
alone, [`contrib/apparmor/plybox`](../contrib/apparmor/plybox). It is the
same `flags=(unconfined)` plus `userns,` form Ubuntu uses for browsers and
container tools. Install it as root, with the binary at the path the
profile names:

```sh
sudo install -o root -g root -m 0755 plybox /usr/local/bin/plybox
sudo install -m 0644 plybox.apparmor /etc/apparmor.d/plybox   # release asset, or contrib/apparmor/plybox
sudo apparmor_parser -r /etc/apparmor.d/plybox
plybox run -- /bin/true      # as your normal user; exits 0
```

What the CI job checks with the restriction on:

- without the profile, plybox exits 1 with the message above;
- with it, the default tier, the README's `python:3.13-slim` check,
  `--mem/--pids/--cpu` limits and placeholder-secret HTTPS through the
  proxy all work;
- every process of a running box (plybox, `unshare`, `runsc`, gofer,
  sentry, systrap stubs) carries the `plybox` label, so the exception
  reaches gVisor by inheritance and needs no rule for the runtime cache;
- the same binary copied to `/tmp` and a plain `unshare --user --net`
  are still blocked: the exception is attached to the one path.

The gVisor security probes were also run under this profile with the
restriction on (40 closed, the SSH-agent probe unavailable, seven
workloads passing): [run 42439561507](https://github.com/iluxav/plybox/actions/runs/42439561507).

Keep the binary root-owned at that path. AppArmor attaches by path, so a
profile on a user-writable path extends the exception to anything put
there. To use another path, change the path in the profile. The
profile trusts what plybox runs: if callers may choose `--runsc`, fix the
runtime with [operator rules](operator.md). Turning the restriction off
for the whole machine (`sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`)
also works but removes Ubuntu's protection for every program; prefer the
profile. Later Ubuntu releases may add profiles that change transitions;
if a run fails there, `journalctl -k | grep apparmor=` shows the denial.

## VPSs and nested containers

- **Full virtual machines:** systrap is intended to work in VMs without
  nested virtualization. The guest still needs the namespace permissions
  above. [gVisor platform guidance](https://gvisor.dev/docs/user_guide/platforms/)
- **Docker containers:** ordinary Docker seccomp restrictions block
  namespace operations needed by this launcher. An image with a recent
  distribution does not change its outer policy. Docker supports custom
  seccomp profiles, but no minimal profile for this pinned plybox/runtime
  pair has been validated here. Use a full VM or have the host operator
  validate a narrowly tailored container policy; this guide does not
  prescribe `--privileged` or disabling seccomp/AppArmor.
  [Docker seccomp restrictions](https://docs.docker.com/engine/security/seccomp/)
- **LXC/LXD containers:** nesting is a host configuration decision. LXD's
  documented `security.nesting` option defaults to false. An operator can
  enable it per instance with `lxc config set INSTANCE security.nesting true`,
  but that is only a prerequisite to investigate, not a verified plybox
  fix: the outer AppArmor/seccomp policy and namespace limits still apply.
  Other LXC managers use different settings.
  [LXD instance options](https://canonical.com/lxd/docs/latest/reference/instance_options/#instance-options-security:security.nesting)
- **OpenVZ/container VPSs:** these use the provider's kernel; installing a
  newer guest userspace cannot replace it. Compatibility is provider- and
  configuration-dependent, and is unverified here. If the provider cannot
  supply the required namespaces and policy, use a full VM.
  [OpenVZ kernel-sharing model](https://wiki.openvz.org/WP/What_are_containers)

## Resource limits and optional namespace tier

For host memory, task and CPU limits, plybox first tries a writable cgroup
v2 subtree with the needed controllers, then `systemd-run --user --scope`.
A working user manager/session is necessary for the latter; simply having
`systemd-run` installed is insufficient. Test:

```sh
systemd-run --user --scope --quiet -- /bin/true
plybox run --mem 512M --pids 256 --cpu 1 -- /bin/true
```

Read the startup report: it should name a cgroup or `systemd-run scope`.
When ordinary `--mem`, `--pids` or `--cpu` limits are requested but neither
backend is available, plybox **warns and continues without those host
cgroup limits**. Mandatory operator cgroup ceilings instead refuse to
start without enforcement. A zero workload exit status alone therefore
does not prove resource limits are active. See
[limit backend behavior](../src/limits.rs), [launch checks](../src/launch.rs),
and [operator ceilings](operator.md).

The explicit `--isolation ns` tier additionally needs bubblewrap:
**0.11 or newer** for its default staged workspace, `--image`, or
`--rootfs`; **0.9 or newer** when using its sized scratch mounts.
Staged workspace edits also need working unprivileged OverlayFS. This tier
still depends on permitted namespaces; it is not a fix for a host that
forbids them. The launcher rejects unsupported overlay/image combinations
rather than silently changing the requested workspace mode. See
[namespace launch checks](../src/launch.rs) and
[upstream bubblewrap](https://github.com/containers/bubblewrap).
