#!/bin/bash
#
# megascript.sh - startup hardening for the 2026 mail service box (Ubuntu)
#
# Scored services (never removed): sshd, postfix, dovecot, roundcube, kerberos client.
# Authentication is AD via LDAP or Kerberos. Those services are assumed to be
# already configured and working, so this script only hardens, it does not configure.
#
# Usage: sudo ./megascript.sh
#
# Layout:
#   1. Bootstrap     : clean environment, shared variables and helpers
#   2. Pre-flight    : keylogger checks, then password prompts
#   3. Steps         : one function per hardening task
#   4. Step table    : ordered list with time estimates
#   5. Runner/report : progress bar, ETA, final report


# =============================================================================
# 1. BOOTSTRAP
# =============================================================================

# Require sudo, then re-run this script inside an empty environment so no
# aliases, functions, bash profile, BASH_ENV, LD_PRELOAD or other inherited
# variables can interfere. Only the values passed to `env -i` below survive.
if [[ -z ${MEGASCRIPT_CLEAN_ENV:-} ]]; then
  if [[ $EUID -ne 0 || -z ${SUDO_USER:-} ]]; then
    echo "Run with: sudo $0" >&2
    exit 1
  fi

  exec /usr/bin/env -i \
    MEGASCRIPT_CLEAN_ENV=1 \
    INVOKING_USER="$SUDO_USER" \
    INVOKING_TTY="$(tty 2>/dev/null)" \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/root \
    TERM="${TERM:-xterm}" \
    LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    /bin/bash --noprofile --norc "$(readlink -f "$0")" "$@"
fi

# Belt and braces: nothing should be defined in a fresh `env -i` shell.
unalias -a 2>/dev/null
hash -r
umask 077

SCRIPT_PID=$$

# Private working directory on tmpfs (cleared on reboot). Holds logs and state.
WORK_DIR=/run/megascript
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
chmod 700 "$WORK_DIR"
export WORK_DIR   # the background upgrade script reads this

MAIN_LOG="$WORK_DIR/main.log"                          # output of every step
WARNINGS_FILE="$WORK_DIR/warnings.log"                 # shown in the final report
PREFLIGHT_FINDINGS_FILE="$WORK_DIR/preflight.log"      # keylogger check findings
NFTBUILD_FETCH_STATUS_FILE="$WORK_DIR/nftbuild_fetch.rc"
UPGRADE_LOG="$WORK_DIR/upgrade.log"
UPGRADE_PID_FILE="$WORK_DIR/upgrade.pid"
UPGRADE_STATUS_FILE="$WORK_DIR/upgrade_status"
PURGE_LIST_FILE="$WORK_DIR/purge.list"

: > "$MAIN_LOG"
: > "$WARNINGS_FILE"

# Options for every apt-get call: non-interactive, wait up to 30 min for the
# dpkg lock (the background upgrade holds it), keep existing config files.
APT_OPTIONS=(-y -o DPkg::Lock::Timeout=1800 -o Dpkg::Options::=--force-confold)

# PIDs of this script and its parents, so checks never kill our own session.
ANCESTOR_PIDS=" $$ "


# ---- Small shared helpers ---------------------------------------------------

# add_warning MESSAGE
#   Queue a message for the "Attention" section of the final report.
add_warning() {
  echo "$*" >> "$WARNINGS_FILE"
}

# is_package_owned PATH
#   True if a dpkg package owns PATH (symlinks resolved first).
is_package_owned() {
  dpkg -S "$(readlink -f "$1")" &>/dev/null
}

# installed_packages_matching REGEX
#   Print the names of installed packages whose name matches REGEX.
installed_packages_matching() {
  local name_regex=$1

  dpkg-query -W -f='${db:Status-Abbrev} ${binary:Package}\n' \
    | awk -v name_regex="$name_regex" '$1=="ii" && $2 ~ name_regex {print $2}'
}

# package_failed_verification PACKAGE
#   True if any non-config file of PACKAGE differs from what dpkg installed.
package_failed_verification() {
  dpkg --verify "$1" 2>/dev/null | grep -qv ' c /'
}


# =============================================================================
# 2. PRE-FLIGHT: KEYLOGGER CHECKS, THEN PASSWORD PROMPTS
# =============================================================================

# add_preflight_finding MESSAGE
#   Record a keylogger-check finding (also shown in the final report).
add_preflight_finding() {
  echo "$*" >> "$PREFLIGHT_FINDINGS_FILE"
  add_warning "PREFLIGHT: $*"
}

# collect_ancestor_pids
#   Fill ANCESTOR_PIDS with this shell and every parent up to init.
collect_ancestor_pids() {
  local pid=$$

  while [[ -n $pid && $pid -gt 1 ]]; do
    ANCESTOR_PIDS+="$pid "
    pid=$(awk '/^PPid:/ {print $2}' "/proc/$pid/status" 2>/dev/null)
  done
}

# preflight_check_preload_hooks
#   Remove /etc/ld.so.preload and flag processes started with LD_PRELOAD.
preflight_check_preload_hooks() {
  local proc_dir pid

  if [[ -s /etc/ld.so.preload ]]; then
    add_preflight_finding "/etc/ld.so.preload existed (removed): $(tr '\n' ' ' < /etc/ld.so.preload)"
  fi
  rm -f /etc/ld.so.preload

  for proc_dir in /proc/[0-9]*; do
    pid=${proc_dir#/proc/}
    if tr '\0' '\n' < "$proc_dir/environ" 2>/dev/null | grep -q '^LD_PRELOAD='; then
      add_preflight_finding "pid $pid ($(readlink "$proc_dir/exe")) has LD_PRELOAD set"
    fi
  done
}

# preflight_check_ptrace_taps
#   Any process being ptraced (strace on sshd/sudo/login etc.) gets its tracer killed.
preflight_check_ptrace_taps() {
  local proc_dir pid tracer_pid

  for proc_dir in /proc/[0-9]*; do
    pid=${proc_dir#/proc/}
    tracer_pid=$(awk '/^TracerPid:/ {print $2}' "$proc_dir/status" 2>/dev/null)

    [[ ${tracer_pid:-0} -gt 0 ]] || continue
    [[ $ANCESTOR_PIDS == *" $tracer_pid "* ]] && continue

    add_preflight_finding "pid $pid ($(cat "$proc_dir/comm" 2>/dev/null)) is traced by pid $tracer_pid ($(readlink "/proc/$tracer_pid/exe")), killing tracer"
    kill -9 "$tracer_pid"
  done
}

# preflight_check_input_device_readers
#   Processes holding /dev/input open can log keystrokes. Unpackaged ones are
#   killed, packaged ones (logind, Xorg) are only reported.
preflight_check_input_device_readers() {
  local proc_dir pid exe_path

  for proc_dir in /proc/[0-9]*; do
    pid=${proc_dir#/proc/}

    readlink "$proc_dir"/fd/* 2>/dev/null | grep -q '^/dev/input/' || continue

    exe_path=$(readlink "$proc_dir/exe" 2>/dev/null)

    if [[ $exe_path != *'(deleted)' ]] && is_package_owned "$exe_path"; then
      add_preflight_finding "packaged process reads /dev/input, review: pid $pid ($exe_path)"
    else
      add_preflight_finding "unpackaged process reads /dev/input, killing: pid $pid ($exe_path)"
      kill -9 "$pid"
    fi
  done
}

# preflight_check_tty_sniffers
#   Kill well-known tty/key logging tools and flag pam_tty_audit.
preflight_check_tty_sniffers() {
  local pid pam_line

  for pid in $(pgrep -x 'script|ttyrec|ttysnoop|logkeys|lkl|keylogger' 2>/dev/null); do
    [[ $ANCESTOR_PIDS == *" $pid "* ]] && continue

    add_preflight_finding "tty/key logger process killed: pid $pid ($(cat "/proc/$pid/comm" 2>/dev/null))"
    kill -9 "$pid"
  done

  grep -rn 'pam_tty_audit' /etc/pam.d 2>/dev/null | while read -r pam_line; do
    add_preflight_finding "pam_tty_audit in use: $pam_line"
  done
}

# preflight_check_pam_and_login_binaries
#   Verify auth-related packages, reinstall tampered ones, then flag PAM modules
#   that are missing or not owned by any package.
preflight_check_pam_and_login_binaries() {
  local auth_package_regex='^(libpam-modules|libpam-modules-bin|libpam-runtime|libpam0g|libpam-krb5|libpam-sss|sudo|login|passwd|openssh-server)$'
  local tampered_packages=()
  local package module_name module_path module_file

  for package in $(installed_packages_matching "$auth_package_regex"); do
    if package_failed_verification "$package"; then
      tampered_packages+=("$package")
    fi
  done

  if ((${#tampered_packages[@]} > 0)); then
    add_preflight_finding "tampered auth packages, reinstalling: ${tampered_packages[*]}"
    apt-get "${APT_OPTIONS[@]}" --reinstall install "${tampered_packages[@]}" >> "$MAIN_LOG" 2>&1

    for package in "${tampered_packages[@]}"; do
      if package_failed_verification "$package"; then
        add_preflight_finding "STILL TAMPERED after reinstall: $package"
      fi
    done
  fi

  # Every .so named in /etc/pam.d must exist and belong to a package.
  cat /etc/pam.d/* 2>/dev/null \
    | grep -v '^\s*#' \
    | grep -Eo '[A-Za-z0-9_./-]+\.so' \
    | sort -u \
    | while read -r module_name; do
        if [[ $module_name == /* ]]; then
          module_path=$module_name
        else
          module_path=$(ls /usr/lib/*/security/"$module_name" /usr/lib/security/"$module_name" /lib/security/"$module_name" 2>/dev/null | head -1)
        fi

        if [[ -z $module_path || ! -e $module_path ]]; then
          add_preflight_finding "PAM module referenced but not found: $module_name"
          continue
        fi

        is_package_owned "$module_path" || add_preflight_finding "unpackaged PAM module in use: $module_path"
      done

  # Any unpackaged file sitting in a PAM module directory is suspicious.
  find /usr/lib/*/security /usr/lib/security /lib/security -maxdepth 1 -type f 2>/dev/null \
    | while read -r module_file; do
        is_package_owned "$module_file" || add_preflight_finding "unpackaged file in PAM module dir: $module_file"
      done
}

# preflight_check_kernel_modules
#   Flag loaded kernel modules whose file no package owns (rootkits, but also
#   legitimate DKMS/out-of-tree drivers).
preflight_check_kernel_modules() {
  local module_name module_file

  lsmod | awk 'NR>1 {print $1}' | while read -r module_name; do
    module_file=$(modinfo -n "$module_name" 2>/dev/null)

    [[ $module_file == /* ]] || continue   # built-in modules have no file

    is_package_owned "$module_file" || add_preflight_finding "kernel module not owned by a package: $module_name ($module_file)"
  done
}

# preflight_check_ebpf_programs
#   Informational only: systemd loads some eBPF programs itself.
preflight_check_ebpf_programs() {
  local program_count

  command -v bpftool > /dev/null || return 0

  program_count=$(bpftool prog show 2>/dev/null | grep -c '^[0-9]')

  if ((program_count > 0)); then
    add_warning "PREFLIGHT info: $program_count eBPF programs loaded (systemd loads some), review with: bpftool prog show"
  fi
}

# preflight_harden_input_and_tty
#   Block ptrace by non-root, block TIOCSTI keystroke injection, make input
#   devices root-only (now and via udev) and drop users from the input group.
preflight_harden_input_and_tty() {
  local input_group_member

  sysctl -qw kernel.yama.ptrace_scope=2 >> "$MAIN_LOG" 2>&1
  sysctl -qw dev.tty.legacy_tiocsti=0   >> "$MAIN_LOG" 2>&1   # kernel 6.2+ only

  chmod 600 /dev/input/event* /dev/input/mice /dev/input/mouse* 2>/dev/null

  printf 'SUBSYSTEM=="input", GROUP="root", MODE="0600"\n' > /etc/udev/rules.d/99-megascript-input.rules
  udevadm control --reload 2>/dev/null

  for input_group_member in $(getent group input | cut -d: -f4 | tr ',' ' '); do
    gpasswd -d "$input_group_member" input >> "$MAIN_LOG" 2>&1
  done
}

# run_preflight
#   Run all keylogger checks. If anything was found, show it and let the user
#   abort before any password is typed.
run_preflight() {
  local answer

  : > "$PREFLIGHT_FINDINGS_FILE"
  collect_ancestor_pids

  echo "Pre-flight: keylogger checks (before any password is typed)"

  echo "  [1/8] preload hooks";                preflight_check_preload_hooks
  echo "  [2/8] ptrace/strace taps";           preflight_check_ptrace_taps
  echo "  [3/8] processes reading /dev/input"; preflight_check_input_device_readers
  echo "  [4/8] tty sniffers";                 preflight_check_tty_sniffers
  echo "  [5/8] PAM and login binaries";       preflight_check_pam_and_login_binaries
  echo "  [6/8] kernel modules";               preflight_check_kernel_modules
  echo "  [7/8] eBPF programs";                preflight_check_ebpf_programs
  echo "  [8/8] input and tty hardening";      preflight_harden_input_and_tty

  if [[ -s $PREFLIGHT_FINDINGS_FILE ]]; then
    echo
    echo "--- Pre-flight findings ---"
    cat "$PREFLIGHT_FINDINGS_FILE"
    echo

    read -rp "Findings above. Enter passwords anyway? [y/N] " answer < /dev/tty
    if [[ $answer != [yY]* ]]; then
      echo "Aborted before password entry."
      exit 1
    fi
  else
    echo "  clean."
  fi

  echo
}

# prompt_new_password USERNAME VARIABLE_NAME
#   Ask twice (hidden input) and store the confirmed password in VARIABLE_NAME.
prompt_new_password() {
  local username=$1
  local result_variable=$2
  local first_entry second_entry

  while true; do
    read -rsp "New password for $username: " first_entry < /dev/tty
    echo
    read -rsp "Confirm: " second_entry < /dev/tty
    echo

    if [[ -n $first_entry && $first_entry == "$second_entry" ]]; then
      printf -v "$result_variable" '%s' "$first_entry"
      return
    fi

    echo "Empty or mismatch, again."
  done
}

run_preflight

prompt_new_password "$INVOKING_USER" NEW_USER_PASSWORD
prompt_new_password root             NEW_ROOT_PASSWORD

# Download nftbuild in parallel with everything else. The nftbuild step waits
# for NFTBUILD_FETCH_STATUS_FILE to appear, which merges it back in.
(
  curl -fsSL --max-time 180 -o "$WORK_DIR/nftbuild" https://tinyurl.com/nftbuild
  echo $? > "$NFTBUILD_FETCH_STATUS_FILE"
) &

# Remote-access packages that are not scored. They are disabled right away and
# purged after the background upgrade finishes (the upgrade holds the apt lock).
cat > "$PURGE_LIST_FILE" <<'PURGE_LIST_EOF'
telnet telnetd inetutils-telnetd telnetd-ssl rsh-client rsh-server rsh-redone-client rsh-redone-server
xinetd openbsd-inetd inetutils-inetd tftpd tftpd-hpa atftpd vsftpd proftpd-basic pure-ftpd
netcat netcat-openbsd netcat-traditional ncat socat tmate autossh sshfs
tightvncserver x11vnc tigervnc-standalone-server tigervnc-scraping-server vino xrdp
cockpit webmin samba nfs-kernel-server snmpd openvpn teamviewer anydesk
PURGE_LIST_EOF


# =============================================================================
# 3. STEPS (each runs in the background, output goes to MAIN_LOG)
# =============================================================================

# Restore Ubuntu default shell profiles for root and sysadmin, remove injected
# PROMPT_COMMAND and environment variables, and drop LD_PRELOAD config.
step_reset_shell_profiles() {
  local account home_dir

  # /etc/skel, /etc/profile and /etc/bash.bashrc come from these packages.
  apt-get "${APT_OPTIONS[@]}" --reinstall -o Dpkg::Options::=--force-confnew install bash base-files \
    || add_warning "could not reinstall bash/base-files defaults"

  [[ -f /etc/skel/.bashrc ]] || add_warning "/etc/skel/.bashrc missing"

  rm -f /etc/ld.so.preload

  # /etc/environment keeps only PATH.
  grep -E '^PATH=' /etc/environment > "$WORK_DIR/environment.keep" 2>/dev/null
  cat "$WORK_DIR/environment.keep" > /etc/environment

  sed -i '/PROMPT_COMMAND/d' /etc/profile.d/*.sh 2>/dev/null

  for account in root sysadmin; do
    id "$account" &>/dev/null || continue

    home_dir=$(getent passwd "$account" | cut -d: -f6)
    [[ -d $home_dir ]] || continue

    rm -f "$home_dir"/.bashrc "$home_dir"/.profile "$home_dir"/.bash_profile \
          "$home_dir"/.bash_login "$home_dir"/.bash_logout "$home_dir"/.bash_aliases \
          "$home_dir"/.inputrc

    cp /etc/skel/.bashrc /etc/skel/.profile /etc/skel/.bash_logout "$home_dir"/

    chown "$account:$(id -gn "$account")" "$home_dir"/.bashrc "$home_dir"/.profile "$home_dir"/.bash_logout
    chmod 644 "$home_dir"/.bashrc "$home_dir"/.profile "$home_dir"/.bash_logout
  done
}

# Set the new passwords collected during pre-flight.
step_change_passwords() {
  printf '%s:%s\n' "$INVOKING_USER" "$NEW_USER_PASSWORD" | chpasswd \
    || add_warning "user password change failed"

  printf 'root:%s\n' "$NEW_ROOT_PASSWORD" | chpasswd \
    || add_warning "root password change failed"
}

# Kill every logged-in terminal session except the one running this script.
step_kill_other_sessions() {
  local terminal

  who | awk '{print $2}' | sort -u | while read -r terminal; do
    [[ "/dev/$terminal" == "$INVOKING_TTY" ]] && continue
    pkill -9 -t "$terminal"
  done
}

# apt update, install fish and make sure it is a valid login shell.
step_install_fish() {
  local fish_path

  apt-get update || add_warning "apt update failed"
  apt-get "${APT_OPTIONS[@]}" install fish || add_warning "fish install failed"

  fish_path=$(command -v fish)
  grep -qx "$fish_path" /etc/shells || echo "$fish_path" >> /etc/shells
}

step_set_root_shell_to_fish() {
  chsh -s "$(command -v fish)" root || add_warning "could not set root shell to fish"
}

# Remove snap entirely. Any snap that looks like a scored or supporting service
# is first migrated to its apt package. If one cannot be migrated, snapd is kept.
step_remove_snap() {
  local scored_service_regex='postfix|dovecot|roundcube|ssh|krb5|kerberos|sssd|php|apache|nginx|mysql|mariadb|postgres'
  local keep_snapd=0
  local migrated_services=()
  local snap_name pass_number

  if command -v snap > /dev/null; then

    # Migrate scored/supporting snaps to apt packages of the same name.
    for snap_name in $(snap list 2>/dev/null | awk 'NR>1 {print $1}' | grep -E "$scored_service_regex"); do
      if apt-cache policy "$snap_name" | grep -q 'Candidate: [^(]' \
         && apt-get "${APT_OPTIONS[@]}" install "$snap_name"; then
        migrated_services+=("$snap_name")
        add_warning "migrated snap $snap_name to apt: copy its config/data manually"
      else
        add_warning "scored snap $snap_name has no apt equivalent: snapd NOT removed"
        keep_snapd=1
      fi
    done

    ((keep_snapd)) && return 1

    # Remove applications first (a few passes for dependency order).
    for pass_number in 1 2 3; do
      for snap_name in $(snap list 2>/dev/null | awk 'NR>1 {print $1}' | grep -Ev '^(snapd|core[0-9]*|bare)$'); do
        snap remove --purge "$snap_name"
      done
    done

    # Then bases (core*, bare, gnome-*), then snapd itself.
    for snap_name in $(snap list 2>/dev/null | awk 'NR>1 {print $1}' | grep -v '^snapd$'); do
      snap remove --purge "$snap_name"
    done
    snap remove --purge snapd
  fi

  systemctl disable --now snapd.service snapd.socket snapd.seeded.service 2>/dev/null

  mount | awk '$3 ~ "^/snap/" {print $3}' | sort -r | xargs -r umount -l

  apt-get "${APT_OPTIONS[@]}" purge snapd
  apt-mark hold snapd

  rm -rf /snap /var/snap /var/lib/snapd /var/cache/snapd /root/snap /home/*/snap

  # Pin snapd so apt never pulls it back in.
  printf 'Package: snapd\nPin: release a=*\nPin-Priority: -10\n' > /etc/apt/preferences.d/nosnap.pref

  # Migrated services may have failed to bind their ports while the snap ran.
  for snap_name in "${migrated_services[@]}"; do
    systemctl restart "$snap_name" 2>/dev/null
  done

  if command -v snap > /dev/null; then
    add_warning "snap binary still present"
    return 1
  fi
}

# Start `apt upgrade` detached in the background, security-relevant packages
# (kernel, PHP, mail stack, auth libraries) first. After the upgrade it purges
# the remote-access packages from PURGE_LIST_FILE.
step_start_background_upgrade() {
  cat > "$WORK_DIR/upgrade.sh" <<'UPGRADE_SCRIPT_EOF'
echo $$ > "$WORK_DIR/upgrade.pid"

APT_OPTIONS=(-y -o DPkg::Lock::Timeout=1800 -o Dpkg::Options::=--force-confold)

priority_regex='^(linux-(image|modules|headers)|php|postfix|dovecot|openssh|openssl|libssl|krb5|libkrb5|sssd|libpam|libc6|sudo|systemd|apache2|nginx|roundcube|libldap|libsasl2)'
priority_packages=$(dpkg-query -W -f='${db:Status-Abbrev} ${binary:Package}\n' \
  | awk -v priority_regex="$priority_regex" '$1=="ii" && $2 ~ priority_regex {print $2}')

# 1. Priority packages first
if [ -n "$priority_packages" ]; then
  apt-get "${APT_OPTIONS[@]}" install --only-upgrade $priority_packages
fi

# 2. Everything else (--with-new-pkgs lets new kernels install, like `apt upgrade`)
apt-get "${APT_OPTIONS[@]}" --with-new-pkgs upgrade
echo "upgrade=$?" > "$WORK_DIR/upgrade_status"

# 3. Purge unscored remote-access packages
installed_purge_targets=""
for package in $(cat "$WORK_DIR/purge.list"); do
  if dpkg -s "$package" > /dev/null 2>&1; then
    installed_purge_targets="$installed_purge_targets $package"
  fi
done

if [ -n "$installed_purge_targets" ]; then
  apt-get "${APT_OPTIONS[@]}" purge $installed_purge_targets
fi

apt-get "${APT_OPTIONS[@]}" autoremove --purge
echo "purge=$?" >> "$WORK_DIR/upgrade_status"
UPGRADE_SCRIPT_EOF

  setsid nohup /bin/bash --noprofile --norc "$WORK_DIR/upgrade.sh" \
    < /dev/null > "$UPGRADE_LOG" 2>&1 &
}

# Wait for the parallel nftbuild download, install it and run it.
step_run_nftbuild() {
  while [[ ! -f $NFTBUILD_FETCH_STATUS_FILE ]]; do
    sleep 1
  done

  if [[ $(cat "$NFTBUILD_FETCH_STATUS_FILE") != 0 ]]; then
    add_warning "nftbuild download failed"
    return 1
  fi

  install -m 700 -o root -g root "$WORK_DIR/nftbuild" /usr/local/sbin/nftbuild

  /usr/local/sbin/nftbuild -sys mail -ssh ei || add_warning "nftbuild exited non-zero"
}

# Neutralise unscored remote-access tools immediately: stop and mask their
# services and make their binaries unexecutable. Packages are purged later.
step_disable_remote_access_tools() {
  local service_name binary_name binary_path

  for service_name in telnet.socket telnetd xinetd inetd vsftpd proftpd pure-ftpd tftpd-hpa \
                      smbd nmbd nfs-server snmpd xrdp vncserver x11vnc cockpit.socket cockpit \
                      webmin openvpn teamviewerd anydesk tmate autossh; do
    if systemctl cat "$service_name" &>/dev/null; then
      systemctl disable --now "$service_name"
      systemctl mask "$service_name"
    fi
  done

  for binary_name in nc ncat netcat socat telnet tmate rsh rlogin rcp x11vnc vncserver xrdp anydesk teamviewer; do
    binary_path=$(command -v "$binary_name") && chmod 000 "$(readlink -f "$binary_path")"
  done
}

# Verify bootloader and kernel packages, reinstall on tampering, strip dangerous
# kernel parameters, regenerate grub config and initramfs, warn if unfixable.
step_check_bootloader() {
  local boot_packages tampered_files

  boot_packages=$(installed_packages_matching '^(grub|shim|linux-image|linux-modules)')

  list_tampered_boot_files() {
    dpkg --verify $boot_packages 2>/dev/null | grep -v ' c /'
  }

  if [[ -n $(list_tampered_boot_files) ]]; then
    add_warning "bootloader/kernel files failed verification, reinstalling"
    apt-get "${APT_OPTIONS[@]}" --reinstall install $boot_packages
  fi

  # Remove kernel parameters that give a shell or swap init.
  sed -i -E 's/ ?(init=[^" ]*|rd\.break[^" ]*|systemd\.unit=[^" ]*|single)//g' /etc/default/grub

  grep -rEl 'init=/|rd\.break' /etc/grub.d 2>/dev/null | while read -r script_path; do
    add_warning "suspicious grub.d script: $script_path"
  done

  chown root:root /boot/grub/grub.cfg 2>/dev/null
  update-grub
  update-initramfs -u -k all

  if grep -Eq 'init=/|rd\.break|systemd\.unit=' /boot/grub/grub.cfg; then
    add_warning "grub.cfg still has suspicious kernel params"
  fi

  tampered_files=$(list_tampered_boot_files)
  if [[ -n $tampered_files ]]; then
    add_warning "UNFIXABLE bootloader tampering, inspect manually: $(echo "$tampered_files" | head -5 | tr '\n' ';')"
  fi
}

# Least-privilege ownership and modes across /etc, /root, homes and the filesystem.
# authorized_keys files are deliberately never touched (another tool manages them).
step_fix_permissions() {
  local home_dir home_user suid_file

  # --- Top-level directories ---
  chown root:root / /etc /root
  chmod 755 / /etc
  chmod 700 /root
  find /root ! -name 'authorized_keys*' -exec chown -h root:root {} +

  # --- /etc: everything root-owned, nothing group/world writable ---
  find /etc -xdev ! -user root -exec chown root {} + 2>/dev/null
  find /etc -xdev ! -type l \( -perm -0002 -o -perm -0020 \) -exec chmod go-w {} + 2>/dev/null

  # --- Account databases and sudo ---
  chmod 644 /etc/passwd /etc/group
  chown root:shadow /etc/shadow /etc/gshadow
  chmod 640 /etc/shadow /etc/gshadow
  chmod 440 /etc/sudoers
  chmod 750 /etc/sudoers.d
  chmod 440 /etc/sudoers.d/* 2>/dev/null

  # --- ssh, kerberos and sssd secrets ---
  chmod 600 /etc/ssh/sshd_config /etc/ssh/ssh_host_*_key /etc/krb5.keytab /etc/sssd/sssd.conf 2>/dev/null
  chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null
  chmod 700 /etc/sssd 2>/dev/null

  # --- dovecot ---
  chmod 640 /etc/dovecot/dovecot-ldap.conf.ext /etc/dovecot/dovecot-sql.conf.ext 2>/dev/null
  chown root:dovecot /etc/dovecot/dovecot-ldap.conf.ext 2>/dev/null

  # --- roundcube (config holds credentials, web server group may read) ---
  if [[ -d /etc/roundcube ]]; then
    chown -R root:www-data /etc/roundcube
    find /etc/roundcube -type d -exec chmod 750 {} +
    find /etc/roundcube -type f -exec chmod 640 {} +
  fi

  # --- postfix ---
  if command -v postfix > /dev/null; then
    postfix set-permissions
  fi

  # --- cron ---
  chmod 600 /var/spool/cron/crontabs/* 2>/dev/null
  chmod 644 /etc/crontab

  # --- home directories: owned by their user, private ---
  for home_dir in /home/*/; do
    home_dir=${home_dir%/}
    home_user=${home_dir##*/}

    if id "$home_user" &>/dev/null; then
      find "$home_dir" ! -name 'authorized_keys*' -exec chown -h "$home_user:$(id -gn "$home_user")" {} +
    else
      find "$home_dir" ! -name 'authorized_keys*' -exec chown -h root:root {} +
      add_warning "home without user: $home_dir"
    fi

    chmod 700 "$home_dir"
  done

  # --- Whole filesystem: no world-writable files, no unsticky world-writable dirs ---
  find / -xdev -type f ! -name 'authorized_keys*' -perm -0002 -exec chmod o-w {} + 2>/dev/null
  find / -xdev -type d -perm -0002 ! -perm -1000 -exec chmod o-w {} + 2>/dev/null

  # --- setuid/setgid files that no package owns lose those bits ---
  find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read -r suid_file; do
    if ! is_package_owned "$suid_file"; then
      chmod ug-s "$suid_file"
      add_warning "stripped suid/sgid from unpackaged file: $suid_file"
    fi
  done
}

# Verify key binaries (ssh, sudo, PAM, mail stack, libc, apt, ...) against dpkg
# checksums and reinstall any that were modified.
step_check_binary_integrity() {
  local critical_package_regex='^(openssh-server|openssh-client|openssh-sftp-server|sudo|login|passwd|util-linux|coreutils|bash|libc6|apt|dpkg|libpam-modules|libpam-modules-bin|libpam-runtime|libpam0g|libpam-krb5|libpam-sss|libnss-sss|krb5-user|libkrb5-3|sssd|sssd-common|postfix|postfix-ldap|dovecot-core|dovecot-imapd|dovecot-pop3d|dovecot-ldap|systemd|openssl)$'
  local tampered_packages=()
  local package changed_files

  for package in $(installed_packages_matching "$critical_package_regex"); do
    if package_failed_verification "$package"; then
      tampered_packages+=("$package")
    fi
  done

  ((${#tampered_packages[@]} == 0)) && return 0

  add_warning "binary integrity failed, reinstalling: ${tampered_packages[*]}"
  apt-get "${APT_OPTIONS[@]}" --reinstall install "${tampered_packages[@]}"

  for package in "${tampered_packages[@]}"; do
    if package_failed_verification "$package"; then
      changed_files=$(dpkg --verify "$package" | grep -v ' c /' | awk '{print $NF}' | head -3 | tr '\n' ' ')
      add_warning "STILL TAMPERED after reinstall: $package ($changed_files)"
    fi
  done
}

# Kernel and network hardening that does not affect ssh or mail delivery.
step_apply_sysctl_hardening() {
  cat > /etc/sysctl.d/99-megascript.conf <<'SYSCTL_EOF'
# Network: no forwarding, no redirects, no source routing, spoof protection
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Kernel: ASLR, hide kernel pointers and logs, restrict ptrace and BPF
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.yama.ptrace_scope = 2
-dev.tty.legacy_tiocsti = 0
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Filesystem: no suid core dumps, protected links and fifos
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
SYSCTL_EOF
  chmod 644 /etc/sysctl.d/99-megascript.conf

  # Disable core dumps for all users.
  echo '* hard core 0' > /etc/security/limits.d/99-nocore.conf
  chmod 644 /etc/security/limits.d/99-nocore.conf

  sysctl --system || add_warning "sysctl --system reported errors (see $MAIN_LOG)"
}

# Read-only audit of postfix, dovecot, PHP and roundcube. Nothing is changed,
# findings go to the final report.
step_check_mail_and_php() {
  local mynetworks php_ini_file installer_dir php_file

  # --- postfix: open relay and TLS ---
  if command -v postconf > /dev/null; then
    mynetworks=$(postconf -h mynetworks 2>/dev/null)

    if echo "$mynetworks" | grep -Eq '(^|[ ,])(0\.0\.0\.0|::)/0|(^|[ ,])[0-9.]+/([0-9]|1[0-5])([ ,]|$)'; then
      add_warning "POSTFIX mynetworks is very broad (possible open relay): $mynetworks"
    fi

    if ! postconf -h smtpd_relay_restrictions smtpd_recipient_restrictions 2>/dev/null | grep -q reject_unauth_destination; then
      add_warning "POSTFIX: reject_unauth_destination not in relay/recipient restrictions (possible open relay)"
    fi

    if ! postconf -h smtpd_tls_security_level 2>/dev/null | grep -Eq 'may|encrypt'; then
      add_warning "POSTFIX: smtpd TLS not enabled"
    fi
  fi

  # --- dovecot: TLS and plaintext auth ---
  if command -v doveconf > /dev/null; then
    [[ $(doveconf -h ssl 2>/dev/null) == no ]] \
      && add_warning "DOVECOT: ssl = no"

    [[ $(doveconf -h disable_plaintext_auth 2>/dev/null) == no ]] \
      && add_warning "DOVECOT: disable_plaintext_auth = no"
  fi

  # --- PHP: risky settings in every php.ini ---
  for php_ini_file in /etc/php/*/*/php.ini; do
    [[ -f $php_ini_file ]] || continue

    grep -Eiq '^\s*expose_php\s*=\s*(on|1)' "$php_ini_file" \
      && add_warning "PHP expose_php is On: $php_ini_file"

    grep -Eiq '^\s*display_errors\s*=\s*(on|1|stdout)' "$php_ini_file" \
      && add_warning "PHP display_errors is On: $php_ini_file"

    grep -Eiq '^\s*allow_url_include\s*=\s*(on|1)' "$php_ini_file" \
      && add_warning "PHP allow_url_include is On: $php_ini_file"
  done

  # --- roundcube: leftover installer and info-leak files ---
  find /usr/share/roundcube /var/lib/roundcube /var/www /opt -maxdepth 4 -type d -name installer 2>/dev/null \
    | while read -r installer_dir; do
        if [[ $installer_dir == *oundcube* || -f $installer_dir/../program/include/iniset.php ]]; then
          add_warning "ROUNDCUBE installer dir present: $installer_dir"
        fi
      done

  grep -Eqs "enable_installer'\]?\s*=\s*true" /etc/roundcube/*.php \
    && add_warning "ROUNDCUBE enable_installer is true"

  grep -rIl --include='*.php' 'phpinfo\s*(' /var/www /usr/share/roundcube 2>/dev/null \
    | while read -r php_file; do
        add_warning "phpinfo() found: $php_file"
      done
}

# Delete temporary files. systemd-private-* dirs are kept because running
# services (PrivateTmp=) depend on them.
step_remove_temp_files() {
  find /tmp /var/tmp -xdev -mindepth 1 -maxdepth 1 ! -name 'systemd-private-*' -exec rm -rf {} + 2>/dev/null

  rm -rf /dev/shm/* /var/crash/* /root/.cache 2>/dev/null
}

# Kill processes running from memory only (deleted binary or memfd). Package
# binaries replaced by the upgrade are NOT killed (that would take down sshd and
# friends), they are listed as "restart needed" instead.
step_stop_memory_only_processes() {
  local proc_dir pid exe_path binary_path

  for proc_dir in /proc/[0-9]*; do
    pid=${proc_dir#/proc/}
    [[ $pid == "$SCRIPT_PID" ]] && continue

    exe_path=$(readlink "$proc_dir/exe" 2>/dev/null) || continue

    case $exe_path in
      *' (deleted)' | /memfd:*) ;;
      *) continue ;;
    esac

    binary_path=${exe_path% (deleted)}

    if [[ $exe_path != /memfd:* ]] && is_package_owned "$binary_path"; then
      add_warning "packaged binary updated, restart needed: pid $pid ($binary_path)"
      continue
    fi

    kill -9 "$pid" && add_warning "killed memory-only process $pid ($exe_path)"
  done
}

step_reload_systemd() {
  systemctl daemon-reload
}


# =============================================================================
# 4. STEP TABLE
# =============================================================================
# Format: "estimated seconds|description|function"
# Estimates drive the progress bar and ETA, and are rescaled by how fast the
# earlier steps actually ran.

STEPS=(
  "25|Reset shell profiles and PROMPT_COMMAND|step_reset_shell_profiles"
  "3|Change user and root passwords|step_change_passwords"
  "2|Kill other shell sessions|step_kill_other_sessions"
  "60|apt update and install fish|step_install_fish"
  "1|Set root shell to fish|step_set_root_shell_to_fish"
  "60|Migrate scored snaps, remove snap|step_remove_snap"
  "3|Start background apt upgrade|step_start_background_upgrade"
  "20|Run nftbuild|step_run_nftbuild"
  "15|Disable unscored remote access tools|step_disable_remote_access_tools"
  "40|Check and fix bootloader|step_check_bootloader"
  "40|Fix permissions and ownership|step_fix_permissions"
  "60|Binary integrity check|step_check_binary_integrity"
  "3|Apply sysctl hardening|step_apply_sysctl_hardening"
  "5|Mail and PHP read-only checks|step_check_mail_and_php"
  "3|Remove temp files|step_remove_temp_files"
  "3|Stop memory-only processes|step_stop_memory_only_processes"
  "2|Daemon reload|step_reload_systemd"
)


# =============================================================================
# 5. RUNNER AND FINAL REPORT
# =============================================================================

BAR_FILLED='##############################'
BAR_EMPTY='..............................'
BAR_WIDTH=30

# run_all_steps
#   Run each step in the background and redraw a per-step progress bar (based on
#   its estimate) plus an overall ETA until it finishes.
run_all_steps() {
  local total_steps=${#STEPS[@]}
  local total_estimate_seconds=0
  local finished_estimate_seconds=0
  local run_start=$SECONDS
  local step_number=0

  local step_entry estimate_seconds description function_name
  local step_pid step_start elapsed percent filled_width
  local speed_ratio_percent eta_seconds exit_code

  for step_entry in "${STEPS[@]}"; do
    total_estimate_seconds=$((total_estimate_seconds + ${step_entry%%|*}))
  done

  for step_entry in "${STEPS[@]}"; do
    IFS='|' read -r estimate_seconds description function_name <<< "$step_entry"
    step_number=$((step_number + 1))
    step_start=$SECONDS

    "$function_name" >> "$MAIN_LOG" 2>&1 &
    step_pid=$!

    while kill -0 "$step_pid" 2>/dev/null; do
      elapsed=$((SECONDS - step_start))

      percent=$((elapsed * 100 / estimate_seconds))
      ((percent > 99)) && percent=99
      filled_width=$((percent * BAR_WIDTH / 100))

      # How much slower/faster than estimated the finished steps ran (100 = on time).
      speed_ratio_percent=100
      if ((finished_estimate_seconds > 0)); then
        speed_ratio_percent=$(( (SECONDS - run_start) * 100 / finished_estimate_seconds ))
      fi

      eta_seconds=$(( (total_estimate_seconds - finished_estimate_seconds) * speed_ratio_percent / 100 - elapsed ))
      ((eta_seconds < 0)) && eta_seconds=0

      printf '\r\033[K[%d/%d] %s [%s%s] %d%% | overall ETA ~%ds' \
        "$step_number" "$total_steps" "$description" \
        "${BAR_FILLED:0:filled_width}" "${BAR_EMPTY:0:BAR_WIDTH-filled_width}" \
        "$percent" "$eta_seconds"

      sleep 0.5
    done

    wait "$step_pid"
    exit_code=$?
    finished_estimate_seconds=$((finished_estimate_seconds + estimate_seconds))

    printf '\r\033[K[%d/%d] %s [%s] done in %ds%s\n' \
      "$step_number" "$total_steps" "$description" "$BAR_FILLED" \
      "$((SECONDS - step_start))" \
      "$([[ $exit_code -ne 0 ]] && echo " (rc=$exit_code, see $MAIN_LOG)")"
  done

  echo
  echo "Total time: $((SECONDS - run_start))s"
}

# report_results
#   Print warnings, then the state of the background apt upgrade. If it is still
#   running, stream its output until it finishes.
report_results() {
  if [[ -s $WARNINGS_FILE ]]; then
    echo "--- Attention ---"
    cat "$WARNINGS_FILE"
  fi

  echo "--- apt upgrade (background) ---"

  if [[ -f $UPGRADE_STATUS_FILE ]] && grep -q '^purge=' "$UPGRADE_STATUS_FILE"; then
    echo "Finished: $(tr '\n' ' ' < "$UPGRADE_STATUS_FILE")"
  else
    echo "Still running. Live output (ends when it finishes):"
    tail -n 20 -f --pid="$(cat "$UPGRADE_PID_FILE" 2>/dev/null)" "$UPGRADE_LOG"
    echo "Finished: $(tr '\n' ' ' < "$UPGRADE_STATUS_FILE" 2>/dev/null)"
  fi

  echo "Logs: $MAIN_LOG  $UPGRADE_LOG (tmpfs, gone on reboot)"
}

run_all_steps

# Passwords are no longer needed.
unset NEW_USER_PASSWORD NEW_ROOT_PASSWORD

report_results