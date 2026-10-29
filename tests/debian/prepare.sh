#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C TZ=UTC
[[ -r /mnt/seed/mode && $(< /mnt/seed/mode) == prepare ]]
exec > >(tee /work/results/prepare.log) 2>&1

# パッケージ準備時だけNICがある。サービスをそのNICへ公開しない。
test ! -e /usr/sbin/policy-rc.d
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d
trap 'rm -f /usr/sbin/policy-rc.d' EXIT
printf 'APT::Keep-Downloaded-Packages "true";\n' > /etc/apt/apt.conf.d/99zcomp-cache
apt-get update
mapfile -t packages < <(tail -n +2 /work/packages-100.tsv | awk -F '\t' '{print $2 "=" $3}')
apt-get install -y --allow-downgrades --no-remove --no-install-recommends \
    "${packages[@]}" python3 gcc openssh-server gpg gpg-agent pamtester \
    libfuse3-dev fonts-dejavu-core xkb-data libxml2-utils
mkdir -p /work/debs-100
cd /work/debs-100
apt-get download "${packages[@]}"
while IFS=$'\t' read -r rank name version arch filename hash; do
    [[ "$rank" == popcon_rank ]] && continue
    found=0
    for deb in ./*.deb; do
        if [[ $(dpkg-deb -f "$deb" Package) == "$name" ]]; then
            printf '%s  %s\n' "$hash" "$deb" | sha256sum -c -
            [[ $(dpkg-query -W -f='${Version}' "$name") == "$version" ]]
            found=1
            break
        fi
    done
    [[ "$found" == 1 ]]
done < /work/packages-100.tsv
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' > /work/installed.tsv
sha256sum /work/debs-100/*.deb > /work/debs-100.sha256
cp /work/debs-100.sha256 /work/debs.sha256
for item in cron.service apt-daily.timer apt-daily-upgrade.timer anacron.timer \
            logrotate.timer apt-listchanges.timer avahi-daemon.socket cups.socket cups.path; do
    systemctl disable --now "$item" 2>/dev/null || true
done
useradd --create-home --uid 1100 --shell /bin/sh testuser
useradd --create-home --uid 1101 --shell /bin/sh zcomp-fixture
chage --lastday 20000 --mindays 0 --maxdays 99999 --warndays 7 zcomp-fixture
printf 'ZCOMP_PROBE=alpha\n' > /etc/environment
python3 /work/experiment.py prepare
touch /work/ready /etc/cloud/cloud-init.disabled
systemctl disable systemd-networkd-wait-online.service
systemctl enable zcomp-test.service
cp /work/installed.tsv /work/debs-100.sha256 /work/results/
sync
