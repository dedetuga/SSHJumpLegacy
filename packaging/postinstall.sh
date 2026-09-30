#!/bin/sh
# POSTINSTALLSCRIPT — run as root (systemd oneshot) by install-package.sh right
# after the app is installed, on EVERY install. Makes the .eap self-configuring
# so a plain `install-package.sh install` works without the extra install-dev.sh
# steps.
#
# What it fixes: Axis' classic web path (mod_trax + TransferMethodProxy) uses a
# proprietary fd-passing IPC and wants to BIND /var/run/http/<app>/http itself,
# which collides with our daemon's listener (errno 98) -> the browser gets
# "daemon unreachable". We remove mod_trax's transfer conf for this app and
# reverse-proxy control.cgi with standard mod_proxy_http to the daemon's socket.
APP=sshjump
PKG=/usr/local/packages/$APP
exec >>"$PKG/postinstall.log" 2>&1
echo "== postinstall $(date) =="

# 1) swap mod_trax (fdipc) for standard mod_proxy_http on control.cgi
rm -f /etc/apache2/transfer/transfer_$APP.conf
if [ -d /etc/apache2/conf.d/vhosts/all ]; then
    cp "$PKG/zz_${APP}_proxy.conf" /etc/apache2/conf.d/vhosts/all/zz_${APP}_proxy.conf
else
    # fall back to a generic conf.d location if the vhost dir differs
    cp "$PKG/zz_${APP}_proxy.conf" /etc/apache2/conf.d/zz_${APP}_proxy.conf 2>/dev/null
fi
mkdir -p /var/run/http/$APP && chmod 777 /var/run/http/$APP

# 2) enable + start now (STARTMODE=once; also starts after a reboot)
echo "ENABLED=yes" > "$PKG/conf/runstate.conf" 2>/dev/null
/etc/init.d/sdk$APP start 2>/dev/null

# 3) load the new proxy conf (mod_proxy needs a restart, not just a reload)
systemctl restart httpd 2>/dev/null || killall -HUP httpd 2>/dev/null

echo "done: proxy wired, app started, httpd restarted"
exit 0
