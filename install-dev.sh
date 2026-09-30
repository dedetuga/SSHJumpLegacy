#!/bin/sh
# Install SSH Jump (classic ACAP, ARTPEC-4/5 MIPS). Run as root on the camera:
#   scp sshjump_1_0_0_mipsisa32r2el.eap install-dev.sh root@CAM:/tmp/
#   ssh root@CAM 'sh /tmp/install-dev.sh'
#
# How it works (each point solved a real blocker on AXIS OS 9.70 / ARTPEC-5):
#  * elflibcheck wants an ET_DYN binary: the package-root "sshjump" is a tiny PIE
#    launcher that exec()s the real Go daemon at bin/sshjump (Go can't emit PIE
#    for mipsle), preserving argv/env so pidof/stop keep working.
#  * The web mechanism: Axis' mod_trax uses a proprietary fd-passing IPC and wants
#    to BIND the socket itself (errno 98 EADDRINUSE vs our listener). We remove its
#    transfer conf for this app and reverse-proxy control.cgi with standard
#    mod_proxy_http (zz_sshjump_proxy.conf) to the daemon's HTTP unix socket.
#  * STARTMODE=once: after 30 min idle the daemon exits and stays stopped.
#  * Verbose logs are off by default; set SSHJUMP_DEBUG=1 in the environment for
#    tracing. Logs go to /tmp/sshjump.log.
APP=sshjump
# .eap path: pass as $1, else auto-detect the artpec4/artpec5 build in /tmp
EAP="${1:-$(ls -1 /tmp/${APP}_1_0_0_*mipsisa32r2el.eap 2>/dev/null | head -1)}"
[ -n "$EAP" ] && [ -f "$EAP" ] || { echo "no .eap found in /tmp (pass its path as an argument)"; exit 1; }
echo "using package: $EAP"
PKG=/usr/local/packages/$APP

echo "===== stop/clean previous ====="
/etc/init.d/sdk$APP stop 2>/dev/null
respawn-off "$PKG/$APP" 2>/dev/null
for p in $(pidof $APP 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
# NOTE: do NOT call `acapmanager stop` here - it hangs on a hand-installed app and
# leaves stuck processes. Clean up any that earlier runs left behind:
killall -9 acapmanager 2>/dev/null
sleep 1
rm -rf "$PKG"; mkdir -p "$PKG"

echo "===== unpack eap into $PKG ====="
tar xzf "$EAP" -C "$PKG" && echo "unpack OK" || { echo "unpack FAILED"; exit 1; }
chmod 755 "$PKG/$APP" "$PKG/bin/$APP" 2>/dev/null

echo "===== run the REAL installer ====="
cd "$PKG" || exit 1
/usr/sbin/install-package.sh install; echo "INSTALL_EXIT=$?"
# make sure it is enabled so it also starts after a reboot (STARTMODE=once)
echo "ENABLED=yes" > "$PKG/conf/runstate.conf" 2>/dev/null

echo "===== runtime socket dir ====="
mkdir -p /var/run/http/$APP && chmod 777 /var/run/http/$APP

echo "===== swap mod_trax (fdipc) for standard mod_proxy_http on control.cgi ====="
rm -f /etc/apache2/transfer/transfer_$APP.conf
cp "$PKG/zz_${APP}_proxy.conf" /etc/apache2/conf.d/vhosts/all/zz_${APP}_proxy.conf
echo "installed zz_${APP}_proxy.conf; removed transfer_$APP.conf"

echo "===== start daemon, then restart apache ====="
/etc/init.d/sdk$APP start 2>&1; echo "START_EXIT=$?"
sleep 2
systemctl restart httpd 2>/dev/null || systemctl restart apache2 2>/dev/null || killall -HUP httpd 2>/dev/null
echo "apache restarted"; sleep 2

echo "===== verify ====="
echo -n "-- process:  "; pidof $APP >/dev/null 2>&1 && echo "running (pid $(pidof $APP))" || echo "NOT RUNNING"
echo -n "-- socket:   "; [ -S /var/run/http/$APP/http ] && echo "present" || echo "MISSING"
echo -n "-- direct:   "; curl -s --unix-socket /var/run/http/$APP/http "http://x/control.cgi?op=health"; echo
echo -n "-- anon:     "; curl -s -o /dev/null -w "%{http_code} (expect 401)\n" "http://127.0.0.1/local/$APP/control.cgi?op=health"
echo    "-- authed:   (expect 200 + json)"
curl -s --anyauth -u root:pass -w "   http_status=%{http_code}\n" "http://127.0.0.1/local/$APP/control.cgi?op=health"
echo "-- stuck acapmanager procs (should be none): $(pidof acapmanager 2>/dev/null | wc -w)"
echo "===== DONE — open  http://<camera-ip>/local/$APP/config.html  (admin login) ====="
