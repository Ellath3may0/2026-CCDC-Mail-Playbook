# General Notes

Update bootloader before even thinking about restarting

## Easy-Copy

- Paranoia:
  `sudo python3 -c "import urllib.request as u,subprocess as s;u.urlretrieve('https://github.com/Ellath3may0/paranoia/releases/download/v0.1.0/paranoia_0.1.0-1_amd64.deb','/tmp/a.deb');s.run(['dpkg','-i','/tmp/a.deb'])"`
- Defender:
  `wget https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/refs/heads/master/linux/defender/linux-defender-1.0.0 && chmod +x linux-defender-1.0.0 && sudo ./linux-defender-1.0.0`
- Force-Reinstall with configs:
  `apt install --reinstall -o Dpkg::Options::="--force-confask,confnew,confmiss" <package-name>`
- Dovecot auth test
  `sudo doveadm auth test <user>@<domain>`
- AD auth test
 `getent passwd <user>@<domain>`
- Test mail
  `echo "b" | mail -s "s" <receiving user>@<domain>`

## Important Links

[Megascript Short](https://tinyurl.com/inv-mega)
[MegaScript](https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/refs/heads/master/linux/mail/megascript.sh)
[Defender Binary](https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/refs/heads/master/linux/defender/linux-defender-1.0.46)
[Defender Github](https://github.com/Slavetomints/linux-defender)

## Passwords

- sysadmin: smallnail33
- root:     broadiguana26
