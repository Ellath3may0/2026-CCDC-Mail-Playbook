# General Notes

Update bootloader before even thinking about restarting

## Easy-Copy

- Megascript:
  `env -i PATH=/usr/local/bin:/usr/bin:/bin bash -c 'unalias -a && wget https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/refs/heads/master/linux/mail/megascript.sh && env -i chmod +x megascript.sh && sudo ./megascript.sh'`
- Defender:
  `wget https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/refs/heads/master/linux/defender/linux-defender-1.0.0 && chmod +x linux-defender-1.0.0 && sudo ./linux-defender-1.0.0`
- Force-Reinstall with configs:
  `apt install --reinstall -o Dpkg::Options::="--force-confask,confnew,confmiss" <package-name>`

## Important Links

[Megascript Short](https://tinyurl.com/inv-mega)
[MegaScript](https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/refs/heads/master/linux/mail/megascript.sh)
[Defender Binary](https://raw.githubusercontent.com/UWStout-CCDC/CCDC-scripts/refs/heads/master/linux/defender/linux-defender-1.0.0)
[Defender Github](https://github.com/Slavetomints/linux-defender)
