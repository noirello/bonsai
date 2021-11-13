#!/usr/bin/env bash

# refs:
# https://github.com/MicrosoftDocs/vsts-docs/issues/3784
# https://forums.docker.com/t/docker-for-mac-unattended-installation/27112

# update: https://github.com/docker/for-mac/issues/2359#issuecomment-853420567
# update: https://github.com/docker/for-mac/issues/2359#issuecomment-943131345

# Docker 4.2.0,70708
curl https://raw.githubusercontent.com/Homebrew/homebrew-cask/50e49106c339cb88c81df3dabec5e04b7a5d77e1/Casks/docker.rb -o ./docker.rb

brew install --cask ./docker.rb
sudo /Applications/Docker.app/Contents/MacOS/Docker --unattended --install-privileged-components
open -a /Applications/Docker.app --args --unattended --accept-license
while ! /Applications/Docker.app/Contents/Resources/bin/docker info &>/dev/null; do sleep 1; done

sudo /bin/chmod 544 /Library/PrivilegedHelperTools/com.docker.vmnetd
sudo /bin/chmod 644 /Library/LaunchDaemons/com.docker.vmnetd.plist
sudo /bin/launchctl load /Library/LaunchDaemons/com.docker.vmnetd.plist

sleep 5