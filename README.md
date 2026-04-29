# Binmon
Short for "Binary Monitor", it's a small project where I plan on using C and potentially eBPF or other related technologies to gather telemetry about different running processes on a Linux system. With these processes, I can determine if they need to be "optimized" either by removal or replacement. The "Binary" part is part of my main vision: to search for binaries or other installed items and use data such as "how long ago was this used" or "when was this downloaded" to determine whether it can be removed. I have this feeling that if I'm using some sort of Linux system for a long time, I've downloaded random stuff in the past without removing it. So I want a programmatic approach to detect these long-gone toolings and just remove them. But this is also a sort of IDS system, in a way, just for endpoints as well.

# Disclaimer
Still very much a work in progress, and I guarantee this does not work at all, but I have it pushed to master because I'm the only one working on this project, so this just acts as a "Ctrl-s" in a way.

# How to Use
```bash
curl -LO https://raw.githubusercontent.com/cjn4825/Binmon/master/scripts/server_setup/bootstrap.sh
./bootstrap.sh
```

# Goals
As I said in the long description at the top, I want a way to eliminate the "I installed a tool a couple of months ago for testing and forgot to remove it, so it's taking a super small percentage of storage and resources" issue I have.

* Definitely more, but I get to it later...
