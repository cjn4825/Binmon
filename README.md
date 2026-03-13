# Binmon
Short for "Binary Monitor", it's a small project where I plan on using C and potentially eBPF or other related technologies to gather telemetry about different running processes on a Linux system. With these processes, I can determine if they need to be "optimized" either by removal or replacement. The "Binary" part is part of my main vision: to search for binaries or other installed items and use data such as "how long ago was this used" or "when was this downloaded" to determine whether it can be removed. I have this feeling that if I'm using some sort of Linux system for a long time, I've downloaded random stuff in the past without removing it. So I want a programmatic approach to detect these long-gone toolings and just remove them. But this is also a sort of IDS system, in a way, just for endpoints as well.

# Disclaimer
Still very much a work in progress, and I guarantee this does not work at all, but I have it pushed to master because I'm the only one working on this project. And it's pushed at all because at my current internship situation, I can work on this project only using their systems, so I use a weird AWS EC2 instance SSM web interface to work on this from time to time, so this just acts as a "Ctrl-s" in a way.

# Goals
As I said in the long description at the top, I want a way to eliminate the "I installed a tool a couple of months ago for testing and forgot to remove it, so it's taking a super small percentage of storage and resources" issue I have.

* Eventually switch to using using linux sockets to transfer the data in a binary format to a centralized server across a network. The server would then have a dashboard to monitor many different systems running this in the background.

* Definitely more, but I get to it later...
