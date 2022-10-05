# PenguinPing
PenguinPing DDoS testing tool

What is PenguinPing?
Security testing is an important information security task, for verification of sites and services before being put into production. This site is about a DDoS testing tool which can help perform structured network and infrastructure testing.

When connecting to the Internet we immediately receive traffic from unknown sources. We should consider testing our infrastructure using active pentest methods, to verify robustness. This talk will be about doing port scans for discovery of infrastructures and detailed advice how to perform active DDoS simulation to find bottlenecks in the network. The attack tools will be already known tools like Nmap and Hping3 with IPv6 patches. The focus is on the process and experiences doing this over many years.

Networks are insecure, and often not as robust as we wish. There is a high risk that networks are vulnerable to one or more DDoS attack vectors, if not tested and verified. When setting up networks we often ignore the built-in features available, and we often have to select which features to enable on specific devices. The vendors tell us they can do everything in every box, but the truth is that attackers can often use more resources than we have available.

## PenguinPing is on Github
PenguinPing is a simple Lua script currently running on top of MoonGen/libmoon. All these can be found on Github:

* PenguinPing - in development, this repository
* [MoonGen](https://github.com/emmericp/MoonGen) and [libmoon](https://github.com/libmoon/libmoon) are the libraries on top of DPDK which are required to run PenguinPing.
* Presentations from TROOPERS22 and Hacktivity 2022 are to be found on Github as well
[DDoS Testing Your Infrastructure, including IPv6 SYN floods](https://github.com/kramse/security-courses/tree/master/presentations/network/ddos-test-troopers22)
