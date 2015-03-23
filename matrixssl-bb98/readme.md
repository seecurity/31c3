## Basic Documentation

This is a SSL/TLS client that takes a user-defined PreMasterSecret and performs a TLS handshake with it. Furthermore, it measures timing delays between each TLS protocol step and prints a trace with the measured delays on stdout. From there, you can parse the particular timing delay that you are interested in

# Compile:
```a
$ make debug
$ cd apps
$ make debug
```

# Usage:
The client accepts the IP of the TLS server, the PORT number of the TLS server and the base64-coded PreMasterSecret as parameters. It then prints a trace to stdout with debug information that also contains the measured timings.
```
Usage: ./client IP PORT base64(pms)
```
```
$ cd apps
$ ./client 194.95.72.231 443 hX1oTZ5tMy1oD/SXkhwgji1Osp/6NaqyomWbD3MFvYa+qPlXFWRb8IEUMtUahMbQKONJ87R+sIe8r2rH/gREzvJi5sUe+PqqbY/ySX6gciX3rqSN/errz1by+AsxCXME28Rj2XGPI1RbrryQBr+7sREiT0juH1jfEbEiE+Cj1xEH6W9gVnqbaeRAwXi8VcBW8CKvE6E0F4NywUnzoMWk8RjlHAR1MABQHexU7O2cNxPXGoEl+2wzArETeJvM+HkBFHbY8s0utW3EOEgeY08RnrrZujeg2uwnBnvm5v0Sm3D3GlwCX6elWH7M853Y4rwf21T6GN3sUGwB8ViGGqqVgA==
```

# Trace
This is an example trace. You should look at the code to determine which line is interesting for you.
```
=== INITIAL CLIENT SESSION ===
$$$$$$$$$$$$$$ Were sending info
$$$$$$$$$$$$$$ Got state: 0
$$$$$$$$$$$$$$ We were receiving info after 8696741 ticks
$$$$$$$$$$$$$$ We were receiving info after 12291610 ticks
$$$$$$$$$$$$$$ We were receiving info after 15015232 ticks
$$$$$$$$$$$$$$ We were receiving info after 18678512 ticks
Allowing anonymous connection for: www.its.fh-muenster.de.
$$$$$$$$$$$$$$ We were receiving info after 27670513 ticks
%%%%%%%%% PMS is now encrypted$$$$$$$$$$$$$$ Were sending info
$$$$$$$$$$$$$$ Got state: 0
$$$$$$$$$$$$$$ We were receiving info after 25007173 ticks
FAIL: No HTTP Response

=== CLIENT SESSION WITH CACHED SESSION ID ===
$$$$$$$$$$$$$$ Were sending info
$$$$$$$$$$$$$$ Got state: 0
$$$$$$$$$$$$$$ We were receiving info after 7996353 ticks
$$$$$$$$$$$$$$ We were receiving info after 8187028 ticks
$$$$$$$$$$$$$$ We were receiving info after 8708341 ticks
Allowing anonymous connection for: www.its.fh-muenster.de.
$$$$$$$$$$$$$$ We were receiving info after 17680468 ticks
%%%%%%%%% PMS is now encrypted$$$$$$$$$$$$$$ Were sending info
$$$$$$$$$$$$$$ Got state: 0
$$$$$$$$$$$$$$ We were receiving info after 21680693 ticks
FAIL: No HTTP Response
```
