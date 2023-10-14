## What is this?
Just a fun side project. I thought of a fun way to scan a large amount of ports, so I did it.

The trick: Send a bunch of raw SYN packets from the same source port, then pull the source port out of replies.

This solution is likely to not work in some instances, but so far I have found it quite successful.
