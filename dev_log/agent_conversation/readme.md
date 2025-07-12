I don't have a lot of the convos added and gave up on even organizing them.
Most conversations I just ended at some point as it would keep filling up useless or incorrect code.

In one case it implemented tests that just called to the parent OS and tried to run the program ... to rename files live in the repo -- vs using the TempDir generators that all the tests used.  [horror]

I'd like to find a way to make these things useful ... but they've just been bad.  They're not even very helpful for syntax as they often try to use deprecated methods.

An agent that just pulls API docs and example use running in the side could be useful.
Having them generate code is kinda nuts.

Alternatively, with clear measureables, they may be able to just loop in a sandbox to generate code to sample from -- e.g. for tests or certain side functions or display stuff.
