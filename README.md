What is this
---

An experiment to implement a universal optimistic execution cache.
The aim is to end up with a tool like so:
```
oc run make
```
`oc` is a wrapper around other commands. It traces and records the runtime
dependencies (e.g. file system accesses) of the specified program.
If run a second time, it checks the recorded trace, and if the
dependencies didn't invalidate since the last call, it opts to not run
the program at all. This becomes especially useful with child processes.

The cache may even be utilized before the executed program returns.
In this case we could do:
```
oc run bash
```
which will cache all executed commands in the shell. In fact
with this approach we can keep the cache in memory all the time.
So actually, first goal will be to support this rather than storing
the cache on disk.

The cache is "optimistic" in the sense that it cannot possibly
account for all impure runtime dependencies of the tracee, which
means there will be false positive cache hits. Example would be:
```
oc wget "http://bla"
```
where we cannot reason about whether `http://bla` has changed
since last call. Other example would be reading `/dev/random`.
We can however make the cache configurable so that e.g.
it doesn't care about network access (assumes they always return the same
thing), or it always invalidates the cache on network calls (e.g. for impurity-fest
build systems like `pip` ).

TODO
---

0. Tracing forks
0. Tracing syscalls
0. Retrieve syscall arguments (https://docs.rs/libc/0.2.80/libc/fn.process_vm_readv.html)
0. Intercept `execve`
0. Cache structure (flexible key). LRU/LFU? Track "heaviness" of cached compute?
0. Cache: execve args
0. Cache: execve env
0. Cache: FS calls
0. Cache: network? Always invalidate? Configurable?
