bitz
====

A BitMessage headless client and library, in development hiatus. 

It's unlikely I'll continue working on this because 1) it's very unlikely that BitMessage will ever become popular, since the barrier to entry is high and there is no evidence that it has any special adoption-easy advantage to existing email alternatives, including PGP 2) I'm having trouble finding a good embedded storage system for Go that is easy for developers to install but it's still feature rich. 

[![Build Status](https://drone.io/github.com/nictuku/bitz/status.png)](https://drone.io/github.com/nictuku/bitz/latest)

The initial focus was to implement the BitMessage protocol and provide a library that others can use.

Speculative project goals:
*  No UI, but maybe a simple web API. Enable the development of a client-side Javascript/HTML5 solution.
*  Simple installation. Download an executable and you're done.
*  Multi-platform. Support for OSX, Linux and Windows.
