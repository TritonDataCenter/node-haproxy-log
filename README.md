# haproxy-log: haproxy log file parser

This module provides a very basic parser for the haproxy "HTTP" log file format
as recorded by syslog.  For information about the haproxy log file, see the
[haproxy
documentation](http://www.haproxy.org/download/1.5/doc/configuration.txt).
There's a great deal of detail in the section called "Logging".

This implementation is somewhat restrictive in the format that it recognizes.
Unrecognized lines generate a warning to stderr or cause the program to exit
prematurely with an error.


## Synopsis

To install the command-line tool:

    $ npm install -g haproxy-log
    ...
    $ haplog my-haproxy-log.txt

You may also use the parser object directly.  For an example, see the
implementation of the "haplog" command.


## Contributing

See separate [contribution guidelines](CONTRIBUTING.md).
