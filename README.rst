=========
KeePassJS
=========

A JavaScript port of KeePassLib, providing access to KeePass 1.x files.

Based on the C implementation by Dominik Reichl. http://keepass.info/

This port also wouldn't have been possible without side-by-side
debugging performed against KeePassDroid by Brian Pellin.
http://www.keepassdroid.com/

Because this is based on a GPL implementation, it must itself be GPL.
I have tried to release as much code as possible under more permissive
licenses, as described in the LICENSE file.

Usage
=====

Try cloning this repository and opening the demo/index.html in your
favourite, modern browser. Then add your KeePass file, enter your
password and wait for your entries to be shown to you.

Limitations
===========

Does not support version 0.1 or 0.2 KDB files. If you wish to open
these files with KeePassJS, open them in a native application first
and save them, so that they may be converted to a newer file format.