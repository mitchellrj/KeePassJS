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

Editing, creation and repair of files is not currently supported and
cases for their use in the browser are limited, so I do not plan to
implement them in the near future.

Paranoia
========

I understand some users will have doubts about giving their file and
password to the browser. If you are concerned, try running the browser
in offline mode. At the end of the day, you just have to trust the
developer, as you would do with any other implementation of KeePass.