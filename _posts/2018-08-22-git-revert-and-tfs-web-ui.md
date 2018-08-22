---
layout: post
title: git revert, diff and apply vs. TFS Web UI
tags: [ git, tfs, revert ]
---

# undoing revert with git diff and git apply

Let's say you were on a vacation and one month later, you changed your mind and want to "revert" your particular commit.
``git revert`` sounds like a logic option, but it has some hidden caveats whose you do not want to test on Microsoft's ``TFS git``.


## Boundary assumptions

Let's assume this is the ``git`` history

```
$ git log

commit aba65f79cfd42ed71a30d13e8514b5bf3916b2e9
Merge: f330352 5a05424
Author: defacedbeef <przemyslaw.duda@gmail.com>
Date:   Wed Aug 22 20:15:09 2018 +0200

    merged revert

commit 5a0542420994f6b6aaaed922a98b618c540a96d5 (test)
Author: defacedbeef <przemyslaw.duda@gmail.com>
Date:   Wed Aug 22 20:11:17 2018 +0200

    Revert "adding foo"
    
    This reverts commit c5fa5debf34e11c76302b460876038bc7d097c29.

commit f330352acdbe6e596e392291608c0e49093bed9f
Author: defacedbeef <przemyslaw.duda@gmail.com>
Date:   Wed Aug 22 20:10:42 2018 +0200

    adding bar on master

commit c5fa5debf34e11c76302b460876038bc7d097c29
Author: defacedbeef <przemyslaw.duda@gmail.com>
Date:   Wed Aug 22 20:08:25 2018 +0200

    adding foo

commit e041d4a169adfb260373173557e7b80ff8d17a84
Author: defacedbeef <przemyslaw.duda@gmail.com>
Date:   Wed Aug 22 20:06:35 2018 +0200

    adding write

commit ff9b8f0f7fd863a56346b9713ae8a17be820852c
Author: defacedbeef <przemyslaw.duda@gmail.com>
Date:   Wed Aug 22 19:56:34 2018 +0200

    hello world.c
```

Here, the commit ``5a054242`` reverts **every** commit down to ``c5fa5debf`` which results in revert of commit ``f330352a`` as well - you do not want to do this.
TFS Web UI won't give you a hint about it. 

## undoing merged revert

You can undo this with with ``git diff`` and ``git apply``. Here is how (assuming you are on the ``master`` branch)

```
$ git checkout -b master_disaster
$ git diff aba65f79 f330352 > patch.diff
$ git apply patch.diff
$ git commit -am 'undoing disaster'
$ git checkout master
$ git merge master_disaster
```

Afterwards, the history is as follows:

$ git log
commit 69326de62e3b78074bf8545dfb3531dc594477e3 (HEAD -> master, master_disaster)
Author: defacedbeef <przemyslaw.duda@gmail.com>
Date:   Wed Aug 22 20:25:25 2018 +0200

    undoing disaster

commit aba65f79cfd42ed71a30d13e8514b5bf3916b2e9
Merge: f330352 5a05424
Author: defacedbeef <przemyslaw.duda@gmail.com>
Date:   Wed Aug 22 20:15:09 2018 +0200

    merged revert

commit 5a0542420994f6b6aaaed922a98b618c540a96d5 (test)
Author: defacedbeef <przemyslaw.duda@gmail.com>
Date:   Wed Aug 22 20:11:17 2018 +0200

    Revert "adding foo"
    
    This reverts commit c5fa5debf34e11c76302b460876038bc7d097c29.

commit f330352acdbe6e596e392291608c0e49093bed9f
Author: defacedbeef <przemyslaw.duda@gmail.com>
Date:   Wed Aug 22 20:10:42 2018 +0200

    adding bar on master

commit c5fa5debf34e11c76302b460876038bc7d097c29
Author: defacedbeef <przemyslaw.duda@gmail.com>
Date:   Wed Aug 22 20:08:25 2018 +0200

    adding foo

commit e041d4a169adfb260373173557e7b80ff8d17a84
Author: defacedbeef <przemyslaw.duda@gmail.com>
Date:   Wed Aug 22 20:06:35 2018 +0200

    adding write

commit ff9b8f0f7fd863a56346b9713ae8a17be820852c
Author: defacedbeef <przemyslaw.duda@gmail.com>
Date:   Wed Aug 22 19:56:34 2018 +0200

    hello world.c
```
