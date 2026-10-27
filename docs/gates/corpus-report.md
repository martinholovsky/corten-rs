Corpus run (all phases): 174 cases for 175 E rows; 1 E rows have no case yet.

- Detection: 161 of 174 cases had every bad program rejected for the expected reason
- False rejection: 0 of 174 matched good programs failed to build (limit: 5%)
- Controls failed (plain cargo did not build a checker case's bad program): 0
- Broken cases: 0
- Passed: 161 of 174; of those, 12 rest only on syntax Rust does not have (weakest evidence)

- Passed but left unverified until the encoder is independently reviewed: 25

| CWE | Proof kind | Result | Detail |
| --- | --- | --- | --- |
| CWE-1045 | language | pass |  |
| CWE-1055 | language | pass (construct absent) |  |
| CWE-1056 | language | pass |  |
| CWE-1058 | checker | pass |  |
| CWE-1079 | language | pass |  |
| CWE-1082 | language | pass |  |
| CWE-1087 | language | pass |  |
| CWE-1091 | checker | not detected | bad-cycle.rs: exit Some(0):  |
| CWE-1096 | checker | pass |  |
| CWE-1098 | checker | pass |  |
| CWE-111 | checker | pass |  |
| CWE-1123 | checker | pass |  |
| CWE-113 | language | pass (awaiting encoder review) |  |
| CWE-117 | language | pass (awaiting encoder review) |  |
| CWE-1235 | language | pass |  |
| CWE-1236 | language | pass (awaiting encoder review) |  |
| CWE-1321 | language | pass |  |
| CWE-1322 | checker | not detected | bad.rs: exit Some(0):  |
| CWE-1333 | checker | not detected | bad-unlisted.rs: exit Some(0):  |
| CWE-1336 | language | pass (awaiting encoder review) |  |
| CWE-134 | language | pass |  |
| CWE-1341 | checker | pass |  |
| CWE-1386 | checker | pass |  |
| CWE-170 | checker | pass |  |
| CWE-188 | checker | pass |  |
| CWE-22 | checker | pass |  |
| CWE-23 | checker | pass |  |
| CWE-24 | checker | pass |  |
| CWE-242 | checker | pass |  |
| CWE-243 | checker | pass |  |
| CWE-25 | checker | pass |  |
| CWE-252 | checker | not detected | bad-bool.rs: exit Some(0):  |
| CWE-26 | checker | pass |  |
| CWE-27 | checker | pass |  |
| CWE-28 | checker | pass |  |
| CWE-29 | checker | pass |  |
| CWE-30 | checker | pass |  |
| CWE-31 | checker | pass |  |
| CWE-32 | checker | pass |  |
| CWE-33 | checker | pass |  |
| CWE-34 | checker | pass |  |
| CWE-35 | checker | pass |  |
| CWE-36 | checker | pass |  |
| CWE-363 | checker | pass |  |
| CWE-37 | checker | pass |  |
| CWE-378 | checker | pass |  |
| CWE-38 | checker | pass |  |
| CWE-39 | checker | pass |  |
| CWE-395 | language | pass (construct absent) |  |
| CWE-396 | checker | not detected | bad-thread.rs: exit Some(0):  |
| CWE-397 | language | pass (construct absent) |  |
| CWE-40 | checker | pass |  |
| CWE-403 | checker | pass |  |
| CWE-415 | checker | pass |  |
| CWE-416 | checker | pass |  |
| CWE-42 | checker | pass |  |
| CWE-426 | checker | pass |  |
| CWE-427 | checker | pass |  |
| CWE-428 | checker | pass |  |
| CWE-43 | checker | pass |  |
| CWE-44 | checker | pass |  |
| CWE-45 | checker | pass |  |
| CWE-456 | language | pass |  |
| CWE-457 | language | pass |  |
| CWE-46 | checker | pass |  |
| CWE-460 | language | pass (construct absent) |  |
| CWE-463 | checker | pass |  |
| CWE-464 | checker | pass |  |
| CWE-466 | checker | pass |  |
| CWE-467 | checker | pass |  |
| CWE-468 | checker | pass |  |
| CWE-469 | checker | pass |  |
| CWE-47 | checker | pass |  |
| CWE-475 | checker | pass |  |
| CWE-476 | checker | pass |  |
| CWE-478 | language | pass |  |
| CWE-479 | checker | pass |  |
| CWE-48 | checker | pass |  |
| CWE-481 | language | pass |  |
| CWE-482 | checker | pass |  |
| CWE-483 | language | pass |  |
| CWE-484 | language | pass (construct absent) |  |
| CWE-49 | checker | pass |  |
| CWE-491 | language | pass (construct absent) |  |
| CWE-493 | checker | not detected | bad-interior.rs: exit Some(0):  |
| CWE-495 | language | pass |  |
| CWE-496 | language | pass |  |
| CWE-50 | checker | pass |  |
| CWE-500 | checker | not detected | bad-interior.rs: exit Some(0):  |
| CWE-51 | checker | pass |  |
| CWE-52 | checker | pass |  |
| CWE-53 | checker | pass |  |
| CWE-54 | checker | pass |  |
| CWE-543 | checker | pass |  |
| CWE-55 | checker | pass |  |
| CWE-56 | checker | pass |  |
| CWE-560 | checker | pass |  |
| CWE-562 | language | pass |  |
| CWE-564 | language | pass (awaiting encoder review) |  |
| CWE-567 | checker | pass |  |
| CWE-568 | language | pass |  |
| CWE-57 | checker | pass |  |
| CWE-572 | language | pass |  |
| CWE-580 | language | pass |  |
| CWE-581 | language | pass |  |
| CWE-582 | language | pass |  |
| CWE-583 | language | pass |  |
| CWE-584 | language | pass (construct absent) |  |
| CWE-586 | language | pass |  |
| CWE-587 | checker | pass |  |
| CWE-588 | checker | pass |  |
| CWE-59 | checker | pass |  |
| CWE-590 | checker | pass |  |
| CWE-597 | language | pass |  |
| CWE-607 | checker | not detected | bad.rs: exit Some(0):  |
| CWE-61 | checker | pass |  |
| CWE-611 | checker | not detected | bad-unlisted.rs: exit Some(0):  |
| CWE-621 | language | pass (construct absent) |  |
| CWE-624 | language | pass (construct absent) |  |
| CWE-626 | checker | pass |  |
| CWE-627 | language | pass (construct absent) |  |
| CWE-628 | language | pass |  |
| CWE-64 | checker | pass |  |
| CWE-643 | language | pass (awaiting encoder review) |  |
| CWE-644 | language | pass (awaiting encoder review) |  |
| CWE-652 | language | pass (awaiting encoder review) |  |
| CWE-66 | checker | pass |  |
| CWE-67 | checker | pass |  |
| CWE-683 | checker | not detected | bad-private.rs: exit Some(0):  ; bad.rs: exit Some(0):  |
| CWE-685 | language | pass |  |
| CWE-686 | language | pass |  |
| CWE-69 | checker | pass |  |
| CWE-690 | checker | pass |  |
| CWE-692 | language | pass (awaiting encoder review) |  |
| CWE-704 | checker | pass |  |
| CWE-705 | language | pass |  |
| CWE-72 | checker | pass |  |
| CWE-761 | checker | pass |  |
| CWE-762 | checker | pass |  |
| CWE-763 | checker | pass |  |
| CWE-765 | checker | pass |  |
| CWE-77 | checker | pass (awaiting encoder review) |  |
| CWE-776 | checker | not detected | bad-unlisted.rs: exit Some(0):  |
| CWE-78 | checker | pass (awaiting encoder review) |  |
| CWE-79 | language | pass (awaiting encoder review) |  |
| CWE-80 | language | pass (awaiting encoder review) |  |
| CWE-81 | language | pass (awaiting encoder review) |  |
| CWE-82 | language | pass (awaiting encoder review) |  |
| CWE-822 | checker | pass |  |
| CWE-823 | checker | pass |  |
| CWE-824 | checker | pass |  |
| CWE-825 | checker | pass |  |
| CWE-827 | checker | not detected | bad-unlisted.rs: exit Some(0):  |
| CWE-83 | language | pass (awaiting encoder review) |  |
| CWE-832 | checker | pass |  |
| CWE-838 | language | not detected | bad-direct.rs: exit Some(0): warning: item in documentation is missing backticks \| warning: item in documentation is missing backticks \| warning: item in documentation is missing backticks \| warning: item in documentation is missing backticks |
| CWE-84 | language | pass (awaiting encoder review) |  |
| CWE-843 | checker | pass |  |
| CWE-85 | language | pass (awaiting encoder review) |  |
| CWE-86 | language | pass (awaiting encoder review) |  |
| CWE-87 | language | pass (awaiting encoder review) |  |
| CWE-89 | language | pass (awaiting encoder review) |  |
| CWE-90 | language | pass (awaiting encoder review) |  |
| CWE-908 | checker | pass |  |
| CWE-91 | language | pass (awaiting encoder review) |  |
| CWE-910 | checker | pass |  |
| CWE-911 | checker | pass |  |
| CWE-914 | language | pass (construct absent) |  |
| CWE-917 | language | pass |  |
| CWE-93 | language | pass (awaiting encoder review) |  |
| CWE-943 | language | pass (awaiting encoder review) |  |
| CWE-95 | language | pass |  |
| CWE-97 | language | pass (construct absent) |  |
| CWE-98 | language | pass |  |
