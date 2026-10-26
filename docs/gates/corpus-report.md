Corpus run (all phases): 93 cases for 175 E rows; 82 E rows have no case yet.

- Detection: 85 of 93 cases had every bad program rejected for the expected reason
- False rejection: 0 of 93 matched good programs failed to build (limit: 5%)
- Controls failed (plain cargo did not build a checker case's bad program): 0
- Broken cases: 0
- Passed: 85 of 93; of those, 11 rest only on syntax Rust does not have (weakest evidence)

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
| CWE-1235 | language | pass |  |
| CWE-1321 | language | pass |  |
| CWE-1322 | checker | not detected | bad.rs: exit Some(0):  |
| CWE-134 | language | pass |  |
| CWE-1341 | checker | pass |  |
| CWE-170 | checker | pass |  |
| CWE-188 | checker | pass |  |
| CWE-242 | checker | pass |  |
| CWE-243 | checker | pass |  |
| CWE-252 | checker | not detected | bad-bool.rs: exit Some(0):  |
| CWE-395 | language | pass (construct absent) |  |
| CWE-396 | checker | not detected | bad-thread.rs: exit Some(0):  |
| CWE-397 | language | pass (construct absent) |  |
| CWE-415 | checker | pass |  |
| CWE-416 | checker | pass |  |
| CWE-456 | language | pass |  |
| CWE-457 | language | pass |  |
| CWE-460 | language | pass (construct absent) |  |
| CWE-463 | checker | pass |  |
| CWE-464 | checker | pass |  |
| CWE-466 | checker | pass |  |
| CWE-467 | checker | pass |  |
| CWE-468 | checker | pass |  |
| CWE-469 | checker | pass |  |
| CWE-475 | checker | pass |  |
| CWE-476 | checker | pass |  |
| CWE-478 | language | pass |  |
| CWE-479 | checker | pass |  |
| CWE-481 | language | pass |  |
| CWE-482 | checker | pass |  |
| CWE-483 | language | pass |  |
| CWE-484 | language | pass (construct absent) |  |
| CWE-491 | language | pass (construct absent) |  |
| CWE-493 | checker | not detected | bad-interior.rs: exit Some(0):  |
| CWE-495 | language | pass |  |
| CWE-496 | language | pass |  |
| CWE-500 | checker | not detected | bad-interior.rs: exit Some(0):  |
| CWE-543 | checker | pass |  |
| CWE-560 | checker | pass |  |
| CWE-562 | language | pass |  |
| CWE-567 | checker | pass |  |
| CWE-568 | language | pass |  |
| CWE-572 | language | pass |  |
| CWE-580 | language | pass |  |
| CWE-581 | language | pass |  |
| CWE-582 | language | pass |  |
| CWE-583 | language | pass |  |
| CWE-584 | language | pass (construct absent) |  |
| CWE-586 | language | pass |  |
| CWE-587 | checker | pass |  |
| CWE-588 | checker | pass |  |
| CWE-590 | checker | pass |  |
| CWE-597 | language | pass |  |
| CWE-607 | checker | not detected | bad.rs: exit Some(0):  |
| CWE-621 | language | pass (construct absent) |  |
| CWE-624 | language | pass (construct absent) |  |
| CWE-627 | language | pass (construct absent) |  |
| CWE-628 | language | pass |  |
| CWE-683 | checker | not detected | bad.rs: exit Some(0):  |
| CWE-685 | language | pass |  |
| CWE-686 | language | pass |  |
| CWE-690 | checker | pass |  |
| CWE-704 | checker | pass |  |
| CWE-705 | language | pass |  |
| CWE-761 | checker | pass |  |
| CWE-762 | checker | pass |  |
| CWE-763 | checker | pass |  |
| CWE-765 | checker | pass |  |
| CWE-822 | checker | pass |  |
| CWE-823 | checker | pass |  |
| CWE-824 | checker | pass |  |
| CWE-825 | checker | pass |  |
| CWE-832 | checker | pass |  |
| CWE-843 | checker | pass |  |
| CWE-908 | checker | pass |  |
| CWE-910 | checker | pass |  |
| CWE-911 | checker | pass |  |
| CWE-914 | language | pass (construct absent) |  |
| CWE-917 | language | pass |  |
| CWE-95 | language | pass |  |
| CWE-98 | language | pass |  |
