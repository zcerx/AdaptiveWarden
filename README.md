# Adaptive Warden

The Adaptive Warden bases the selection of its active rules based on the observed traffic.

#### Adaptive filter CLI options

| Arg                     | Modes    | Description                                                                                       |
|:------------------------|:---------|:--------------------------------------------------------------------------------------------------|
| `-i IN_IP`              | ALL      | Input IP address. Determines the input network device                                             |
| `-o OUT_IP`             | ALL      | Output IP address. Determines the output network device                                           |
| `-m MODE`               | ALL      | Type of warden. Can be 0 (gateway), 1 (static), 2(random), 3 (dynamic), 4(random dynamic) or 5 (adaptive) |
| `-n RULES_COUNT`        | 1, 2 & 3 | no. of rules to use, in case the -l is not specified. To use all rules, provide "all" as the argument to -n |
| `-l RULE_NUMS`          | 1        | list of rules, separated by "," e.g 2,3,4 |
| `-t TIMEOUT`            | 2 & 3    | rules reset timeout in seconds |
| `-pn MAX_PKTS_COUNT`    | 3        | number of packets to filter before INCR_RULES more rules are added |
| `-P PROTO`              | 3        | protocol to be used to filer packets {0:'HOPOPT', 1: 'ICMP', 4: 'IPv4', 6: 'TCP', 17: 'UDP', 132: 'SCTP', 999: 'ALL'} |
| `-I INCR_RULES_COUNT`   | 3        | no. of rules to be incremented in case of MODE 3 |
| `-tr TIMEOUT_RANGE`     | 4        | timeout range in the case of mode 4, e.g. -tr 1-20, -tr 7-89 |
| `-nr RULES_COUNT_RANGE` | 4        | rules count range in the case of mode 4, e.g. -nr 1-3 |
| `-ws WIN_SIZE`          | 5        | the length of the sliding window in seconds (mode 5 only), e.g. -ws 10 |
| `-ic INACTIVE_CP`       | 5        | percentage of initial rules to be used as INACTIVE_CHECKED (mode 5 only), e.g. -ic 10 |
| `-twt T_WIN_TRIG`       | 5        | number of timestamps that must be present to move a rule from INACTIVE_CHECKED to ACTIVE (mode 5 only), e.g. -twt 3 |
