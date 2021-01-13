# Adaptive Warden

The adaptive warden is a novel countermeasure for sophisticated network covert channels. It was implemented by M. Chourib. For the simulation of a NEL-capable covert channel, you can use the [NELtool](https://github.com/cdpxe/NELphase).

This repository accompanies the following paper submission:

M. Chourib, S. Wendzel, W. Mazurczyk: *Eliminating Network Covert Channels with the Adaptive Warden*.

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


## Adaptive Filter CLI Help.

> WINDOW_COUNTER[rule].triggerlist: the list of “triggers” for the rule “rule”: 
> it contains a list of timestamps at which the rule would have been activated 
> by a packet would the rule have been active; number of rules for which such lists are needed is INACTIVE_CHECKED.
>
> count_entries(): just a function to count the number of timestamps of a rule
>
> INACTIVE_CHECKED: % of inactive rules that are not applied but tested whether incoming packets match them; values for testing: 5%, 20% [10%]

`WINDOW_COUNTER` is a key-val data store implemented in such a way that `WINDOW_COUNTER[rule_number]` returns a list of trigger timestamps for that rule (rule number). A trigger timestamp is a point in time at which an `inactive_checked` rule would ahve been activated by a packet would the rule have been `active`.

Programmatically, `WINDOW_COUNTER` resembles the data structure below.
```
{
  RULE_NUMBER1: [ TIMESTAMP1, TIMESTAMP2, ..., TIMESTAMP-n ],
  RULE_NUMBER2: [ TIMESTAMP1, TIMESTAMP2, ..., TIMESTAMP-n ],
  ...,
  RULE_NUMBER-n: [ TIMESTAMP1, TIMESTAMP2, ..., TIMESTAMP-n ]
}
```

`count_entries()` is a utility function that, given a rule number, returns the number of timestamps for that rule number in the `WINDOW_COUNTER` store. Actually, the function is implemented using Python builtin functions. Consider the pseudocode below.
```
rule_num <-- 1

// WINDOW_COUNTER[rule].triggerlist
triggerlist = WINDOW_COUNTER[rule_num]

// count_entries()
count_entries = len(triggerlist)
```

#### -ws WIN_SIZE

> `WINDOW_SIZE`: this is the length of the sliding window in seconds; values for testing: 15s [10s]

`WINDOW_SIZE` is the maximum number of seconds a trigger timestamp for a certain `INACTIVE_CHECKED` rule is expected to stay in `WINDOW_COUNTER[rule].triggerlist`. The filter sleeps for a second before checking that there exists some timestamps that have outlived the `WINDOW_SIZE`. All timestamps, for each rule, older than the `WINDOW_SIZE` are removed from `WINDOW_COUNTER[rule].triggerlist`.

`WIN_SIZE` must always be a positive number, the number of seconds.
*Example*
`python3 main.py -m 5 -i 192.168.1.2 -o 192.168.1.3 -ic 20 -ws 15 -twt 3`

In the example above, the `WINDOW_SIZE` is set to 15 seconds. This means that whenever a trigger timestamp for a certain `rule` is added to `WINDOW_COUNTER[rule].triggerlist`, it should stay in that trigger list for atleast 15 seconds, after which the timestamp is dropped.

#### -ic INACTIVE_CP

> `INACTIVE_CHECKED`: % of inactive rules that are not applied but tested whether incoming packets match them;
> values for testing: 5%, 20% [10%]

*Consider the example below*
`python3 main.py -m 5 -i 192.168.1.2 -o 192.168.1.3 -ic 15 -ws 5 -twt 5`

The percentage of the total number, `n`, of `INACTIVE_CHECKED` rules is set to `15%`. The actual number is the `INACTIVE_CHECKED` rules is calculated by

```
N = roundOffToWholeNumber((INACTIVE_CP / 100) * TOTAL_NO_OF_RULES)
```

#### -twt T_WIN_TRIG

> `THRESHOLD_WIN_TRIG`: number of timestamps that must be present to move a rule from INACTIVE_CHECKED to ACTIVE (and then one of 
> the existing rules is removed); values to be tested: 3 triggers [5 triggers]; this could be required to be changed depending on 
> the results

*Consider the example below*
`python3 main.py -m 5 -i 192.168.1.2 -o 192.168.1.3 -ic 25 -ws 30 -twt 3`

The `T_WIN_TRIG` is set to 3. This means that the length of list `WINDOW_COUNTER[rule].triggerlist` must be greater than or equal to 3 for rule number, `rule`, to be considered for migration from the `INACTIVE_CHECKED` list into the `ACTIVE` rules list. 

