# Changes compared to Zodiac FX Custom version B

* `src/openflow/of_helper.c` change the way flows are matched:
    * `flowmatch10` now returns the first matching flow
    (**before**: return matching flow with highest priority; 
    **if multiple matching flows have the same priority,
    return the first of them**)