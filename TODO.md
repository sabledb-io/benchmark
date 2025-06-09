## TODO

- `vecdb_ingest` add support for sub-options:
    - `--m` Number of maximum allowed outgoing edges for each node in the graph in each layer. on layer zero the maximal
      number of outgoing edges will be 2M. Default is 16 Maximum is 512
    - `--ef-construction` controls the number of vectors examined during index construction. Higher values for this
      parameter will improve recall ratio at the expense of longer index creation times(Default value is 200. Maximum value is 4096)
    - `--ef-runtime` controls the number of vectors examined during query operations. Higher values for this parameter
      can yield improved recall at the expense of longer query times. The value of this parameter can be
      overriden on a per-query basis. Default value is 10. Maximum value is 4096.
