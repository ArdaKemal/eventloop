# TOML configuration API contract

- Include `eventloop/util/toml.h` and call
  `eventloop::util::parse_toml(input, nodes, decoded_strings)` for synchronous
  parsing of [TOML 1.1.0](https://toml.io/en/v1.1.0). The result is
  `std::expected<toml_document, toml_error>`. This utility has no loop affinity,
  asynchronous work, or cancellation operation and is available on Linux,
  macOS, and Windows. Applications handle file reading separately.
- The parser borrows the input `std::string_view`, a mutable
  `std::span<toml_value>`, and a mutable `std::span<char>` for decoded strings.
  Keep all three backing buffers alive and unchanged while using the document
  or any node, key, or string view obtained from it. The document is a view;
  copying it does not copy or own the parsed data. Parsing into the same
  storage again invalidates earlier documents and views.
- The caller sets node and decoded-string capacities through the spans.
  The root consumes one node, as does each value or implicit table. Keys and
  plain strings may borrow the input; escaped strings and strings requiring
  newline normalization consume decoded storage. `node_capacity` and
  `string_capacity` report exhaustion without growing storage. Nested values
  and dotted paths have a maximum depth of 64; exceeding it reports
  `nesting_limit`. The document reports `nodes_used()` and `strings_used()`.
- Parse errors carry a `toml_error_code` and a byte offset into the input.
  Invalid UTF-8, duplicate keys, conflicting table definitions, invalid values,
  and capacity limits return an error. Failure may partially overwrite the
  storage; no document is returned. Callers must inspect the result before
  accessing data.
- `root()` is the unnamed table. Use `toml_value::find(name)` to look up one
  decoded key component, `at(index)` to select an array element, and range
  iteration to visit children in source order. `find("a.b")` names a single
  key; traverse `find("a")` then `find("b")` for a dotted path. Lookup and
  indexing scan siblings. Check `type` before reading the associated value
  field; applications validate their own configuration schema and ranges.
- Integers use signed 64-bit storage; floats use `double`. Date and time values
  retain their TOML kind and local fields. Fractional seconds use nanoseconds,
  truncating additional precision; omitted seconds are zero. Offset date-time
  values retain the offset in minutes rather than converting to UTC.
  The parser uses caller storage and bounded local state. File I/O and setup
  libraries may allocate independently; this is not a process-wide allocation
  guarantee.
