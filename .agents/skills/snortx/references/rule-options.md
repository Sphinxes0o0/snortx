# Supported Snort rule options

These are the options snortx parses and (where relevant) uses to build packets. Anything not listed is either parsed-and-ignored or rejected.

## Rule header

- **Action**: `alert`, `log`, `pass`, `drop`, `reject`, `sdrop`. Only `drop`/`reject`/`sdrop` are Snort inline-only and have no runtime effect in snortx.
- **Protocol**: `tcp`, `udp`, `icmp`, `ip`, `ipv6`, `sctp`, `arp`, `dns`. App protocols (`http`, `https`, `ftp`, `ssh`, `smtp`, `dns`, `sip`, `smb`) are mapped to TCP in `parseHeader()`.
- **Direction**: `->` (unidirectional) or `<>` (bidirectional — generates two packets).
- **Networks**: CIDR, IPv6, `any`, `!CIDR` (negation stored in rule text, semantically treated as `any`).
- **Ports**: single, range (`8000:9000` → uses first), list (`80,443,8080` → uses first), variable (`$HTTP_PORTS`), `any`.

## Content match

`content:"..."` or `content:!..."` (negated).

- **String** content: `content:"GET"`
- **Hex** content: `content:"|48 65 6c 6c 6f|"` (ASCII "Hello")
- **Negation**: `content:!"pattern"` or `content:!pattern` → generates generic `"test payload"` (no positive payload to build)
- **Modifiers**: `nocase`, `rawbytes`, `fast_pattern`, `offset:N`, `depth:N`, `distance:N`, `within:N`
- **fast_pattern**: only one per rule; snortx stores in `Options["fast_pattern"]` but does not implement fast-pattern optimization
- `uricontent:"..."` — alias for `content:"..."; http_uri;`

## PCRE

`pcre:"/pattern/modifiers"`.

- Supported modifiers: `i` (case-insensitive), `m` (multiline), `s` (dotall)
- Detected but unsupported: `R` (PCRE_MATCH_END), `U` (PCRE_UNGREEDY)
- When only PCRE is specified, generator extracts literals: quoted strings → hex escapes → strip constructs → fall back to default payload
- `nopcre` or `no_pcre` disables PCRE matching for the rule

## Flow

`flow:<value>[,<value>...]`

| Value | Description |
|-------|-------------|
| `established` | Established connection |
| `to_server` / `from_client` | Client → server |
| `to_client` / `from_server` | Server → client |
| `only_stream` | Reassembled stream only |
| `no_stream` | Un-reassembled packets only |

## Byte test / byte jump

`byte_test:<count>, <operator>, <value>, <offset>[, relative][, big][, little][, string][, negate]`

`byte_jump:<count>, <offset>[, relative][, big][, little][, string][, align <n>][, post_offset <n>]`

Operators: `<`, `>`, `=`, `!`, `<=`, `>=`.

## Rule ID

`sid:<n>`, `gid:<n>`, `rev:<n>`. Valid ranges: GID 0–999_999_999; SID 0–999_999_999; REV 0–999.

Default: GID=1, SID=0, REV=1 if omitted.

## HTTP modifiers

| Modifier | Scope |
|----------|-------|
| `http_uri` / `http_raw_uri` | URI (normalized / raw) |
| `http_header` / `http_raw_header` | Any / raw header |
| `http_cookie` | Cookie header |
| `http_method` | Method (GET, POST, ...) |
| `http_stat_code` / `http_stat_msg` | Status code / message |
| `http_client_body` | Request body |

Stored in both `Options` and `ParsedRule.HTTPModifiers` (structured `{Type, Modifies, Content}`).

## Detection filters

- `threshold:type <t>, track <by>, count <n>, seconds <n>` → `ParsedRule.Threshold`
- `rate_filter:type filter, track <by>, count <n>, seconds <n>, new_action <a>` → `ParsedRule.RateFilter`
- `detection_filter:track <by>, count <n>, seconds <n>` → `ParsedRule.DetectionFilter`

Parsed but do not affect snortx behavior.

## Flowbits

`flowbits:<op>,<name>` — `set`, `isset`, `isnotset`, `toggle`, `unset`, `noalert`.

Stored in `ParsedRule.Flowbits` (`[]Flowbit{Op, Name}`). snortx implements flowbit state tracking across rules within a test run: rules are evaluated in order; if a flowbit condition (isset/isnotset) isn't met, the rule fails with "flowbit condition not met".

## DSize

`dsize:<n>` (exact), `dsize:>N`, `dsize:<N`, `dsize:<min><><max>`.

## IP/ICMP options

`ttl:`, `tos:`, `ip_id:`, `dsize:`, `icmp_id:`, `icmp_seq:`, `itype:`, `icode:`.

## IP protocol

`ip_proto:<proto>`, `rawip`.

## TCP flags

`flags:<flags>[,<ignored>]` — flags: `F` (FIN), `S` (SYN), `R` (RST), `P` (PSH), `A` (ACK), `U` (URG), `E` (ECE), `C` (CWR).

Example: `flags:SF,RA` = SYN+FIN set, RST+ACK ignored.

## Detection points

`pkt_data`, `file_data`, `base64_data`, `raw_data`, `pkt_header` — recognized, no effect on generation.

## VLAN

`vlan:<vlan_id>` — supports both IPv4 and IPv6. Generates DOT1Q header.

## IPv6 extension headers

Stored in `ParsedRule.IPv6ExtHeaders`: `hopopts`, `dstopts`, `routing`, `fragment`, `ah`, `esp`, `mip6`. Parsed, no effect on generation.

## Recognized, no effect

These are stored in `Options` but do not change packet generation:

- `sameip` — flag; generator uses same expanded IP for src and dst
- `logto:"..."`, `tag:session`, `classtype:`, `priority:`, `replace:"..."`
- `activates:<sid>`, `activated_by:<sid>`, `count:<n>` — dynamic rule chaining parsed, state tracking not implemented
- `metadata:`, `service:`, `reference:`
- `stream_reassemble:`, `stream_size:`

## Variable expansion

Generator expands from `engine.generator.vars`:

| Var | Default |
|-----|---------|
| `$HOME_NET` | `10.0.0.0/24` |
| `$EXTERNAL_NET` | `any` |
| `$HTTP_SERVERS` | `any` |
| `$SMTP_SERVERS` | `any` |
| `$DNS_SERVERS` | `any` |
| `$SSH_SERVERS` | `any` |

Config file vars override defaults; unspecified vars keep defaults.

## Empty rule handling

Rule parses successfully but has no `content:`, `pcre:`, or other payload-generating option → packet payload is the literal string `"test payload"`.

## Example

```
alert tcp any any -> any any (
  msg:"HTTP GET";
  content:"GET";
  nocase;
  http_uri;
  flow:established,to_server;
  sid:1000001; rev:1;
)
```