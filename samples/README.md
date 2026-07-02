# Sample captures

Synthetic PCAP files for offline detector replay — crafted with scapy using
RFC 5737 documentation address space (never sniffed from a real network).

| File | Scenario | Expected detection |
|------|----------|--------------------|
| `syn_scan.pcap` | one source SYN-probes 60 ports on one host in ~3 s | `syn_scan` (CRITICAL) |
| `icmp_sweep.pcap` | one source pings 25 distinct hosts in ~5 s | `icmp_sweep` (WARNING) |

Replay them through the full detection pipeline (no admin rights needed):

```bash
python -m network.replay samples/syn_scan.pcap
python -m network.replay samples/icmp_sweep.pcap --sweep   # + correlation sweep
```

Regenerate (deterministic — fixed timestamps):

```bash
python samples/make_sample_pcaps.py
```
