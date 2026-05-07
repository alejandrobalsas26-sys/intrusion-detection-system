> ⚠️ **LEGAL DISCLAIMER**
> 
> This module performs passive packet capture and network traffic analysis. It is intended exclusively for defensive operations, educational purposes, and deployment on networks the operator owns or has explicit written authorization to monitor. 
> 
> Unauthorized network monitoring may violate local and international laws, including but not limited to the US 18 U.S.C. § 2511 (Wiretap Act) and the EU ePrivacy Directive. The authors of this repository disclaim all liability for misuse.
> 
> By setting `NETWORK_MONITOR_CONSENT=true` in the environment configuration, the operator explicitly acknowledges and accepts all legal responsibility for the deployment context.

# Network Sensor (L2)

This module acts as the Layer 2 detection engine for the Intrusion Detection System. It operates as a passive continuous sniffer, designed to observe network traffic asynchronously without generating noisy active scans. Its primary objective is to detect volumetric anomalies and reconnaissance activities, dispatching findings to the L1 Alerts module via the L0 Logger infrastructure.

## Implementation Status

*⚠️ This module is currently under development.*

Technical reference documentation—including API contracts, threshold tuning instructions, state management architecture, and forensic query examples—will be appended in a subsequent commit upon the completion of the implementation phase.
