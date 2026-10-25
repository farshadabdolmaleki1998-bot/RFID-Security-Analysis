# RFID-Security-Analysis

Code and data for the paper

> F. Abdolmaleki and M. Choubin, "Security Pitfalls in Lightweight RFID Authentication: Cryptanalysis and Robust Enhancements for EPC C1 G2 Standards", IETE Journal of Research (under revision).

The repository contains the experiments behind every table of the paper: passive attacks on the protocols of
Cheng et al. and Caballero-Gil et al., and the simulation of the proposed hash-based protocol.

## Contents

| File | Purpose |
|---|---|
| `rfid_experiments.py` | One script that produces every number in the paper (Tables 2, 3, 5, 6 and Section 7.3) and writes `results.json` |
| `results.json` | Results of the run reported in the paper (seed 20261023) |
| `proverif/proposed_protocol.pv` | ProVerif model of the proposed protocol: secrecy and authentication (Appendix A of the paper) |
| `proverif/untraceability.pv` | ProVerif model of untraceability as observational equivalence (Appendix A of the paper) |
| `requirements.txt` | No third-party packages are needed |

## Running the experiments

```
python3 rfid_experiments.py
```

Python 3 with the standard library only. The run takes one to two minutes on one CPU core, prints a summary of all
tables and writes `results.json`. The random seed is fixed, so counts and percentages are reproducible;
run times depend on the machine.

What the script contains:

1. **Cheng et al.** Algorithm 1 (passive disclosure of N, EPC16 and RT2 by chained lookups in a table of the PRNG inverse)
   and Algorithm 2 (tracking through the predicted next pseudonym), plus the known-N first-match search for comparison.
2. **Caballero-Gil et al.** Algorithm 3 (recovery of (ID, SSK) and K = ID xor SSK by a table join) for n = 12, 16, 24, 32,
   and Algorithm 4 (linking by Query replay) for a random-function PRNG and for a plain linear LFSR.
3. **Proposed protocol.** Correctness with lost messages, replay and forgery tests, the birthday experiment for the size of N_T,
   and the server-side identification cost.

## Models and assumptions

* The PRNG is modelled as a random function (truncated SHA-256 of the seed). The attacks only need a public PRNG that can be
  evaluated on all 2^16 inputs; a PRNG with exploitable structure can only make them easier.
* The lightweight hash of the proposed protocol is replaced by SHA-256 truncated to 128 bits. The security arguments of the paper
  assume an ideal hash. Real tags would use a lightweight hash such as SPONGENT or PHOTON.
* The experiments check attacks and protocol logic; they are not security proofs. The symbolic analysis (ProVerif) covers one
  session without key update.

## ProVerif

```
proverif proverif/proposed_protocol.pv
proverif proverif/untraceability.pv
```

Both models give `true` for every query: secrecy of the key, server-side and tag-side authentication, their injective (replay-resistant) versions, and untraceability (`Observational equivalence is true`). Only a single session without key update is modelled.

## Notes

The earlier version of this repository (`cheng_attacks.py`, `caballero_attacks.py`, `utils.py`) has been replaced:
its tracking test for Caballero-Gil et al. assumed a linear PRNG and did not reproduce the reported success rate, and its
Cheng et al. attack compared a formula with itself and returned the first match of a non-injective search.
