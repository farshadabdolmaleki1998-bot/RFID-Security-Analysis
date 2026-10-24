"""
Reproducible experiments for:
  "Security Pitfalls in Lightweight RFID Authentication: Cryptanalysis and Robust
   Enhancements for EPC C1 G2 Standards"
Run:  python3 rfid_experiments.py          (writes results.json, prints all numbers)
Only the Python 3 standard library is used (hashlib stands in for the PRNG / hash).
"""
import hashlib, json, os, random, time, math
from collections import defaultdict

SEED = 20261023
random.seed(SEED)
R = {}                      # results dictionary -> results.json

# ---------------------------------------------------------------- PRNG models
def P16(x):                 # Cheng et al. model (same function as the original repository)
    return int(hashlib.sha256(str(x).encode()).hexdigest()[:4], 16)

def make_Pn(n):             # Caballero et al.: last n bits of the keystream seeded with a 16-bit value
    def Pn(x):
        d = hashlib.sha256(b"C" + x.to_bytes(2, "big")).digest()
        return int.from_bytes(d[:4], "big") >> (32 - n)
    return Pn

def lfsr_linear(seed, length=16):   # plain LFSR of the original repository (GF(2)-linear)
    state, out = seed, 0
    for _ in range(length):
        out = (out << 1) | (state & 1)
        nb = (state ^ (state >> 2) ^ (state >> 3)) & 1
        state = (state >> 1) | (nb << 15)
    return out & 0xFFFF

# ------------------------------------------------- E0: original Algorithm 1 as published
def alg1_original(C, D, Rr, N):
    RT2 = C ^ P16(N ^ Rr)
    for g in range(0x10000):
        if D == P16(N ^ RT2 ^ g ^ Rr):
            return g
T = 1000; ok = 0
for _ in range(T):
    N, E, Rr, RT2 = (random.getrandbits(16) for _ in range(4))
    C = P16(N ^ Rr) ^ RT2; D = P16(N ^ RT2 ^ E ^ Rr)
    ok += alg1_original(C, D, Rr, N) == E
R["E0_alg1_original_firstmatch_success"] = {"trials": T, "success_pct": 100 * ok / T}

# ------------------------------------------- E1: Cheng passive disclosure (N unknown)
t0 = time.perf_counter()
INV = defaultdict(list)
for x in range(0x10000):
    INV[P16(x)].append(x)
t_table = time.perf_counter() - t0

def cheng_candidates(RT1, B, C, D, Rr):
    out = []
    for u in INV.get(B, []):
        s = u ^ RT1 ^ Rr                       # s = N xor EPC16
        for v in INV.get(D, []):
            rt2 = v ^ s ^ Rr
            for w in INV.get(C ^ rt2, []):
                N = w ^ Rr
                out.append((N, s ^ N, rt2))
    return out

def cheng_session(N, E):
    Rr, RT1, RT2 = (random.getrandbits(16) for _ in range(3))
    B = P16(N ^ RT1 ^ E ^ Rr); C = P16(N ^ Rr) ^ RT2; D = P16(N ^ RT2 ^ E ^ Rr)
    return Rr, RT1, RT2, B, C, D

T = 2000; sizes = []; hit = uniq = 0; walk = 0.0; hit2 = uniq2 = 0; T2 = 1000
for _ in range(T):
    N, E = random.getrandbits(16), random.getrandbits(16)
    Rr, RT1, RT2, B, C, D = cheng_session(N, E)
    t = time.perf_counter(); cand = cheng_candidates(RT1, B, C, D, Rr); walk += time.perf_counter() - t
    sizes.append(len(cand)); hit += (N, E, RT2) in cand; uniq += (len(cand) == 1 and cand[0] == (N, E, RT2))
for _ in range(T2):                            # two sessions of the same tag: EPC16 is static
    E = random.getrandbits(16); eset = None; ok_all = True
    for s in range(2):
        N = random.getrandbits(16)
        Rr, RT1, RT2, B, C, D = cheng_session(N, E)
        es = {c[1] for c in cheng_candidates(RT1, B, C, D, Rr)}
        eset = es if eset is None else eset & es
    hit2 += E in eset; uniq2 += (eset == {E})
R["E1_cheng_passive_disclosure"] = {
    "trials_1session": T, "table_build_s": t_table, "walk_us_per_session": 1e6 * walk / T,
    "true_triple_in_candidates_pct": 100 * hit / T, "unique_pct": 100 * uniq / T,
    "mean_candidates": sum(sizes) / T, "max_candidates": max(sizes),
    "trials_2sessions": T2, "epc_in_set_2sessions_pct": 100 * hit2 / T2, "epc_unique_2sessions_pct": 100 * uniq2 / T2}

# ---------------------------------------------------- E2: Cheng tracking (N unknown)
T = 20000; tp = fp = 0; psz = 0
for _ in range(T):
    N, E = random.getrandbits(16), random.getrandbits(16)
    Rr, RT1, RT2, B, C, D = cheng_session(N, E)
    IDS_old = random.getrandbits(16); IDS_new = P16(IDS_old ^ RT2)
    cand = cheng_candidates(RT1, B, C, D, Rr)
    pred = {P16(IDS_old ^ c[2]) for c in cand}; psz += len(pred)
    tp += IDS_new in pred
    fp += random.getrandbits(16) in pred       # IDS observed from a different tag (uniform)
R["E2_cheng_tracking"] = {"trials": T, "tpr_pct": 100 * tp / T, "fpr_pct": 100 * fp / T, "mean_predictions": psz / T}

# -------------------------------------------- E3: Caballero passive state disclosure
def caballero_attack(n, trials):
    Pn = make_Pn(n); stats = dict(contains=0, unique=0, k_unique=0, sizes=[], t=0.0)
    for _ in range(trials):
        ID, SSK, Q, N1 = (random.getrandbits(16) for _ in range(4))
        N2 = Pn(ID ^ Q) ^ Pn(SSK ^ Q); N3 = Pn(ID ^ N1) ^ Pn(SSK ^ N1)
        t = time.perf_counter()
        TQ = [Pn(x ^ Q) for x in range(0x10000)]; T1 = [Pn(x ^ N1) for x in range(0x10000)]
        idx = defaultdict(list)
        for x, v in enumerate(TQ): idx[v].append(x)
        cand = []
        for a in range(0x10000):
            for b in idx.get(TQ[a] ^ N2, ()):
                if b >= a and (T1[a] ^ T1[b]) == N3: cand.append((a, b))
        stats["t"] += time.perf_counter() - t
        true = (min(ID, SSK), max(ID, SSK)); ks = {a ^ b for a, b in cand}
        stats["contains"] += true in cand; stats["unique"] += (cand == [true])
        stats["k_unique"] += (ks == {ID ^ SSK}); stats["sizes"].append(len(cand))
    return {"n": n, "trials": trials, "pair_in_list_pct": 100 * stats["contains"] / trials,
            "unique_pct": 100 * stats["unique"] / trials, "k_unique_pct": 100 * stats["k_unique"] / trials,
            "mean_list": sum(stats["sizes"]) / trials, "max_list": max(stats["sizes"]),
            "mean_time_s": stats["t"] / trials}
R["E3_caballero_state_disclosure"] = [caballero_attack(12, 20), caballero_attack(16, 150),
                                       caballero_attack(24, 40), caballero_attack(32, 40)]

# ------------------------------------ E4: Caballero query-replay linkability (any PRNG)
def replay_link(label, f2, n, pairs):
    same = diff = 0
    for _ in range(pairs):
        ID, SSK, ID2, SSK2, Q = (random.getrandbits(16) for _ in range(5))
        a = f2(ID, Q) ^ f2(SSK, Q)
        b = f2(ID, Q) ^ f2(SSK, Q)             # same tag, same Query, state unchanged
        c = f2(ID2, Q) ^ f2(SSK2, Q)           # a different tag
        same += (a == b); diff += (a == c)
    return {"prng": label, "n_bits": n, "pairs": pairs, "tpr_pct": 100 * same / pairs, "fp_count": diff,
            "fpr_pct": 100 * diff / pairs, "fpr_theory_pct": 100 * 2.0 ** -n}
Pn16 = make_Pn(16)
R["E4_caballero_query_replay"] = [
    replay_link("nonlinear (random function)", lambda x, q: Pn16(x ^ q), 16, 200000),
    replay_link("plain LFSR (linear)", lambda x, q: lfsr_linear(x ^ q), 16, 200000)]

# ------------------------------------------------------------ E5: proposed protocol
def H(*parts, n=16):
    return hashlib.sha256(b"|".join(parts)).digest()[:n]
NR_B, NT_B = 4, 8                              # 32-bit N_R, 64-bit N_T
class Tag:
    def __init__(s, k): s.k = k
    def respond(s, NR):
        NT = os.urandom(NT_B); return NT, H(s.k, NR, NT, b"\x01", n=8)
    def finish(s, NR, NT, B):
        if B == H(s.k, NT, NR, b"\x02", n=8):
            s.k = H(s.k, NR, NT, b"\x03"); return True
        return False
class Server:
    def __init__(s, recs): s.recs = recs; s.pending = set()
    def challenge(s):
        NR = os.urandom(NR_B); s.pending.add(NR); return NR
    def run(s, NR, NT, A):
        if NR not in s.pending: return None, None
        s.pending.discard(NR)
        for tid, (kc, ko) in s.recs.items():
            for kx in (kc, ko):
                if kx is not None and A == H(kx, NR, NT, b"\x01", n=8):
                    B = H(kx, NT, NR, b"\x02", n=8)
                    s.recs[tid] = [H(kx, NR, NT, b"\x03"), kx]; return tid, B
        return None, None
NT_TAGS = 100
tags = {i: Tag(os.urandom(16)) for i in range(NT_TAGS)}
S = Server({i: [t.k, None] for i, t in tags.items()})
sessions = 5000; ident = completed = lostB = 0
for _ in range(sessions):
    i = random.randrange(NT_TAGS); t = tags[i]
    NR = S.challenge(); NT, A = t.respond(NR); tid, B = S.run(NR, NT, A)
    ident += (tid == i)
    if random.random() < 0.2: lostB += 1; continue          # message B lost -> desynchronisation
    completed += t.finish(NR, NT, B)
# replay of a recorded valid transcript
rep = 0; REP = 1000
for _ in range(REP):
    i = random.randrange(NT_TAGS); t = tags[i]
    NR = S.challenge(); NT, A = t.respond(NR); tid, B = S.run(NR, NT, A); t.finish(NR, NT, B)
    rep += S.run(NR, NT, A)[0] is not None
# random forgery
FORG = 200000; forg = 0; NRf = S.challenge()
fk = tags[0].k
for _ in range(FORG):
    forg += S.run(NRf, os.urandom(NT_B), os.urandom(8))[0] is not None
    NRf = S.challenge()
# linking experiment: rogue reader repeats a fixed N_R, tag never completes the session
def link_game(nt_bits, q):
    # returns True if a repeated (N_T, A) pair is seen in q unauthenticated queries to ONE tag
    seen = set()
    for _ in range(q):
        v = random.getrandbits(nt_bits)
        if v in seen: return True
        seen.add(v)
    return False
birthday = []
for b, q in ((16, 2 ** 10), (24, 2 ** 12), (32, 2 ** 12), (32, 2 ** 16), (64, 2 ** 16)):
    th = 1 - math.exp(-(q * q) / 2.0 ** (b + 1))
    sim = None
    if b <= 32 and q <= 2 ** 16:
        G = 300 if q > 2 ** 12 else 600
        sim = 100 * sum(link_game(b, q) for _ in range(G)) / G
    birthday.append({"nt_bits": b, "queries": q, "theory_pct": 100 * th, "simulated_pct": sim})
# server identification cost (worst case: matching key is k_old of the last record)
srv_time = []
for n in (1000, 10000, 100000):
    keys = [(os.urandom(16), os.urandom(16)) for _ in range(n)]
    NR, NT = os.urandom(NR_B), os.urandom(NT_B); A = H(keys[-1][1], NR, NT, b"\x01", n=8)
    ts = []
    for _ in range(5):
        t0 = time.perf_counter()
        for kc, ko in keys:
            if H(kc, NR, NT, b"\x01", n=8) == A or H(ko, NR, NT, b"\x01", n=8) == A: break
        ts.append(time.perf_counter() - t0)
    srv_time.append({"tags": n, "worst_case_s": sum(ts) / len(ts)})
R["E5_proposed"] = {"tags": NT_TAGS, "sessions": sessions, "identified_correctly": ident,
                    "completed_pct_of_non_lost": 100 * completed / (sessions - lostB), "lost_B": lostB,
                    "replays": REP, "replays_accepted": rep, "forgeries": FORG, "forgeries_accepted": forg,
                    "birthday": birthday, "server_time": srv_time}
R["meta"] = {"seed": SEED, "python": __import__("sys").version.split()[0], "cpu_count": os.cpu_count()}
json.dump(R, open("results.json", "w"), indent=1)

# ------------------------------------------------------------ readable summary
e1, e2 = R["E1_cheng_passive_disclosure"], R["E2_cheng_tracking"]
print("== Cheng et al. (Table 2) ==")
print("table build %.3f s | per-session recovery %.1f us" % (e1["table_build_s"], e1["walk_us_per_session"]))
print("true triple in list %.1f%% | unique (1 session) %.2f%% | mean/max list %.1f/%d"
      % (e1["true_triple_in_candidates_pct"], e1["unique_pct"], e1["mean_candidates"], e1["max_candidates"]))
print("EPC16 unique after 2 sessions %.1f%% | tracking TPR %.1f%% FPR %.3f%% | known-N first-match %.1f%%"
      % (e1["epc_unique_2sessions_pct"], e2["tpr_pct"], e2["fpr_pct"], R["E0_alg1_original_firstmatch_success"]["success_pct"]))
print("== Caballero-Gil et al. (Table 3a) ==")
for r in R["E3_caballero_state_disclosure"]:
    print("n=%2d trials=%3d in list %.0f%% unique %.1f%% mean/max list %.2f/%d time %.2f s"
          % (r["n"], r["trials"], r["pair_in_list_pct"], r["unique_pct"], r["mean_list"], r["max_list"], r["mean_time_s"]))
print("== Caballero-Gil et al. (Table 3b) ==")
for r in R["E4_caballero_query_replay"]:
    print("%-28s TPR %.1f%% false positives %d (%.4f%%, theory %.4f%%)"
          % (r["prng"], r["tpr_pct"], r["fp_count"], r["fpr_pct"], r["fpr_theory_pct"]))
e5 = R["E5_proposed"]
print("== Proposed protocol (Section 7.3, Tables 5 and 8) ==")
print("identified %d/%d | replays accepted %d/%d | forgeries accepted %d/%d"
      % (e5["identified_correctly"], e5["sessions"], e5["replays_accepted"], e5["replays"], e5["forgeries_accepted"], e5["forgeries"]))
for b in e5["birthday"]:
    print("N_T %2d bits, 2^%d queries: repeat probability theory %.3g%%, simulation %s"
          % (b["nt_bits"], round(math.log2(b["queries"])), b["theory_pct"], b["simulated_pct"]))
for t in e5["server_time"]:
    print("server worst-case identification, %6d tags: %.1f ms" % (t["tags"], 1000 * t["worst_case_s"]))
print("Full results written to results.json")
