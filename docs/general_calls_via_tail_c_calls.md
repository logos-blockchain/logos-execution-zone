## Specification LP-0015: General Cross-Program Calls via Tail Calls

### 1. Overview
This mechanism allows programs within the LEZ ecosystem to perform cross-program calls (CPS - _Continuation Passing Style_) while using **tail calls** as the sole execution primitive. The primary objective is to provide a secure "_call-and-return_" abstraction for developers without compromising the encapsulation of internal functions.

### 2. Technical Design
**2.1 Instruction Wrapper**
All cross-program calls are wrapped in a `GeneralCallInstruction` structure containing:
- **route:** Opsional, contains authorization tickets and state data for the continuation function.
- **function_id:** Target function name to be called.
- **args:** Function arguments in serialized format.

**2.2 Unforgeable Capability Ticket (`ReturnRoute`)**
Security is guaranteed through unforgeable authorization tickets. This ticket (`ReturnRoute`) contains:
- **caller_program_id:** The ID of the program initiating the call.
- **continuation_id:** The name of the internal function to be called upon return.
- **ticket_hash:** SHA-256 hash of (SelfID + ContinuationID + StatePayload).
- **context_payload:** Local data (context) from Program A stored for later processing.

**2.3 The Dispatcher Gatekeeper**
Every program uses the `lez_dispatcher!` macro, which acts as a gatekeeper:
- **Public Functions:** Can be called directly by anyone.
- **Internal Functions:** Can only be executed if the instruction includes a valid `ReturnRoute`. If a user attempts to call this function directly, the dispatcher will trigger a deterministic `panic`.

### 3. Execution Flow (CPS Engine)
1. **Initiation (`call_program!`):**
Program A creates an authorization ticket, saves its local state into the ticket, and issues the ticket via `with_issued_tickets` in `ProgramOutput`. Program A then performs a _tail-call_ to Program B.
2. **Processing:**
Program B receives the instruction, processes the data, and uses the `return_to_caller!` macro to perform a _tail-call_ back to Program A's internal function, including the original ticket.
3. **Finalization:**
Program A's dispatcher receives the return ticket, verifies the `ticket_hash`, restores the local state from the `context_payload`, and executes the final logic. The ticket is then marked as consumed via `with_consumed_ticket` to prevent _replay_ attacks.

### 4. Security Model
The system adopts _Capability-Based Security_:
- **Non-Forgeability:** Users cannot forge ticket hashes as the process requires specific knowledge of the **Program ID** and internal **state data**, which are hashed dynamically at runtime.
- **Replay Prevention:** Every ticket follows a strict lifecycle (**Issued → Consumed**). Once a ticket has been consumed at the host level, it is invalidated and cannot be reused to trigger internal functions.
- **Deterministic Rejection:** Any direct calls to internal functions lacking a valid ticket are **deterministically rejected** by the dispatcher before any business logic is executed.

### 5. Determinism Guarantees & Error Semantics
To ensure predictable execution and safe state transitions, the CPS mechanism enforces strict rules:
- **Ordering Guarantees:** Chained calls are queued and executed strictly sequentially by the host sequencer. Program B will only execute after Program A successfully yields control, and Program A's continuation will only execute after Program B returns.
- **State Atomicity & Rollback:** The entire multi-hop call chain is treated as a single atomic transaction. If any hop fails, the sequencer discards the entire state diff for that transaction series, ensuring an O(1) consistent rollback.
- **Error Semantics:** - *Missing/Invalid Ticket:* Triggers a deterministic `panic!("Access Denied")` within the guest VM.
  - *Replay Attack:* Triggers a deterministic rejection by the host sequencer when it detects an already consumed ticket.
  - *Business Logic Failure:* If Program B panics (e.g., insufficient funds), the error propagates upward, invalidating the issued ticket and reverting Program A's initial state changes.

### 6. Performance & CU Evaluation (Latest Benchmarks)
Based on testing conducted on a `standalone sequencer` with active ZK Proving (**RISC0_DEV_MODE=0**), the following are the efficiency metrics for the three-step workflow (A -> B -> A):


**6.1 Execution Time Breakdown**
| **Execution Stage** | **Description** | **Execution Time (ms)** |
| **Hop 1 (Program A)** | Initiation, State Preservation, & Ticket Issuance | 7.83 ms |
| **Hop 2 (Program B)** | Logic Processing & Ticket Return | 8.94 ms |
| **Hop 3 (Program A)** | Ticket Validation & Internal Finalization | 7.19 ms |
| **Total Chain** | Complete CPS Execution | ~23.96 ms |

**6.2 Overhead Analysis**
- **Baseline Comparison:** A standard single transaction in the same environment averages ~11–12 ms.
- **Management Cost:** The process of SHA-256 hashing and ticket injection into the `ProgramOutput` adds only negligible overhead. This efficiency ensures that multi-hop call chain scalability is not bottlenecked by the ticket security infrastructure itself.
- **Rollback Efficiency:** Since every step in the chain is atomic at the sequencer level, any failure within an internal function (e.g., ticket expiration or a business logic panic) will trigger a full transaction reversal, leaving no dangling states.

### 7. Developer Ergonomics
Developers interact with high-level APIs:
```bash
// initiating a call
call_program!(ctx: ctx, target: target_b, func: b_func(args) => then a_internal(local_state));

// Returning result
return_to_caller!(ctx: ctx, route: route, result: is_success);
```