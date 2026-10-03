// Pure state-transition function: no I/O, fully unit-testable.
//
// accounts: { [address]: { balance, nonce, existed } }  (mutated in place)
// txs:      [{ id, from, to, amount, fee, nonce, createdAt }]
//
// Rules:
//   nonce <  account.nonce            -> rejected (stale-nonce); never consumes a nonce
//   nonce >  account.nonce            -> skipped this round; may run later in the same call
//   balance < amount + fee            -> rejected (insufficient-funds); never consumes a nonce
//   otherwise                         -> executed: sender pays amount+fee, recipient gets amount,
//                                        feeRecipient gets fee, sender nonce + 1
// Total supply is conserved by construction, so balances stay safe integers as long as the
// genesis supply is a safe integer (enforced in config).
export function applyTransactions({ accounts, txs, feeRecipient }) {
  const executed = [];
  const rejected = [];
  const touched = new Set();

  let remaining = [...txs].sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  for (;;) {
    let progressed = false;
    const next = [];

    for (const tx of remaining) {
      const sender = accounts[tx.from];
      if (tx.nonce < sender.nonce) {
        rejected.push({ tx, reason: 'stale-nonce' });
        progressed = true;
        continue;
      }
      if (tx.nonce > sender.nonce) {
        next.push(tx);
        continue;
      }
      const cost = tx.amount + tx.fee;
      if (!Number.isSafeInteger(cost) || sender.balance < cost) {
        rejected.push({ tx, reason: 'insufficient-funds' });
        progressed = true;
        continue;
      }
      sender.balance -= cost;
      sender.nonce += 1;
      accounts[tx.to].balance += tx.amount;
      accounts[feeRecipient].balance += tx.fee;
      touched.add(tx.from).add(tx.to).add(feeRecipient);
      executed.push(tx);
      progressed = true;
    }

    remaining = next;
    if (!progressed || remaining.length === 0) break;
  }

  return { executed, rejected, skipped: remaining, touched };
}
