# SHRINCS Lock Script Specification
A new lock script on CKB powered by [SHRINCS](https://blog.blockstream.com/shrincs-324-byte-stateful-post-quantum-signatures-with-static-backups/), a post-quantum signature scheme.

## Script
A SHRINCS lock script has following structure:
```
Code hash: SHRINCS lock script code hash
Hash type: SHRINCS lock script hash type
Args:  <SHRINCS pubkey, 32 bytes>
```

## Witness
The corresponding witness must be a proper WitnessArgs data structure in molecule format. In the `lock` field of the WitnessArgs, a SHRINCS signature must be present.

## Unlocking Process
While SHRINCS itself supports variable-length signing messages, the current lock script requires the signing message to be 32 bytes long. It is calculated using the [CKB_TX_MESSAGE_ALL](https://github.com/nervosnetwork/rfcs/pull/446) specification. In the CKB_TX_MESSAGE_ALL process, a blake2b hash function with a 32-byte output length, using `ckb-shrincs-msg-` as the personalization field, is used as the hasher. The resulting 32-byte hash is then used as the signing message.

The validation process then verifies the message, signature, and pubkey with the SHRINCS verification function.  


