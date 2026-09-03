# Shrincs Lock
A new lock script on CKB powered by [SHRINCS](https://blog.blockstream.com/shrincs-324-byte-stateful-post-quantum-signatures-with-static-backups/), a post-quantum signature scheme. See [spec](./docs/shrincs-lock-spec.md).


## Introduction
A previous [quantum resistant lock script](https://github.com/nervosnetwork/quantum-resistant-lock-script) was implemented using SPHINCS+, but its signature is quite large (from 8K to 50K). On a blockchain, storage is precious, and large signatures also impact TPS.

Here we use SHRINCS, developed by [BlockStream](https://blockstream.com/), which can achieve a signature of only 324 bytes in the minimal scenario.
There are two methods of verifying SHRINCS: stateful and stateless. With stateful verification, the signature can be as small as 324 bytes, but the state (a count) must be stored on the local device.
The other method is stateless verification, which works like SPHINCS+ but with a much smaller signature size (2.5K bytes).
For most scenarios, a stateful signature can be used to unlock. In specific scenarios, such as transferring a wallet to another device, a stateless signature can be used.

## Parameter Set Used by Shrincs Lock
| Parameter | Value |
| --- | --- |
| Set | SHRINCS_B |
| Stateful Signature size | 324 bytes |
| Stateless Signature size | 2568 bytes |
| Public key size | 32 bytes |


| Verification type | Cycles |
| --- | --- |
| Stateless | 19.4 M |
| Stateful | 9.5 M |

The cycle cost also beats SPHINCS+, which ranges from 11M to 150M cycles.

## Build & Test
```
make build
make test
```


*This project was bootstrapped with [ckb-script-templates].*

[ckb-script-templates]: https://github.com/nervosnetwork/ckb-script-templates
