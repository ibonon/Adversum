# Adversum — Benchmark SmartBugs Curated

- **Dataset** : `C:\Users\SMC-DXB\Projects\adversum-bench\smartbugs-curated`
- **Moteur évalué** : règles Solidity natives d'Adversum (Slither/Aderyn désactivés)
- **Contrats** : 143
- **Contrats signalés par au moins une règle** : 121/143
- **Contrats avec la bonne catégorie détectée** : 45/143
- **Rappel niveau ligne (±3 lignes)** : 11.7% (222 lignes étiquetées)

## Métriques par catégorie (niveau contrat)

| Catégorie SmartBugs | Règles | TP | FP | FN | Précision | Rappel | F1 |
|---|---|---:|---:|---:|---:|---:|---:|
| access_control | SOL-002, SOL-003 | 4 | 5 | 14 | 44.4% | 22.2% | 29.6% |
| arithmetic | SOL-004 | 14 | 73 | 1 | 16.1% | 93.3% | 27.5% |
| bad_randomness | SOL-006, SOL-014 | 0 | 0 | 8 | 0.0% | 0.0% | 0.0% |
| denial_of_service | — | 0 | 0 | 6 | 0.0% | 0.0% | 0.0% |
| front_running | SOL-009 | 0 | 1 | 4 | 0.0% | 0.0% | 0.0% |
| other | — | 0 | 0 | 3 | 0.0% | 0.0% | 0.0% |
| reentrancy | SOL-001 | 1 | 68 | 30 | 1.4% | 3.2% | 2.0% |
| short_addresses | — | 0 | 0 | 1 | 0.0% | 0.0% | 0.0% |
| time_manipulation | SOL-006 | 0 | 0 | 5 | 0.0% | 0.0% | 0.0% |
| unchecked_low_level_calls | SOL-007 | 26 | 24 | 26 | 52.0% | 50.0% | 51.0% |

## Preuves — vulnérabilités manquées (faux négatifs)

### access_control — 14 ratés
`FibonacciBalance.sol`, `arbitrary_location_write_simple.sol`, `incorrect_constructor_name1.sol`, `incorrect_constructor_name2.sol`, `incorrect_constructor_name3.sol`, `mapping_write.sol`, `multiowned_vulnerable.sol`, `proxy.sol`, `rubixi.sol`, `simple_suicide.sol`, `unprotected0.sol`, `wallet_02_refund_nosub.sol`, `wallet_03_wrong_constructor.sol`, `wallet_04_confused_sign.sol`

### arithmetic — 1 ratés
`BECToken.sol`

### bad_randomness — 8 ratés
`blackjack.sol`, `etheraffle.sol`, `guess_the_random_number.sol`, `lottery.sol`, `lucky_doubler.sol`, `old_blockhash.sol`, `random_number_generator.sol`, `smart_billions.sol`

### denial_of_service — 6 ratés
`auction.sol`, `dos_address.sol`, `dos_number.sol`, `dos_simple.sol`, `list_dos.sol`, `send_loop.sol`

### front_running — 4 ratés
`ERC20.sol`, `FindThisHash.sol`, `eth_tx_order_dependence_minimal.sol`, `odds_and_evens.sol`

### other — 3 ratés
`crypto_roulette.sol`, `name_registrar.sol`, `open_address_lottery.sol`

### reentrancy — 30 ratés
`0x01f8c4e3fa3edeb29e514cba738d87ce8c091d3f.sol`, `0x23a91059fdc9579a9fbd0edc5f2ea0bfdb70deb4.sol`, `0x4320e6f8c05b27ab4707cd1f6d5ce6f3e4b3a5a1.sol`, `0x4e73b32ed6c35f570686b89848e5f39f20ecc106.sol`, `0x561eac93c92360949ab1f1403323e6db345cbf31.sol`, `0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839.sol`, `0x7541b76cb60f4c60af330c208b0623b7f54bf615.sol`, `0x7a8721a9d64c74da899424c1b52acbf58ddc9782.sol`, `0x7b368c4e805c3870b6c49a3f1f49f69af8662cf3.sol`, `0x8c7777c45481dba411450c228cb692ac3d550344.sol`, `0x93c32845fae42c83a70e5f06214c8433665c2ab5.sol`, `0x941d225236464a25eb18076df7da6a91d0f95e9e.sol`, `0x96edbe868531bd23a6c05e9d0c424ea64fb1b78b.sol`, `0xaae1f51cf3339f18b6d3f3bdc75a5facd744b0b8.sol`, `0xb5e1b1ee15c6fa0e48fce100125569d430f1bd12.sol`, `0xb93430ce38ac4a6bb47fb1fc085ea669353fd89e.sol`, `0xbaf51e761510c1a11bf48dd87c0307ac8a8c8a4f.sol`, `0xbe4041d55db380c5ae9d4a9b9703f1ed4e7e3888.sol`, `0xcead721ef5b11f1a7b530171aab69b16c5e66b6e.sol`, `0xf015c35649c82f5467c9c74b7f28ee67665aad68.sol`

### short_addresses — 1 ratés
`short_address_example.sol`

### time_manipulation — 5 ratés
`ether_lotto.sol`, `governmental_survey.sol`, `lottopollo.sol`, `roulette.sol`, `timed_crowdsale.sol`

### unchecked_low_level_calls — 26 ratés
`0x0cbe050f75bc8f8c2d6c0d249fea125fd6e1acc9.sol`, `0x2972d548497286d18e92b5fa1f8f9139e5653fd2.sol`, `0x39cfd754c85023648bf003bea2dd498c5612abfa.sol`, `0x3a0e9acd953ffc0dd18d63603488846a6b8b2b01.sol`, `0x4051334adc52057aca763453820cb0e045076ef3.sol`, `0x4a66ad0bca2d700f11e1f2fc2c106f7d3264504c.sol`, `0x4b71ad9c1a84b9b643aa54fdd66e2dec96e8b152.sol`, `0x524960d55174d912768678d8c606b4d50b79d7b1.sol`, `0x627fa62ccbb1c1b04ffaecd72a53e37fc0e17839.sol`, `0x84d9ec85c9c568eb332b7226a8f826d897e0a4a8.sol`, `0x89c1b3807d4c67df034fffb62f3509561218d30b.sol`, `0x8fd1e427396ddb511533cf9abdbebd0a7e08da35.sol`, `0x9d06cbafa865037a01d322d3f4222fa3e04e5488.sol`, `0xa1fceeff3acc57d257b917e30c4df661401d6431.sol`, `0xa46edd6a9a93feec36576ee5048146870ea2c3ae.sol`, `0xb0510d68f210b7db66e8c7c814f22680f2b8d1d6.sol`, `0xb7c5c5aa4d42967efe906e1b66cb8df9cebf04f7.sol`, `0xd5967fed03e85d1cce44cab284695b41bc675b5c.sol`, `0xe894d54dca59cb53fe9cbc5155093605c7068220.sol`, `0xf2570186500a46986f3139f65afedc2afe4f445d.sol`
