"use strict";

import { NFC } from 'nfc-pcsc';
import EthTx from 'ethereumjs-tx';
import LuksoNfcChip from './reader/LuksoNfcChip';
import Tlv from './tlv/Tlv';

const nfc = new NFC();

nfc.on('reader', async reader => {
  console.log(`${reader.reader.name}  device attached`);
  reader.aid = '654E6F7465734170706C6574';
  reader.on('card', async card => {
    console.log();

    // Get Chip Object (Automatic read public key)
    let chip = await LuksoNfcChip.build(reader);
    console.log(`Public key:                0x${chip.blkPubKey}`);

    // Transaction Signature Counter
    let counter = await chip.read(Tlv.TAG_TRANSACTION_SIGNATURE_COUNTER);
    console.log(`Tx Signature Counter:      0x${counter}`)

    // Challenge-response
    let result = await chip.verify(Tlv.TAG_PRIVATE_KEY_BLK);
    console.log(`Challenge-response result: ${result}`);

    // Sign Transaction (Ethereum)
    const txParam = {
      nonce: 0,
      gasPrice: 18000000000, 
      gasLimit: 21000,
      to: '0x91f5c1f36981e300eb9ddcb5149e210eb77cce29', 
      value: 10000000000000000, 
      data: '0x7f7465737432000000000000000000000000000000000000000000000000000000600057',
      chainId: 42
    };
    const tx = new EthTx(txParam);
    const hash = tx.hash(false);
    const sig = await chip.signTransactionHash(tx.getChainId(), hash);
    console.log(`TX Signature:              r = 0x${sig.r}, s = 0x${sig.s}, v = ${sig.v}`);

    // Signed Raw Transaction
    let v = [];
    v.push(sig.v);
    tx.r = Buffer.from(sig.r, 'hex');
    tx.s = Buffer.from(sig.s, 'hex');
    tx.v = Buffer.from(v);
    const raw = tx.serialize();
    console.log(`Signed Raw TX:             0x${raw.toString('hex').toUpperCase()}`);

    // Transaction Signature Counter
    counter = await chip.read(Tlv.TAG_TRANSACTION_SIGNATURE_COUNTER);
    console.log(`Tx Signature Counter:      0x${counter}`)
  });
});

nfc.on('error', err => {
  console.log('an error occurred', err);
});