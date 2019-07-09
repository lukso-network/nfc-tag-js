/**
 * @file Deal with LUKSO NFC Chip.
 * 
 */

'use strict';

import BN from 'bn.js';
import crypto from 'crypto';
import * as Elliptic from 'elliptic';
import CommandApdu from '../apdu/CommandApdu';
import ResponseApdu from '../apdu/ResponseApdu';
import Tlv from '../tlv/Tlv';
import SimpleTlv from '../tlv/SimpleTlv';

const ec = new Elliptic.ec('secp256k1');

class LuksoNfcChip {
  
  // Constructor.
  constructor(reader, blkPubKey) {
    const fields = ['reader', 'blkPubKey'];
    fields.forEach(field => {
      Object.defineProperty(this, field, {
        enumerable: true,
        configurable: true,
        writable: true,
        value: null
      });
    });
    this.reader = reader;
    if (typeof blkPubKey === 'string') {
      this.blkPubKey = blkPubKey;
    }
  }

  // Class builder.
  static async build(reader) {
    const response = await reader.transmit(CommandApdu.readInformation(Tlv.TAG_PUBLIC_KEY_BLK), 128);
    const responseApdu = new ResponseApdu(response);
    if (responseApdu.isOk()) {
      const tlv = new SimpleTlv(responseApdu.getDataOnly());
      const blkPubKey = tlv.get(Tlv.TAG_PUBLIC_KEY_BLK, 'hex');
      return new LuksoNfcChip(reader, blkPubKey);
    } else {
      return null;
    }
  }

  // Read chip information, eg, public key.
  read(tag) {
    return new Promise((resolve, reject) => {
      if (tag !== Tlv.TAG_PUBLIC_KEY_BLK && tag !== Tlv.TAG_PUBLIC_KEY_BLK && tag != Tlv.TAG_TRANSACTION_SIGNATURE_COUNTER) {
          reject(`wrong commands params`);
      }
      this.reader.transmit(CommandApdu.readInformation(tag), 255).then((response) => {
        const responseApdu = new ResponseApdu(response);
        if (responseApdu.isOk()) {
          const tlv = new SimpleTlv(responseApdu.getDataOnly());
          const data = tlv.get(tag, 'hex');
          if (data) {
            resolve(data);
          } else {
            reject(`no required data in response`);
          }
        } else {
          reject(`sw ${responseApdu.getStatusCode()}`);
        }
      }).catch(error => {
        reject(error);
      });
    });
  }

  // Verify chip by challenge-response.
  verify(tag) {
    return new Promise((resolve, reject) => {
      if (tag !== Tlv.TAG_PRIVATE_KEY_DEV && tag !== Tlv.TAG_PRIVATE_KEY_BLK) {
        reject(`wrong command params`);
      }
      const challenge = crypto.randomBytes(Tlv.LENGTH_CHALLENGE).toString('hex');
      this.reader.transmit(CommandApdu.internalAuthenticate(tag, challenge), 255).then((response) => {
        const responseApdu = new ResponseApdu(response);
        if (responseApdu.isOk()) {
          const tlv = new SimpleTlv(responseApdu.getDataOnly());
          const salt = tlv.get(Tlv.TAG_SALT, 'hex');
          const sig = {r:tlv.get(Tlv.TAG_VERIFICATION_SIGNATURE, 'hex').slice(0, 64), s:tlv.get(Tlv.TAG_VERIFICATION_SIGNATURE, 'hex').slice(64)};
          if (salt && sig) {
            let pubKey;
            if (tag === Tlv.TAG_PRIVATE_KEY_DEV) {
              pubKey = this.devPubKey;
            } else {
              pubKey = this.blkPubKey;
            }
            const hash = this._doubleSHA256(challenge + salt);
            const keyPair = ec.keyFromPublic(pubKey, 'hex');
            if(keyPair.verify(hash, sig)) {
              resolve(`success`);
            } else {
              reject(`invalid chip inserted`);
            }
            resolve();
          } else {
            reject(`no required data in response`);
          }
        } else {
          reject(`sw ${responseApdu.getStatusCode()}`);
        }
      }).catch(error => {
        reject(error);
      });
    });
  }

  // Sign transaction hash.
  signTransactionHash(chainID, hash) {
    return new Promise((resolve, reject) => {
      this.reader.transmit(CommandApdu.signTxHash(hash), 255).then((response) => {
        const responseApdu = new ResponseApdu(response);
        if (responseApdu.isOk()) {
          const tlv = new SimpleTlv(responseApdu.getDataOnly());
          const res = tlv.get(Tlv.TAG_TRANSACTION_SIGNATURE, 'hex');
          let sig = {r:res.slice(0, 64), s:this._toCanonicalised(res.slice(64)), v:0};
          const rec = this._calculateRec(chainID, hash, sig);
          if (rec.error) {
            reject(`calculate recovery param failed`);
          } else {
            sig.v = rec.v;
            resolve(sig);
          }
        } else {
          reject(`invalid chip inserted`);
        }
      }).catch(error => {
        reject(error);
      });
    });
  }

  // Double SHA256.
  _doubleSHA256(msg) {
    let first = crypto.createHash('sha256').update(msg, 'hex').digest();
    let sencond = crypto.createHash('sha256').update(first, 'hex').digest();
    return sencond;
  }

  // Make signature canonicalised.
  _toCanonicalised(s) {
    const bnS = new BN(s, 16);
    const bnN = new BN('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);
    const bnNH = new BN('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0', 16);
    if (bnS.cmp(bnNH) > 0) {
      return bnN.sub(bnS).toString(16).toUpperCase();
    } else {
      return s;
    }
  }

  // Calculate public key recovery parameter. 
  _calculateRec(chainID, hash, sig) {
    try {
      const key = ec.keyFromPublic(Buffer.from(this.blkPubKey, 'hex'));
      const rec = ec.getKeyRecoveryParam(hash, sig, key.getPublic());
      if (chainID > 0) {
        return {error:null, v:rec + chainID * 2 + 35};
      } else {
        return {error:null, v:rec + 27};
      }
    } catch(e) {
      return {error:e};
    }
  }
}

export default LuksoNfcChip;
