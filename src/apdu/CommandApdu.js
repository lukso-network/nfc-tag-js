/**
 * @file Construct APDU commands.
 * 
 */

'use strict';

import Hexify from 'hexify';
import Tlv from '../tlv/Tlv';
import SimpleTlv from '../tlv/SimpleTlv';

const cla = 0x00;
const ins = {
  'DISABLE_VERIFICATION': 0x26,
  'ENABLE_VERIFICATION': 0x28,
  'INTERNAL_AUTHENTICATE': 0x88,
  'READ_DATA': 0xCA,
  'SIGN_TRANSACTION': 0xA0
};

class CommandApdu {

  // Construcotr.
  // APDU Commnd = CLAss(1 byte) + INStruct(1 byte) + Parameter1(1 byte) + Parameter2(1 byte) + LC(Length Command 1 byte) + Data (LEN byte) + LE(Length Response 1 byte, optional)
  constructor(obj) {
    let cla = obj.cla;
    let ins = obj.ins;
    let p1 = obj.p1;
    let p2 = obj.p2;
    let data = obj.data;
    let le = obj.le;

    this.bytes = [];
    this.bytes.push(cla);
    this.bytes.push(ins);
    this.bytes.push(p1);
    this.bytes.push(p2);

    if (data) {
      this.bytes.push(data.length);
      this.bytes = this.bytes.concat(data);
    }

    if (le) {
      this.bytes.push(le);
    }
  }

  // Get hex string.
  toHexString() {
    return Hexify.toHexString(this.bytes).toUpperCase();
  }

  // Get byte array.
  toByteArray() {
    return this.bytes;
  }

  // Get buffer.
  toBuffer() {
    return Buffer.from(this.bytes);
  }
}

export default {
  // Get APDU command: disable PIN.
  disableVerification(pin) {
    let tlv = new SimpleTlv();
    tlv.set(Tlv.TAG_TRANSACTION_FREEZE_PIN, pin);
    let commandApdu = new CommandApdu({
      cla: cla,
      ins: ins.DISABLE_VERIFICATION,
      p1: Tlv.TAG_TRANSACTION_FREEZE_STATUS,
      p2: 0x00,
      data: tlv.serialize('array')
    });
    return commandApdu.toBuffer();
  },

  // Get APDU command: enable PIN.
  enableVerification(pin) {
    let tlv = new SimpleTlv();
    tlv.set(Tlv.TAG_TRANSACTION_FREEZE_PIN, pin);
    let commandApdu = new CommandApdu({
      cla: cla,
      ins: ins.ENABLE_VERIFICATION,
      p1: Tlv.TAG_TRANSACTION_FREEZE_STATUS,
      p2: 0x00,
      data: tlv.serialize('array')
    });
    return commandApdu.toBuffer();
  },

  // Get APDU command: chanllenge response.
  internalAuthenticate(tag, chanllenge) {
    let tlv = new SimpleTlv();
    tlv.set(Tlv.TAG_CHALLENGE, chanllenge);
    let commandApdu = new CommandApdu({
      cla: cla,
      ins: ins.INTERNAL_AUTHENTICATE,
      p1: tag,
      p2: 0x00,
      data: tlv.serialize('array')
    });
    return commandApdu.toBuffer();
  },

  // Get APDU command: read chip information. eg, public key, sign transaction times(counter).
  readInformation(tag) {
    let commandApdu = new CommandApdu({
      cla: cla,
      ins: ins.READ_DATA,
      p1: 0x00,
      p2: tag
    });
    return commandApdu.toBuffer();
  },

  // Get APDU command: read chip certification issued by manufacturer.
  readCertification(offset) {
    let commandApdu = new CommandApdu({
      cla: cla,
      ins: ins.READ_DATA,
      p1: offset,
      p2: Tlv.TAG_CERTIFICATE
    });
    return commandApdu.toBuffer();
  },

  // Get APDU command: sign transaction hash.
  signTxHash(txHash) {
    let tlv = new SimpleTlv();
    tlv.set(Tlv.TAG_TRANSACTION_HASH, txHash);
    let commandApdu = new CommandApdu({
      cla: cla,
      ins: ins.SIGN_TRANSACTION,
      p1: Tlv.TAG_PRIVATE_KEY_BLK,
      p2: 0x00,
      data: tlv.serialize('array')
    });
    return commandApdu.toBuffer();
  }
}
