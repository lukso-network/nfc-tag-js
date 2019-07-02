'use strict';

const Hexify = require('hexify');

class Tlv {
  
  constructor(obj) {
    const fields = ['t', 'l', 'v'];

    fields.forEach((field) => {
      Object.defineProperty(this, field, {
        enumerable: true,
        configurable: true,
        writable: true,
        value: []
      });
    });

    if (obj) {
      this.t = obj.t;
      this.l = obj.l;
      this.v = obj.v;
    }
  }

  serialize(encoding) {
    let array = this.t.concat(this.l, this.v);
    if (encoding === 'hex') {
      return Hexify.toHexString(array);
    } else if (encoding === 'buffer') {
      return Buffer.from(array);
    } else if (encoding === 'array') {
      return array;
    } else {
      return {t:this.t, l:this.l, v:this.v};
    }
  }
}

class SimpleTlv {

  constructor(obj) {
    this._tlv = [];
    if (obj) {
      this._set(obj);
    }
  }

  get length() {
    return this._tlv.length;
  }

  get(tag, encoding) {
    let arr = null;
    this._tlv.forEach(e => {
      if (e.t[0] === tag) {
        arr = Array.from(e.v);
      }
    });
    if (arr !== null) {
      if (encoding === 'buffer') {
        return Buffer.from(arr);
      } else if (encoding === 'hex') {
        return Hexify.toHexString(arr).toUpperCase();
      } else {
        return arr;
      }
    } else {
      return null;
    }
  }

  set(tag, value) {
    if (this._existingTag(tag)) {
      return;
    }

    let tlv = {t:[], l:[], v:[]};

    if (typeof value === 'string') {
      tlv.v = Hexify.toByteArray(value);
    } else if (Buffer.isBuffer(value)) {
      tlv.v = Array.from(value);
    } else if (Array.isArray(value)) {
      tlv.v = value;
    }

    const length = tlv.v.length;
    if (length <= 0xff) {
      tlv.l.push(length);
    } else if (length <= 0xffff) {
      tlv.l.push(0xff);
      tlv.l.push(length & 0xff00 >> 8);
      tlv.l.push(length & 0x00ff);
    } else {
      return;
    }

    tlv.t.push(tag);

    this._tlv.push(new Tlv(tlv));
  }

  serialize(encoding) {
    let tlv = [];
    if (encoding) {
      this._tlv.forEach(e => {
        tlv = tlv.concat(e.serialize('array'));
      });
      if (encoding === 'array') {
        return tlv;
      } else if (encoding === 'buffer') {
        return Buffer.from(tlv);
      } else if (encoding === 'hex') {
        return Hexify.toHexString(tlv).toUpperCase();
      }
    } else {
      this._tlv.forEach(e => {
        tlv.push(e.serialize());
      });
      return tlv;
    }
  }

  _set(obj) {
    let tlv = [];
    if (typeof obj === 'string') {
      tlv = this._parse(Hexify.toByteArray(obj));
    } else if (Buffer.isBuffer(obj)) {
      tlv = this._parse(Array.from(obj));
    } else if (Array.isArray(obj)) {
      tlv = this._parse(obj);
    } else {
      tlv.push(new Tlv(obj));
    }

    if (typeof tlv !== 'undefined') {
      tlv.forEach(e => {
        this._tlv.push(e);
      });
    }
  }

  _parse(array) {
    let tlv = [];
    let obj = {t: null, l: null, v: null};
    let length = 0;
    let index = 0;

    while (index < array.length) {
      obj.t = array.slice(index, index + 1);
      index += 1;
      if (array[index] < 0xff) {
        obj.l = array.slice(index, index + 1);
        length = array[index];
        index += 1;
      } else {
        obj.l = array.slice(index, index + 3);
        length = array[index + 1] << 8 | array[index + 2];
        index += 3;
      }
      if (index + length <= array.length) {
        obj.v = array.slice(index, index + length);
        index += length;
        if (!this._existingTag(obj.t[0])) {
          tlv.push(new Tlv(obj));
        }
      } else {
        break;
      }
    }

    if (tlv.length > 0) {
      return tlv;
    }
  }

  _existingTag(tag) {
    this._tlv.forEach(e => {
      if (tag === e.t[0]) {
        return true;
      }
    });
    return false;
  }
}

export default SimpleTlv;
