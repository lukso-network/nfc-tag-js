/**
 * @file Parse APDU response.
 * 
 */

'use strict';

class ResponseApdu {

    // Constructor.
    // APDU response = Data(variable length) + Status Words(2 byte)
    constructor(buffer) {
        this.buffer = buffer;
        this.data = buffer.toString('hex');
    }

    // Get response data.
    getDataOnly() {
      return this.data.substr(0, this.data.length-4);
    }
    
    // Get status code.
    getStatusCode() {
        return this.data.substr(-4);
    }

    // Check succes or not.
    isOk() {
        return this.getStatusCode() === '9000';
    }

    // Get entire response.
    buffer() {
        return this.buffer;
    }

    // Convert to string.
    toString() {
        return this.data.toString('hex');
    }
}

export default ResponseApdu;