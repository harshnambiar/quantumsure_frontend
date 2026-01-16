/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 251:
/***/ ((__unused_webpack_module, exports) => {

/*! ieee754. BSD-3-Clause License. Feross Aboukhadijeh <https://feross.org/opensource> */
exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = (e * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = (m * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  var i = isLE ? 0 : (nBytes - 1)
  var d = isLE ? 1 : -1
  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = ((value * c) - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = (e << mLen) | m
  eLen += mLen
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128
}


/***/ }),

/***/ 4329:
/***/ ((module) => {

"use strict";

/*
 * Copyright (c) 2017, Bubelich Mykola
 * https, 0x//www.bubelich.com
 *
 * (｡◕‿‿◕｡)
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met, 0x
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * ChaCha20 is a stream cipher designed by D. J. Bernstein.
 * It is a refinement of the Salsa20 algorithm, and it uses a 256-bit key.
 *
 * ChaCha20 successively calls the ChaCha20 block function, with the same key and nonce, and with successively increasing block counter parameters.
 * ChaCha20 then serializes the resulting state by writing the numbers in little-endian order, creating a keystream block.
 *
 * Concatenating the keystream blocks from the successive blocks forms a keystream.
 * The ChaCha20 function then performs an XOR of this keystream with the plaintext.
 * Alternatively, each keystream block can be XORed with a plaintext block before proceeding to create the next block, saving some memory.
 * There is no requirement for the plaintext to be an integral multiple of 512 bits.  If there is extra keystream from the last block, it is discarded.
 *
 * The inputs to ChaCha20 are
 * - 256-bit key
 * - 32-bit initial counter
 * - 96-bit nonce.  In some protocols, this is known as the Initialization Vector
 * - Arbitrary-length plaintext
 *
 * Implementation derived from chacha-ref.c version 20080118
 * See for details, 0x http, 0x//cr.yp.to/chacha/chacha-20080128.pdf
 */

/**
 *
 * @param {Uint8Array} key
 * @param {Uint8Array} nonce
 * @param {number} counter
 * @throws {Error}
 *
 * @constructor
 */
var JSChaCha20 = function (key, nonce, counter) {
  if (typeof counter === 'undefined') {
    counter = 0
  }

  if (!(key instanceof Uint8Array) || key.length !== 32) {
    throw new Error('Key should be 32 byte array!')
  }

  if (!(nonce instanceof Uint8Array) || nonce.length !== 12) {
    throw new Error('Nonce should be 12 byte array!')
  }

  this._rounds = 20
  // Constants
  this._sigma = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

  // param construction
  this._param = [
    this._sigma[0],
    this._sigma[1],
    this._sigma[2],
    this._sigma[3],
    // key
    this._get32(key, 0),
    this._get32(key, 4),
    this._get32(key, 8),
    this._get32(key, 12),
    this._get32(key, 16),
    this._get32(key, 20),
    this._get32(key, 24),
    this._get32(key, 28),
    // counter
    counter,
    // nonce
    this._get32(nonce, 0),
    this._get32(nonce, 4),
    this._get32(nonce, 8)
  ]

  // init 64 byte keystream block //
  this._keystream = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  ]

  // internal byte counter //
  this._byteCounter = 0
}

JSChaCha20.prototype._chacha = function () {
  var mix = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  var i = 0
  var b = 0

  // copy param array to mix //
  for (i = 0; i < 16; i++) {
    mix[i] = this._param[i]
  }

  // mix rounds //
  for (i = 0; i < this._rounds; i += 2) {
    this._quarterround(mix, 0, 4, 8, 12)
    this._quarterround(mix, 1, 5, 9, 13)
    this._quarterround(mix, 2, 6, 10, 14)
    this._quarterround(mix, 3, 7, 11, 15)

    this._quarterround(mix, 0, 5, 10, 15)
    this._quarterround(mix, 1, 6, 11, 12)
    this._quarterround(mix, 2, 7, 8, 13)
    this._quarterround(mix, 3, 4, 9, 14)
  }

  for (i = 0; i < 16; i++) {
    // add
    mix[i] += this._param[i]

    // store keystream
    this._keystream[b++] = mix[i] & 0xFF
    this._keystream[b++] = (mix[i] >>> 8) & 0xFF
    this._keystream[b++] = (mix[i] >>> 16) & 0xFF
    this._keystream[b++] = (mix[i] >>> 24) & 0xFF
  }
}

/**
 * The basic operation of the ChaCha algorithm is the quarter round.
 * It operates on four 32-bit unsigned integers, denoted a, b, c, and d.
 *
 * @param {Array} output
 * @param {number} a
 * @param {number} b
 * @param {number} c
 * @param {number} d
 * @private
 */
JSChaCha20.prototype._quarterround = function (output, a, b, c, d) {
  output[d] = this._rotl(output[d] ^ (output[a] += output[b]), 16)
  output[b] = this._rotl(output[b] ^ (output[c] += output[d]), 12)
  output[d] = this._rotl(output[d] ^ (output[a] += output[b]), 8)
  output[b] = this._rotl(output[b] ^ (output[c] += output[d]), 7)

  // JavaScript hack to make UINT32 :) //
  output[a] >>>= 0
  output[b] >>>= 0
  output[c] >>>= 0
  output[d] >>>= 0
}

/**
 * Little-endian to uint 32 bytes
 *
 * @param {Uint8Array|[number]} data
 * @param {number} index
 * @return {number}
 * @private
 */
JSChaCha20.prototype._get32 = function (data, index) {
  return data[index++] ^ (data[index++] << 8) ^ (data[index++] << 16) ^ (data[index] << 24)
}

/**
 * Cyclic left rotation
 *
 * @param {number} data
 * @param {number} shift
 * @return {number}
 * @private
 */
JSChaCha20.prototype._rotl = function (data, shift) {
  return ((data << shift) | (data >>> (32 - shift)))
}

/**
 *  Encrypt data with key and nonce
 *
 * @param {Uint8Array} data
 * @return {Uint8Array}
 */
JSChaCha20.prototype.encrypt = function (data) {
  return this._update(data)
}

/**
 *  Decrypt data with key and nonce
 *
 * @param {Uint8Array} data
 * @return {Uint8Array}
 */
JSChaCha20.prototype.decrypt = function (data) {
  return this._update(data)
}

/**
 *  Encrypt or Decrypt data with key and nonce
 *
 * @param {Uint8Array} data
 * @return {Uint8Array}
 * @private
 */
JSChaCha20.prototype._update = function (data) {
  if (!(data instanceof Uint8Array) || data.length === 0) {
    throw new Error('Data should be type of bytes (Uint8Array) and not empty!')
  }

  var output = new Uint8Array(data.length)

  // core function, build block and xor with input data //
  for (var i = 0; i < data.length; i++) {
    if (this._byteCounter === 0 || this._byteCounter === 64) {
      // generate new block //

      this._chacha()
      // counter increment //
      this._param[12]++

      // reset internal counter //
      this._byteCounter = 0
    }

    output[i] = data[i] ^ this._keystream[this._byteCounter++]
  }

  return output
}

// EXPORT //
if ( true && module.exports) {
  module.exports = JSChaCha20
}


/***/ }),

/***/ 7526:
/***/ ((__unused_webpack_module, exports) => {

"use strict";


exports.byteLength = byteLength
exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

var lookup = []
var revLookup = []
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for (var i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i]
  revLookup[code.charCodeAt(i)] = i
}

// Support decoding URL-safe base64 strings, as Node.js does.
// See: https://en.wikipedia.org/wiki/Base64#URL_applications
revLookup['-'.charCodeAt(0)] = 62
revLookup['_'.charCodeAt(0)] = 63

function getLens (b64) {
  var len = b64.length

  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // Trim off extra bytes after placeholder bytes are found
  // See: https://github.com/beatgammit/base64-js/issues/42
  var validLen = b64.indexOf('=')
  if (validLen === -1) validLen = len

  var placeHoldersLen = validLen === len
    ? 0
    : 4 - (validLen % 4)

  return [validLen, placeHoldersLen]
}

// base64 is 4/3 + up to two characters of the original data
function byteLength (b64) {
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function _byteLength (b64, validLen, placeHoldersLen) {
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function toByteArray (b64) {
  var tmp
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]

  var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen))

  var curByte = 0

  // if there are placeholders, only get up to the last complete 4 chars
  var len = placeHoldersLen > 0
    ? validLen - 4
    : validLen

  var i
  for (i = 0; i < len; i += 4) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 18) |
      (revLookup[b64.charCodeAt(i + 1)] << 12) |
      (revLookup[b64.charCodeAt(i + 2)] << 6) |
      revLookup[b64.charCodeAt(i + 3)]
    arr[curByte++] = (tmp >> 16) & 0xFF
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 2) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 2) |
      (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 1) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 10) |
      (revLookup[b64.charCodeAt(i + 1)] << 4) |
      (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] +
    lookup[num >> 12 & 0x3F] +
    lookup[num >> 6 & 0x3F] +
    lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  var tmp
  var output = []
  for (var i = start; i < end; i += 3) {
    tmp =
      ((uint8[i] << 16) & 0xFF0000) +
      ((uint8[i + 1] << 8) & 0xFF00) +
      (uint8[i + 2] & 0xFF)
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

function fromByteArray (uint8) {
  var tmp
  var len = uint8.length
  var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  var parts = []
  var maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1]
    parts.push(
      lookup[tmp >> 2] +
      lookup[(tmp << 4) & 0x3F] +
      '=='
    )
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + uint8[len - 1]
    parts.push(
      lookup[tmp >> 10] +
      lookup[(tmp >> 4) & 0x3F] +
      lookup[(tmp << 2) & 0x3F] +
      '='
    )
  }

  return parts.join('')
}


/***/ }),

/***/ 8287:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";
/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */



const base64 = __webpack_require__(7526)
const ieee754 = __webpack_require__(251)
const customInspectSymbol =
  (typeof Symbol === 'function' && typeof Symbol['for'] === 'function') // eslint-disable-line dot-notation
    ? Symbol['for']('nodejs.util.inspect.custom') // eslint-disable-line dot-notation
    : null

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

const K_MAX_LENGTH = 0x7fffffff
exports.kMaxLength = K_MAX_LENGTH

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Print warning and recommend using `buffer` v4.x which has an Object
 *               implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * We report that the browser does not support typed arrays if the are not subclassable
 * using __proto__. Firefox 4-29 lacks support for adding new properties to `Uint8Array`
 * (See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438). IE 10 lacks support
 * for __proto__ and has a buggy typed array implementation.
 */
Buffer.TYPED_ARRAY_SUPPORT = typedArraySupport()

if (!Buffer.TYPED_ARRAY_SUPPORT && typeof console !== 'undefined' &&
    typeof console.error === 'function') {
  console.error(
    'This browser lacks typed array (Uint8Array) support which is required by ' +
    '`buffer` v5.x. Use `buffer` v4.x if you require old browser support.'
  )
}

function typedArraySupport () {
  // Can typed array instances can be augmented?
  try {
    const arr = new Uint8Array(1)
    const proto = { foo: function () { return 42 } }
    Object.setPrototypeOf(proto, Uint8Array.prototype)
    Object.setPrototypeOf(arr, proto)
    return arr.foo() === 42
  } catch (e) {
    return false
  }
}

Object.defineProperty(Buffer.prototype, 'parent', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.buffer
  }
})

Object.defineProperty(Buffer.prototype, 'offset', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.byteOffset
  }
})

function createBuffer (length) {
  if (length > K_MAX_LENGTH) {
    throw new RangeError('The value "' + length + '" is invalid for option "size"')
  }
  // Return an augmented `Uint8Array` instance
  const buf = new Uint8Array(length)
  Object.setPrototypeOf(buf, Buffer.prototype)
  return buf
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new TypeError(
        'The "string" argument must be of type string. Received type number'
      )
    }
    return allocUnsafe(arg)
  }
  return from(arg, encodingOrOffset, length)
}

Buffer.poolSize = 8192 // not used by this implementation

function from (value, encodingOrOffset, length) {
  if (typeof value === 'string') {
    return fromString(value, encodingOrOffset)
  }

  if (ArrayBuffer.isView(value)) {
    return fromArrayView(value)
  }

  if (value == null) {
    throw new TypeError(
      'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
      'or Array-like Object. Received type ' + (typeof value)
    )
  }

  if (isInstance(value, ArrayBuffer) ||
      (value && isInstance(value.buffer, ArrayBuffer))) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof SharedArrayBuffer !== 'undefined' &&
      (isInstance(value, SharedArrayBuffer) ||
      (value && isInstance(value.buffer, SharedArrayBuffer)))) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof value === 'number') {
    throw new TypeError(
      'The "value" argument must not be of type number. Received type number'
    )
  }

  const valueOf = value.valueOf && value.valueOf()
  if (valueOf != null && valueOf !== value) {
    return Buffer.from(valueOf, encodingOrOffset, length)
  }

  const b = fromObject(value)
  if (b) return b

  if (typeof Symbol !== 'undefined' && Symbol.toPrimitive != null &&
      typeof value[Symbol.toPrimitive] === 'function') {
    return Buffer.from(value[Symbol.toPrimitive]('string'), encodingOrOffset, length)
  }

  throw new TypeError(
    'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
    'or Array-like Object. Received type ' + (typeof value)
  )
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(value, encodingOrOffset, length)
}

// Note: Change prototype *after* Buffer.from is defined to workaround Chrome bug:
// https://github.com/feross/buffer/pull/148
Object.setPrototypeOf(Buffer.prototype, Uint8Array.prototype)
Object.setPrototypeOf(Buffer, Uint8Array)

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be of type number')
  } else if (size < 0) {
    throw new RangeError('The value "' + size + '" is invalid for option "size"')
  }
}

function alloc (size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpreted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(size).fill(fill, encoding)
      : createBuffer(size).fill(fill)
  }
  return createBuffer(size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(size, fill, encoding)
}

function allocUnsafe (size) {
  assertSize(size)
  return createBuffer(size < 0 ? 0 : checked(size) | 0)
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(size)
}

function fromString (string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('Unknown encoding: ' + encoding)
  }

  const length = byteLength(string, encoding) | 0
  let buf = createBuffer(length)

  const actual = buf.write(string, encoding)

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    buf = buf.slice(0, actual)
  }

  return buf
}

function fromArrayLike (array) {
  const length = array.length < 0 ? 0 : checked(array.length) | 0
  const buf = createBuffer(length)
  for (let i = 0; i < length; i += 1) {
    buf[i] = array[i] & 255
  }
  return buf
}

function fromArrayView (arrayView) {
  if (isInstance(arrayView, Uint8Array)) {
    const copy = new Uint8Array(arrayView)
    return fromArrayBuffer(copy.buffer, copy.byteOffset, copy.byteLength)
  }
  return fromArrayLike(arrayView)
}

function fromArrayBuffer (array, byteOffset, length) {
  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('"offset" is outside of buffer bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('"length" is outside of buffer bounds')
  }

  let buf
  if (byteOffset === undefined && length === undefined) {
    buf = new Uint8Array(array)
  } else if (length === undefined) {
    buf = new Uint8Array(array, byteOffset)
  } else {
    buf = new Uint8Array(array, byteOffset, length)
  }

  // Return an augmented `Uint8Array` instance
  Object.setPrototypeOf(buf, Buffer.prototype)

  return buf
}

function fromObject (obj) {
  if (Buffer.isBuffer(obj)) {
    const len = checked(obj.length) | 0
    const buf = createBuffer(len)

    if (buf.length === 0) {
      return buf
    }

    obj.copy(buf, 0, 0, len)
    return buf
  }

  if (obj.length !== undefined) {
    if (typeof obj.length !== 'number' || numberIsNaN(obj.length)) {
      return createBuffer(0)
    }
    return fromArrayLike(obj)
  }

  if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
    return fromArrayLike(obj.data)
  }
}

function checked (length) {
  // Note: cannot use `length < K_MAX_LENGTH` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= K_MAX_LENGTH) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + K_MAX_LENGTH.toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return b != null && b._isBuffer === true &&
    b !== Buffer.prototype // so Buffer.isBuffer(Buffer.prototype) will be false
}

Buffer.compare = function compare (a, b) {
  if (isInstance(a, Uint8Array)) a = Buffer.from(a, a.offset, a.byteLength)
  if (isInstance(b, Uint8Array)) b = Buffer.from(b, b.offset, b.byteLength)
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError(
      'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
    )
  }

  if (a === b) return 0

  let x = a.length
  let y = b.length

  for (let i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!Array.isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  let i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; ++i) {
      length += list[i].length
    }
  }

  const buffer = Buffer.allocUnsafe(length)
  let pos = 0
  for (i = 0; i < list.length; ++i) {
    let buf = list[i]
    if (isInstance(buf, Uint8Array)) {
      if (pos + buf.length > buffer.length) {
        if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf)
        buf.copy(buffer, pos)
      } else {
        Uint8Array.prototype.set.call(
          buffer,
          buf,
          pos
        )
      }
    } else if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    } else {
      buf.copy(buffer, pos)
    }
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (ArrayBuffer.isView(string) || isInstance(string, ArrayBuffer)) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    throw new TypeError(
      'The "string" argument must be one of type string, Buffer, or ArrayBuffer. ' +
      'Received type ' + typeof string
    )
  }

  const len = string.length
  const mustMatch = (arguments.length > 2 && arguments[2] === true)
  if (!mustMatch && len === 0) return 0

  // Use a for loop to avoid recursion
  let loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len
      case 'utf8':
      case 'utf-8':
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) {
          return mustMatch ? -1 : utf8ToBytes(string).length // assume utf8
        }
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  let loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coercion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// This property is used by `Buffer.isBuffer` (and the `is-buffer` npm package)
// to detect a Buffer instance. It's not possible to use `instanceof Buffer`
// reliably in a browserify context because there could be multiple different
// copies of the 'buffer' package in use. This method works even for Buffer
// instances that were created from another copy of the `buffer` package.
// See: https://github.com/feross/buffer/issues/154
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  const i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  const len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (let i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  const len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (let i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.swap64 = function swap64 () {
  const len = this.length
  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits')
  }
  for (let i = 0; i < len; i += 8) {
    swap(this, i, i + 7)
    swap(this, i + 1, i + 6)
    swap(this, i + 2, i + 5)
    swap(this, i + 3, i + 4)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  const length = this.length
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.toLocaleString = Buffer.prototype.toString

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  let str = ''
  const max = exports.INSPECT_MAX_BYTES
  str = this.toString('hex', 0, max).replace(/(.{2})/g, '$1 ').trim()
  if (this.length > max) str += ' ... '
  return '<Buffer ' + str + '>'
}
if (customInspectSymbol) {
  Buffer.prototype[customInspectSymbol] = Buffer.prototype.inspect
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (isInstance(target, Uint8Array)) {
    target = Buffer.from(target, target.offset, target.byteLength)
  }
  if (!Buffer.isBuffer(target)) {
    throw new TypeError(
      'The "target" argument must be one of type Buffer or Uint8Array. ' +
      'Received type ' + (typeof target)
    )
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  let x = thisEnd - thisStart
  let y = end - start
  const len = Math.min(x, y)

  const thisCopy = this.slice(thisStart, thisEnd)
  const targetCopy = target.slice(start, end)

  for (let i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

// Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf
function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset = +byteOffset // Coerce to Number.
  if (numberIsNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : (buffer.length - 1)
  }

  // Normalize byteOffset: negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset
  if (byteOffset >= buffer.length) {
    if (dir) return -1
    else byteOffset = buffer.length - 1
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0
    else return -1
  }

  // Normalize val
  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  // Finally, search either indexOf (if dir is true) or lastIndexOf
  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
  } else if (typeof val === 'number') {
    val = val & 0xFF // Search for a byte value [0-255]
    if (typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
      }
    }
    return arrayIndexOf(buffer, [val], byteOffset, encoding, dir)
  }

  throw new TypeError('val must be string, number or Buffer')
}

function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
  let indexSize = 1
  let arrLength = arr.length
  let valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  let i
  if (dir) {
    let foundIndex = -1
    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
    for (i = byteOffset; i >= 0; i--) {
      let found = true
      for (let j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false
          break
        }
      }
      if (found) return i
    }
  }

  return -1
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
}

Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  const remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  const strLen = string.length

  if (length > strLen / 2) {
    length = strLen / 2
  }
  let i
  for (i = 0; i < length; ++i) {
    const parsed = parseInt(string.substr(i * 2, 2), 16)
    if (numberIsNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset >>> 0
    if (isFinite(length)) {
      length = length >>> 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  const remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  let loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
      case 'latin1':
      case 'binary':
        return asciiWrite(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  const res = []

  let i = start
  while (i < end) {
    const firstByte = buf[i]
    let codePoint = null
    let bytesPerSequence = (firstByte > 0xEF)
      ? 4
      : (firstByte > 0xDF)
          ? 3
          : (firstByte > 0xBF)
              ? 2
              : 1

    if (i + bytesPerSequence <= end) {
      let secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
const MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  const len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  let res = ''
  let i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  let ret = ''
  end = Math.min(buf.length, end)

  for (let i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function latin1Slice (buf, start, end) {
  let ret = ''
  end = Math.min(buf.length, end)

  for (let i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  const len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  let out = ''
  for (let i = start; i < end; ++i) {
    out += hexSliceLookupTable[buf[i]]
  }
  return out
}

function utf16leSlice (buf, start, end) {
  const bytes = buf.slice(start, end)
  let res = ''
  // If bytes.length is odd, the last 8 bits must be ignored (same as node.js)
  for (let i = 0; i < bytes.length - 1; i += 2) {
    res += String.fromCharCode(bytes[i] + (bytes[i + 1] * 256))
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  const len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  const newBuf = this.subarray(start, end)
  // Return an augmented `Uint8Array` instance
  Object.setPrototypeOf(newBuf, Buffer.prototype)

  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUintLE =
Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  let val = this[offset]
  let mul = 1
  let i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUintBE =
Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  let val = this[offset + --byteLength]
  let mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUint8 =
Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUint16LE =
Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUint16BE =
Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUint32LE =
Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUint32BE =
Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readBigUInt64LE = defineBigIntMethod(function readBigUInt64LE (offset) {
  offset = offset >>> 0
  validateNumber(offset, 'offset')
  const first = this[offset]
  const last = this[offset + 7]
  if (first === undefined || last === undefined) {
    boundsError(offset, this.length - 8)
  }

  const lo = first +
    this[++offset] * 2 ** 8 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 24

  const hi = this[++offset] +
    this[++offset] * 2 ** 8 +
    this[++offset] * 2 ** 16 +
    last * 2 ** 24

  return BigInt(lo) + (BigInt(hi) << BigInt(32))
})

Buffer.prototype.readBigUInt64BE = defineBigIntMethod(function readBigUInt64BE (offset) {
  offset = offset >>> 0
  validateNumber(offset, 'offset')
  const first = this[offset]
  const last = this[offset + 7]
  if (first === undefined || last === undefined) {
    boundsError(offset, this.length - 8)
  }

  const hi = first * 2 ** 24 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 8 +
    this[++offset]

  const lo = this[++offset] * 2 ** 24 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 8 +
    last

  return (BigInt(hi) << BigInt(32)) + BigInt(lo)
})

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  let val = this[offset]
  let mul = 1
  let i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  let i = byteLength
  let mul = 1
  let val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  const val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  const val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readBigInt64LE = defineBigIntMethod(function readBigInt64LE (offset) {
  offset = offset >>> 0
  validateNumber(offset, 'offset')
  const first = this[offset]
  const last = this[offset + 7]
  if (first === undefined || last === undefined) {
    boundsError(offset, this.length - 8)
  }

  const val = this[offset + 4] +
    this[offset + 5] * 2 ** 8 +
    this[offset + 6] * 2 ** 16 +
    (last << 24) // Overflow

  return (BigInt(val) << BigInt(32)) +
    BigInt(first +
    this[++offset] * 2 ** 8 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 24)
})

Buffer.prototype.readBigInt64BE = defineBigIntMethod(function readBigInt64BE (offset) {
  offset = offset >>> 0
  validateNumber(offset, 'offset')
  const first = this[offset]
  const last = this[offset + 7]
  if (first === undefined || last === undefined) {
    boundsError(offset, this.length - 8)
  }

  const val = (first << 24) + // Overflow
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 8 +
    this[++offset]

  return (BigInt(val) << BigInt(32)) +
    BigInt(this[++offset] * 2 ** 24 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 8 +
    last)
})

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUintLE =
Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    const maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  let mul = 1
  let i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUintBE =
Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    const maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  let i = byteLength - 1
  let mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUint8 =
Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeUint16LE =
Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeUint16BE =
Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeUint32LE =
Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset + 3] = (value >>> 24)
  this[offset + 2] = (value >>> 16)
  this[offset + 1] = (value >>> 8)
  this[offset] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeUint32BE =
Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

function wrtBigUInt64LE (buf, value, offset, min, max) {
  checkIntBI(value, min, max, buf, offset, 7)

  let lo = Number(value & BigInt(0xffffffff))
  buf[offset++] = lo
  lo = lo >> 8
  buf[offset++] = lo
  lo = lo >> 8
  buf[offset++] = lo
  lo = lo >> 8
  buf[offset++] = lo
  let hi = Number(value >> BigInt(32) & BigInt(0xffffffff))
  buf[offset++] = hi
  hi = hi >> 8
  buf[offset++] = hi
  hi = hi >> 8
  buf[offset++] = hi
  hi = hi >> 8
  buf[offset++] = hi
  return offset
}

function wrtBigUInt64BE (buf, value, offset, min, max) {
  checkIntBI(value, min, max, buf, offset, 7)

  let lo = Number(value & BigInt(0xffffffff))
  buf[offset + 7] = lo
  lo = lo >> 8
  buf[offset + 6] = lo
  lo = lo >> 8
  buf[offset + 5] = lo
  lo = lo >> 8
  buf[offset + 4] = lo
  let hi = Number(value >> BigInt(32) & BigInt(0xffffffff))
  buf[offset + 3] = hi
  hi = hi >> 8
  buf[offset + 2] = hi
  hi = hi >> 8
  buf[offset + 1] = hi
  hi = hi >> 8
  buf[offset] = hi
  return offset + 8
}

Buffer.prototype.writeBigUInt64LE = defineBigIntMethod(function writeBigUInt64LE (value, offset = 0) {
  return wrtBigUInt64LE(this, value, offset, BigInt(0), BigInt('0xffffffffffffffff'))
})

Buffer.prototype.writeBigUInt64BE = defineBigIntMethod(function writeBigUInt64BE (value, offset = 0) {
  return wrtBigUInt64BE(this, value, offset, BigInt(0), BigInt('0xffffffffffffffff'))
})

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    const limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  let i = 0
  let mul = 1
  let sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    const limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  let i = byteLength - 1
  let mul = 1
  let sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  this[offset + 2] = (value >>> 16)
  this[offset + 3] = (value >>> 24)
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeBigInt64LE = defineBigIntMethod(function writeBigInt64LE (value, offset = 0) {
  return wrtBigUInt64LE(this, value, offset, -BigInt('0x8000000000000000'), BigInt('0x7fffffffffffffff'))
})

Buffer.prototype.writeBigInt64BE = defineBigIntMethod(function writeBigInt64BE (value, offset = 0) {
  return wrtBigUInt64BE(this, value, offset, -BigInt('0x8000000000000000'), BigInt('0x7fffffffffffffff'))
})

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!Buffer.isBuffer(target)) throw new TypeError('argument should be a Buffer')
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('Index out of range')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  const len = end - start

  if (this === target && typeof Uint8Array.prototype.copyWithin === 'function') {
    // Use built-in when available, missing from IE11
    this.copyWithin(targetStart, start, end)
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, end),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
    if (val.length === 1) {
      const code = val.charCodeAt(0)
      if ((encoding === 'utf8' && code < 128) ||
          encoding === 'latin1') {
        // Fast path: If `val` fits into a single byte, use that numeric value.
        val = code
      }
    }
  } else if (typeof val === 'number') {
    val = val & 255
  } else if (typeof val === 'boolean') {
    val = Number(val)
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  let i
  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val
    }
  } else {
    const bytes = Buffer.isBuffer(val)
      ? val
      : Buffer.from(val, encoding)
    const len = bytes.length
    if (len === 0) {
      throw new TypeError('The value "' + val +
        '" is invalid for argument "value"')
    }
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// CUSTOM ERRORS
// =============

// Simplified versions from Node, changed for Buffer-only usage
const errors = {}
function E (sym, getMessage, Base) {
  errors[sym] = class NodeError extends Base {
    constructor () {
      super()

      Object.defineProperty(this, 'message', {
        value: getMessage.apply(this, arguments),
        writable: true,
        configurable: true
      })

      // Add the error code to the name to include it in the stack trace.
      this.name = `${this.name} [${sym}]`
      // Access the stack to generate the error message including the error code
      // from the name.
      this.stack // eslint-disable-line no-unused-expressions
      // Reset the name to the actual name.
      delete this.name
    }

    get code () {
      return sym
    }

    set code (value) {
      Object.defineProperty(this, 'code', {
        configurable: true,
        enumerable: true,
        value,
        writable: true
      })
    }

    toString () {
      return `${this.name} [${sym}]: ${this.message}`
    }
  }
}

E('ERR_BUFFER_OUT_OF_BOUNDS',
  function (name) {
    if (name) {
      return `${name} is outside of buffer bounds`
    }

    return 'Attempt to access memory outside buffer bounds'
  }, RangeError)
E('ERR_INVALID_ARG_TYPE',
  function (name, actual) {
    return `The "${name}" argument must be of type number. Received type ${typeof actual}`
  }, TypeError)
E('ERR_OUT_OF_RANGE',
  function (str, range, input) {
    let msg = `The value of "${str}" is out of range.`
    let received = input
    if (Number.isInteger(input) && Math.abs(input) > 2 ** 32) {
      received = addNumericalSeparator(String(input))
    } else if (typeof input === 'bigint') {
      received = String(input)
      if (input > BigInt(2) ** BigInt(32) || input < -(BigInt(2) ** BigInt(32))) {
        received = addNumericalSeparator(received)
      }
      received += 'n'
    }
    msg += ` It must be ${range}. Received ${received}`
    return msg
  }, RangeError)

function addNumericalSeparator (val) {
  let res = ''
  let i = val.length
  const start = val[0] === '-' ? 1 : 0
  for (; i >= start + 4; i -= 3) {
    res = `_${val.slice(i - 3, i)}${res}`
  }
  return `${val.slice(0, i)}${res}`
}

// CHECK FUNCTIONS
// ===============

function checkBounds (buf, offset, byteLength) {
  validateNumber(offset, 'offset')
  if (buf[offset] === undefined || buf[offset + byteLength] === undefined) {
    boundsError(offset, buf.length - (byteLength + 1))
  }
}

function checkIntBI (value, min, max, buf, offset, byteLength) {
  if (value > max || value < min) {
    const n = typeof min === 'bigint' ? 'n' : ''
    let range
    if (byteLength > 3) {
      if (min === 0 || min === BigInt(0)) {
        range = `>= 0${n} and < 2${n} ** ${(byteLength + 1) * 8}${n}`
      } else {
        range = `>= -(2${n} ** ${(byteLength + 1) * 8 - 1}${n}) and < 2 ** ` +
                `${(byteLength + 1) * 8 - 1}${n}`
      }
    } else {
      range = `>= ${min}${n} and <= ${max}${n}`
    }
    throw new errors.ERR_OUT_OF_RANGE('value', range, value)
  }
  checkBounds(buf, offset, byteLength)
}

function validateNumber (value, name) {
  if (typeof value !== 'number') {
    throw new errors.ERR_INVALID_ARG_TYPE(name, 'number', value)
  }
}

function boundsError (value, length, type) {
  if (Math.floor(value) !== value) {
    validateNumber(value, type)
    throw new errors.ERR_OUT_OF_RANGE(type || 'offset', 'an integer', value)
  }

  if (length < 0) {
    throw new errors.ERR_BUFFER_OUT_OF_BOUNDS()
  }

  throw new errors.ERR_OUT_OF_RANGE(type || 'offset',
                                    `>= ${type ? 1 : 0} and <= ${length}`,
                                    value)
}

// HELPER FUNCTIONS
// ================

const INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node takes equal signs as end of the Base64 encoding
  str = str.split('=')[0]
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = str.trim().replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  let codePoint
  const length = string.length
  let leadSurrogate = null
  const bytes = []

  for (let i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  const byteArray = []
  for (let i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  let c, hi, lo
  const byteArray = []
  for (let i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  let i
  for (i = 0; i < length; ++i) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

// ArrayBuffer or Uint8Array objects from other contexts (i.e. iframes) do not pass
// the `instanceof` check but they should be treated as of that type.
// See: https://github.com/feross/buffer/issues/166
function isInstance (obj, type) {
  return obj instanceof type ||
    (obj != null && obj.constructor != null && obj.constructor.name != null &&
      obj.constructor.name === type.name)
}
function numberIsNaN (obj) {
  // For IE11 support
  return obj !== obj // eslint-disable-line no-self-compare
}

// Create lookup table for `toString('hex')`
// See: https://github.com/feross/buffer/issues/219
const hexSliceLookupTable = (function () {
  const alphabet = '0123456789abcdef'
  const table = new Array(256)
  for (let i = 0; i < 16; ++i) {
    const i16 = i * 16
    for (let j = 0; j < 16; ++j) {
      table[i16 + j] = alphabet[i] + alphabet[j]
    }
  }
  return table
})()

// Return not function with Error if BigInt not supported
function defineBigIntMethod (fn) {
  return typeof BigInt === 'undefined' ? BufferBigIntNotDefined : fn
}

function BufferBigIntNotDefined () {
  throw new Error('BigInt not supported')
}


/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			id: moduleId,
/******/ 			loaded: false,
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Flag the module as loaded
/******/ 		module.loaded = true;
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = __webpack_modules__;
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat get default export */
/******/ 	(() => {
/******/ 		// getDefaultExport function for compatibility with non-harmony modules
/******/ 		__webpack_require__.n = (module) => {
/******/ 			var getter = module && module.__esModule ?
/******/ 				() => (module['default']) :
/******/ 				() => (module);
/******/ 			__webpack_require__.d(getter, { a: getter });
/******/ 			return getter;
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/create fake namespace object */
/******/ 	(() => {
/******/ 		var getProto = Object.getPrototypeOf ? (obj) => (Object.getPrototypeOf(obj)) : (obj) => (obj.__proto__);
/******/ 		var leafPrototypes;
/******/ 		// create a fake namespace object
/******/ 		// mode & 1: value is a module id, require it
/******/ 		// mode & 2: merge all properties of value into the ns
/******/ 		// mode & 4: return value when already ns object
/******/ 		// mode & 16: return value when it's Promise-like
/******/ 		// mode & 8|1: behave like require
/******/ 		__webpack_require__.t = function(value, mode) {
/******/ 			if(mode & 1) value = this(value);
/******/ 			if(mode & 8) return value;
/******/ 			if(typeof value === 'object' && value) {
/******/ 				if((mode & 4) && value.__esModule) return value;
/******/ 				if((mode & 16) && typeof value.then === 'function') return value;
/******/ 			}
/******/ 			var ns = Object.create(null);
/******/ 			__webpack_require__.r(ns);
/******/ 			var def = {};
/******/ 			leafPrototypes = leafPrototypes || [null, getProto({}), getProto([]), getProto(getProto)];
/******/ 			for(var current = mode & 2 && value; typeof current == 'object' && !~leafPrototypes.indexOf(current); current = getProto(current)) {
/******/ 				Object.getOwnPropertyNames(current).forEach((key) => (def[key] = () => (value[key])));
/******/ 			}
/******/ 			def['default'] = () => (value);
/******/ 			__webpack_require__.d(ns, def);
/******/ 			return ns;
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/define property getters */
/******/ 	(() => {
/******/ 		// define getter functions for harmony exports
/******/ 		__webpack_require__.d = (exports, definition) => {
/******/ 			for(var key in definition) {
/******/ 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/ensure chunk */
/******/ 	(() => {
/******/ 		__webpack_require__.f = {};
/******/ 		// This file contains only the entry chunk.
/******/ 		// The chunk loading function for additional chunks
/******/ 		__webpack_require__.e = (chunkId) => {
/******/ 			return Promise.all(Object.keys(__webpack_require__.f).reduce((promises, key) => {
/******/ 				__webpack_require__.f[key](chunkId, promises);
/******/ 				return promises;
/******/ 			}, []));
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/get javascript chunk filename */
/******/ 	(() => {
/******/ 		// This function allow to reference async chunks
/******/ 		__webpack_require__.u = (chunkId) => {
/******/ 			// return url for filenames based on template
/******/ 			return "" + chunkId + ".main.js";
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/global */
/******/ 	(() => {
/******/ 		__webpack_require__.g = (function() {
/******/ 			if (typeof globalThis === 'object') return globalThis;
/******/ 			try {
/******/ 				return this || new Function('return this')();
/******/ 			} catch (e) {
/******/ 				if (typeof window === 'object') return window;
/******/ 			}
/******/ 		})();
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/load script */
/******/ 	(() => {
/******/ 		var inProgress = {};
/******/ 		var dataWebpackPrefix = "gaoma_pre:";
/******/ 		// loadScript function to load a script via script tag
/******/ 		__webpack_require__.l = (url, done, key, chunkId) => {
/******/ 			if(inProgress[url]) { inProgress[url].push(done); return; }
/******/ 			var script, needAttach;
/******/ 			if(key !== undefined) {
/******/ 				var scripts = document.getElementsByTagName("script");
/******/ 				for(var i = 0; i < scripts.length; i++) {
/******/ 					var s = scripts[i];
/******/ 					if(s.getAttribute("src") == url || s.getAttribute("data-webpack") == dataWebpackPrefix + key) { script = s; break; }
/******/ 				}
/******/ 			}
/******/ 			if(!script) {
/******/ 				needAttach = true;
/******/ 				script = document.createElement('script');
/******/ 		
/******/ 				script.charset = 'utf-8';
/******/ 				script.timeout = 120;
/******/ 				if (__webpack_require__.nc) {
/******/ 					script.setAttribute("nonce", __webpack_require__.nc);
/******/ 				}
/******/ 				script.setAttribute("data-webpack", dataWebpackPrefix + key);
/******/ 		
/******/ 				script.src = url;
/******/ 			}
/******/ 			inProgress[url] = [done];
/******/ 			var onScriptComplete = (prev, event) => {
/******/ 				// avoid mem leaks in IE.
/******/ 				script.onerror = script.onload = null;
/******/ 				clearTimeout(timeout);
/******/ 				var doneFns = inProgress[url];
/******/ 				delete inProgress[url];
/******/ 				script.parentNode && script.parentNode.removeChild(script);
/******/ 				doneFns && doneFns.forEach((fn) => (fn(event)));
/******/ 				if(prev) return prev(event);
/******/ 			}
/******/ 			var timeout = setTimeout(onScriptComplete.bind(null, undefined, { type: 'timeout', target: script }), 120000);
/******/ 			script.onerror = onScriptComplete.bind(null, script.onerror);
/******/ 			script.onload = onScriptComplete.bind(null, script.onload);
/******/ 			needAttach && document.head.appendChild(script);
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/make namespace object */
/******/ 	(() => {
/******/ 		// define __esModule on exports
/******/ 		__webpack_require__.r = (exports) => {
/******/ 			if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 				Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 			}
/******/ 			Object.defineProperty(exports, '__esModule', { value: true });
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/node module decorator */
/******/ 	(() => {
/******/ 		__webpack_require__.nmd = (module) => {
/******/ 			module.paths = [];
/******/ 			if (!module.children) module.children = [];
/******/ 			return module;
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/publicPath */
/******/ 	(() => {
/******/ 		var scriptUrl;
/******/ 		if (__webpack_require__.g.importScripts) scriptUrl = __webpack_require__.g.location + "";
/******/ 		var document = __webpack_require__.g.document;
/******/ 		if (!scriptUrl && document) {
/******/ 			if (document.currentScript && document.currentScript.tagName.toUpperCase() === 'SCRIPT')
/******/ 				scriptUrl = document.currentScript.src;
/******/ 			if (!scriptUrl) {
/******/ 				var scripts = document.getElementsByTagName("script");
/******/ 				if(scripts.length) {
/******/ 					var i = scripts.length - 1;
/******/ 					while (i > -1 && (!scriptUrl || !/^http(s?):/.test(scriptUrl))) scriptUrl = scripts[i--].src;
/******/ 				}
/******/ 			}
/******/ 		}
/******/ 		// When supporting browsers where an automatic publicPath is not supported you must specify an output.publicPath manually via configuration
/******/ 		// or pass an empty string ("") and set the __webpack_public_path__ variable from your code to use your own logic.
/******/ 		if (!scriptUrl) throw new Error("Automatic publicPath is not supported in this browser");
/******/ 		scriptUrl = scriptUrl.replace(/^blob:/, "").replace(/#.*$/, "").replace(/\?.*$/, "").replace(/\/[^\/]+$/, "/");
/******/ 		__webpack_require__.p = scriptUrl;
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/jsonp chunk loading */
/******/ 	(() => {
/******/ 		// no baseURI
/******/ 		
/******/ 		// object to store loaded and loading chunks
/******/ 		// undefined = chunk not loaded, null = chunk preloaded/prefetched
/******/ 		// [resolve, reject, Promise] = chunk loading, 0 = chunk loaded
/******/ 		var installedChunks = {
/******/ 			792: 0
/******/ 		};
/******/ 		
/******/ 		__webpack_require__.f.j = (chunkId, promises) => {
/******/ 				// JSONP chunk loading for javascript
/******/ 				var installedChunkData = __webpack_require__.o(installedChunks, chunkId) ? installedChunks[chunkId] : undefined;
/******/ 				if(installedChunkData !== 0) { // 0 means "already installed".
/******/ 		
/******/ 					// a Promise means "currently loading".
/******/ 					if(installedChunkData) {
/******/ 						promises.push(installedChunkData[2]);
/******/ 					} else {
/******/ 						if(true) { // all chunks have JS
/******/ 							// setup Promise in chunk cache
/******/ 							var promise = new Promise((resolve, reject) => (installedChunkData = installedChunks[chunkId] = [resolve, reject]));
/******/ 							promises.push(installedChunkData[2] = promise);
/******/ 		
/******/ 							// start chunk loading
/******/ 							var url = __webpack_require__.p + __webpack_require__.u(chunkId);
/******/ 							// create error before stack unwound to get useful stacktrace later
/******/ 							var error = new Error();
/******/ 							var loadingEnded = (event) => {
/******/ 								if(__webpack_require__.o(installedChunks, chunkId)) {
/******/ 									installedChunkData = installedChunks[chunkId];
/******/ 									if(installedChunkData !== 0) installedChunks[chunkId] = undefined;
/******/ 									if(installedChunkData) {
/******/ 										var errorType = event && (event.type === 'load' ? 'missing' : event.type);
/******/ 										var realSrc = event && event.target && event.target.src;
/******/ 										error.message = 'Loading chunk ' + chunkId + ' failed.\n(' + errorType + ': ' + realSrc + ')';
/******/ 										error.name = 'ChunkLoadError';
/******/ 										error.type = errorType;
/******/ 										error.request = realSrc;
/******/ 										installedChunkData[1](error);
/******/ 									}
/******/ 								}
/******/ 							};
/******/ 							__webpack_require__.l(url, loadingEnded, "chunk-" + chunkId, chunkId);
/******/ 						}
/******/ 					}
/******/ 				}
/******/ 		};
/******/ 		
/******/ 		// no prefetching
/******/ 		
/******/ 		// no preloaded
/******/ 		
/******/ 		// no HMR
/******/ 		
/******/ 		// no HMR manifest
/******/ 		
/******/ 		// no on chunks loaded
/******/ 		
/******/ 		// install a JSONP callback for chunk loading
/******/ 		var webpackJsonpCallback = (parentChunkLoadingFunction, data) => {
/******/ 			var [chunkIds, moreModules, runtime] = data;
/******/ 			// add "moreModules" to the modules object,
/******/ 			// then flag all "chunkIds" as loaded and fire callback
/******/ 			var moduleId, chunkId, i = 0;
/******/ 			if(chunkIds.some((id) => (installedChunks[id] !== 0))) {
/******/ 				for(moduleId in moreModules) {
/******/ 					if(__webpack_require__.o(moreModules, moduleId)) {
/******/ 						__webpack_require__.m[moduleId] = moreModules[moduleId];
/******/ 					}
/******/ 				}
/******/ 				if(runtime) var result = runtime(__webpack_require__);
/******/ 			}
/******/ 			if(parentChunkLoadingFunction) parentChunkLoadingFunction(data);
/******/ 			for(;i < chunkIds.length; i++) {
/******/ 				chunkId = chunkIds[i];
/******/ 				if(__webpack_require__.o(installedChunks, chunkId) && installedChunks[chunkId]) {
/******/ 					installedChunks[chunkId][0]();
/******/ 				}
/******/ 				installedChunks[chunkId] = 0;
/******/ 			}
/******/ 		
/******/ 		}
/******/ 		
/******/ 		var chunkLoadingGlobal = self["webpackChunkgaoma_pre"] = self["webpackChunkgaoma_pre"] || [];
/******/ 		chunkLoadingGlobal.forEach(webpackJsonpCallback.bind(null, 0));
/******/ 		chunkLoadingGlobal.push = webpackJsonpCallback.bind(null, chunkLoadingGlobal.push.bind(chunkLoadingGlobal));
/******/ 	})();
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry needs to be wrapped in an IIFE because it needs to be in strict mode.
(() => {
"use strict";

;// ./node_modules/crystals-kyber-js/esm/src/errors.js
/**
 * The base error class of kyber-ts.
 */
class MlKemError extends Error {
    constructor(e) {
        let message;
        if (e instanceof Error) {
            message = e.message;
        }
        else if (typeof e === "string") {
            message = e;
        }
        else {
            message = "";
        }
        super(message);
        this.name = this.constructor.name;
    }
}

;// ./node_modules/crystals-kyber-js/esm/src/consts.js
/**
 * This implementation is based on https://github.com/antontutoveanu/crystals-kyber-javascript,
 * which was deveploped under the MIT licence below:
 * https://github.com/antontutoveanu/crystals-kyber-javascript/blob/main/LICENSE
 */
const N = 256;
const Q = 3329;
const Q_INV = 62209;
// deno-fmt-ignore
const NTT_ZETAS = [
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,
    2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,
    732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,
    1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,
    107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,
    430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,
    1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
    418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
    1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459,
    478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628,
];
// deno-fmt-ignore
const NTT_ZETAS_INV = [
    1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535,
    1278, 1530, 1185, 1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465,
    1285, 2007, 2719, 2726, 2232, 2512, 75, 156, 3000, 2911, 2980, 872, 2685,
    1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676, 1755, 460, 291, 235,
    3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275, 2652,
    1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853,
    1860, 3203, 1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552,
    2677, 2106, 1571, 205, 2918, 1542, 2721, 2597, 2312, 681, 130, 1602, 1871,
    829, 2946, 3065, 1325, 2756, 1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
    3127, 3042, 1907, 1836, 1517, 359, 758, 1441,
];

;// ./node_modules/crystals-kyber-js/esm/src/sha3/_u64.js
/**
 * This file is based on noble-hashes (https://github.com/paulmillr/noble-hashes).
 *
 * noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-hashes/blob/4e358a46d682adfb005ae6314ec999f2513086b9/src/_u64.ts
 */
/**
 * Internal helpers for u64. BigUint64Array is too slow as per 2025, so we implement it using Uint32Array.
 * @todo re-check https://issues.chromium.org/issues/42212588
 * @module
 */
const U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
const _32n = /* @__PURE__ */ BigInt(32);
function fromBig(n, le = false) {
    if (le) {
        return { h: Number(n & U32_MASK64), l: Number((n >> _32n) & U32_MASK64) };
    }
    return {
        h: Number((n >> _32n) & U32_MASK64) | 0,
        l: Number(n & U32_MASK64) | 0,
    };
}
function split(lst, le = false) {
    const len = lst.length;
    const Ah = new Uint32Array(len);
    const Al = new Uint32Array(len);
    for (let i = 0; i < len; i++) {
        const { h, l } = fromBig(lst[i], le);
        [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
}
const toBig = (h, l) => (BigInt(h >>> 0) << _32n) | BigInt(l >>> 0);
// for Shift in [0, 32)
const shrSH = (h, _l, s) => h >>> s;
const shrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
// Right rotate for Shift in [1, 32)
const rotrSH = (h, l, s) => (h >>> s) | (l << (32 - s));
const rotrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
// Right rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotrBH = (h, l, s) => (h << (64 - s)) | (l >>> (s - 32));
const rotrBL = (h, l, s) => (h >>> (s - 32)) | (l << (64 - s));
// Right rotate for shift===32 (just swaps l&h)
const rotr32H = (_h, l) => l;
const rotr32L = (h, _l) => h;
// Left rotate for Shift in [1, 32)
const rotlSH = (h, l, s) => (h << s) | (l >>> (32 - s));
const rotlSL = (h, l, s) => (l << s) | (h >>> (32 - s));
// Left rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotlBH = (h, l, s) => (l << (s - 32)) | (h >>> (64 - s));
const rotlBL = (h, l, s) => (h << (s - 32)) | (l >>> (64 - s));
// JS uses 32-bit signed integers for bitwise operations which means we cannot
// simple take carry out of low bit sum by shift, we need to use division.
function add(Ah, Al, Bh, Bl) {
    const l = (Al >>> 0) + (Bl >>> 0);
    return { h: (Ah + Bh + ((l / 2 ** 32) | 0)) | 0, l: l | 0 };
}
// Addition with more than 2 elements
const add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
const add3H = (low, Ah, Bh, Ch) => (Ah + Bh + Ch + ((low / 2 ** 32) | 0)) | 0;
const add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
const add4H = (low, Ah, Bh, Ch, Dh) => (Ah + Bh + Ch + Dh + ((low / 2 ** 32) | 0)) | 0;
const add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
const add5H = (low, Ah, Bh, Ch, Dh, Eh) => (Ah + Bh + Ch + Dh + Eh + ((low / 2 ** 32) | 0)) | 0;
// prettier-ignore

// prettier-ignore
const u64 = {
    fromBig,
    split,
    toBig,
    shrSH,
    shrSL,
    rotrSH,
    rotrSL,
    rotrBH,
    rotrBL,
    rotr32H,
    rotr32L,
    rotlSH,
    rotlSL,
    rotlBH,
    rotlBL,
    add,
    add3L,
    add3H,
    add4L,
    add4H,
    add5H,
    add5L,
};
/* harmony default export */ const _u64 = ((/* unused pure expression or super */ null && (u64)));

;// ./node_modules/crystals-kyber-js/esm/src/sha3/utils.js
// deno-lint-ignore-file no-explicit-any
/**
 * This file is based on noble-hashes (https://github.com/paulmillr/noble-hashes).
 *
 * noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-hashes/blob/4e358a46d682adfb005ae6314ec999f2513086b9/src/utils.ts
 */
/**
 * Utilities for hex, bytes, CSPRNG.
 * @module
 */
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
/** Checks if something is Uint8Array. Be careful: nodejs Buffer will return true. */
function isBytes(a) {
    return a instanceof Uint8Array ||
        (ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array");
}
/** Asserts something is positive integer. */
function utils_anumber(n, title = "") {
    if (!Number.isSafeInteger(n) || n < 0) {
        const prefix = title && `"${title}" `;
        throw new Error(`${prefix}expected integer >0, got ${n}`);
    }
}
/** Asserts something is Uint8Array. */
function utils_abytes(value, length, title = "") {
    const bytes = isBytes(value);
    const len = value?.length;
    const needsLen = length !== undefined;
    if (!bytes || (needsLen && len !== length)) {
        const prefix = title && `"${title}" `;
        const ofLen = needsLen ? ` of length ${length}` : "";
        const got = bytes ? `length=${len}` : `type=${typeof value}`;
        throw new Error(prefix + "expected Uint8Array" + ofLen + ", got " + got);
    }
    return value;
}
/** Asserts a hash instance has not been destroyed / finished */
function aexists(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error("Hash instance has been destroyed");
    if (checkFinished && instance.finished) {
        throw new Error("Hash#digest() has already been called");
    }
}
/** Asserts output is properly-sized byte array */
function aoutput(out, instance) {
    utils_abytes(out, undefined, "digestInto() output");
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error('"digestInto() output" expected to be of length >=' + min);
    }
}
/** Cast u8 / u16 / u32 to u32. */
function u32(arr) {
    return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
/** Zeroize a byte array. Warning: JS provides no guarantees. */
function clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
        arrays[i].fill(0);
    }
}
/** Is current platform little-endian? Most are. Big-Endian platform: IBM */
const isLE = 
/* @__PURE__ */ (() => new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44)();
/** The byte swap operation for uint32 */
function byteSwap(word) {
    return (((word << 24) & 0xff000000) |
        ((word << 8) & 0xff0000) |
        ((word >>> 8) & 0xff00) |
        ((word >>> 24) & 0xff));
}
/** Conditionally byte swap if on a big-endian platform */
const swap8IfBE = (/* unused pure expression or super */ null && (isLE
    ? (n) => n
    : (n) => byteSwap(n)));
/** @deprecated */
const byteSwapIfBE = (/* unused pure expression or super */ null && (swap8IfBE));
/** In place byte swap for Uint32Array */
function byteSwap32(arr) {
    for (let i = 0; i < arr.length; i++) {
        arr[i] = byteSwap(arr[i]);
    }
    return arr;
}
const swap32IfBE = isLE
    ? (u) => u
    : byteSwap32;
// Built-in hex conversion https://caniuse.com/mdn-javascript_builtins_uint8array_fromhex
const hasHexBuiltin = /* @__PURE__ */ (/* unused pure expression or super */ null && ((() => 
// @ts-ignore: to check the existence of the method
typeof Uint8Array.from([]).toHex === "function" &&
    // @ts-ignore: to check the existence of the method
    typeof Uint8Array.fromHex === "function")()));
// We use optimized technique to convert hex string to byte array
const asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
function asciiToBase16(ch) {
    if (ch >= asciis._0 && ch <= asciis._9)
        return ch - asciis._0; // '2' => 50-48
    if (ch >= asciis.A && ch <= asciis.F)
        return ch - (asciis.A - 10); // 'B' => 66-(65-10)
    if (ch >= asciis.a && ch <= asciis.f)
        return ch - (asciis.a - 10); // 'b' => 98-(97-10)
    return;
}
/**
 * Convert hex string to byte array. Uses built-in function, when available.
 * @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
 */
function hexToBytes(hex) {
    if (typeof hex !== "string") {
        throw new Error("hex string expected, got " + typeof hex);
    }
    // @ts-ignore: to check the existence of the method
    if (hasHexBuiltin)
        return Uint8Array.fromHex(hex);
    const hl = hex.length;
    const al = hl / 2;
    if (hl % 2) {
        throw new Error("hex string expected, got unpadded hex of length " + hl);
    }
    const array = new Uint8Array(al);
    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
        const n1 = asciiToBase16(hex.charCodeAt(hi));
        const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
        if (n1 === undefined || n2 === undefined) {
            const char = hex[hi] + hex[hi + 1];
            throw new Error('hex string expected, got non-hex character "' + char + '" at index ' +
                hi);
        }
        array[ai] = n1 * 16 + n2; // multiply first octet, e.g. 'a3' => 10*16+3 => 160 + 3 => 163
    }
    return array;
}
/**
 * Converts string to bytes using UTF8 encoding.
 * @example utf8ToBytes('abc') // Uint8Array.from([97, 98, 99])
 */
function utf8ToBytes(str) {
    if (typeof str !== "string")
        throw new Error("string expected");
    return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
}
/**
 * Converts bytes to string using UTF8 encoding.
 * @example bytesToUtf8(Uint8Array.from([97, 98, 99])) // 'abc'
 */
function bytesToUtf8(bytes) {
    return new TextDecoder().decode(bytes);
}
/** Copies several Uint8Arrays into one. */
function utils_concatBytes(...arrays) {
    let sum = 0;
    for (let i = 0; i < arrays.length; i++) {
        const a = arrays[i];
        utils_abytes(a);
        sum += a.length;
    }
    const res = new Uint8Array(sum);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const a = arrays[i];
        res.set(a, pad);
        pad += a.length;
    }
    return res;
}
function createHasher(hashCons, info = {}) {
    const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
    const tmp = hashCons(undefined);
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = (opts) => hashCons(opts);
    Object.assign(hashC, info);
    return Object.freeze(hashC);
}
// 06 09 60 86 48 01 65 03 04 02
const oidNist = (suffix) => ({
    oid: Uint8Array.from([
        0x06,
        0x09,
        0x60,
        0x86,
        0x48,
        0x01,
        0x65,
        0x03,
        0x04,
        0x02,
        suffix,
    ]),
});

;// ./node_modules/crystals-kyber-js/esm/src/sha3/sha3.js
/**
 * This file is based on noble-hashes (https://github.com/paulmillr/noble-hashes).
 *
 * noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-hashes/blob/4e358a46d682adfb005ae6314ec999f2513086b9/src/sha3.ts
 */
/**
 * SHA3 (keccak) hash function, based on a new "Sponge function" design.
 * Different from older hashes, the internal state is bigger than output size.
 *
 * Check out [FIPS-202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf),
 * [Website](https://keccak.team/keccak.html),
 * [the differences between SHA-3 and Keccak](https://crypto.stackexchange.com/questions/15727/what-are-the-key-differences-between-the-draft-sha-3-standard-and-the-keccak-sub).
 *
 * Check out `sha3-addons` module for cSHAKE, k12, and others.
 * @module
 */

// prettier-ignore

// No __PURE__ annotations in sha3 header:
// EVERYTHING is in fact used on every export.
// Various per round constants calculations
const _0n = BigInt(0);
const _1n = BigInt(1);
const _2n = BigInt(2);
const _7n = BigInt(7);
const _256n = BigInt(256);
const _0x71n = BigInt(0x71);
const SHA3_PI = [];
const SHA3_ROTL = [];
const _SHA3_IOTA = []; // no pure annotation: var is always used
for (let round = 0, R = _1n, x = 1, y = 0; round < 24; round++) {
    // Pi
    [x, y] = [y, (2 * x + 3 * y) % 5];
    SHA3_PI.push(2 * (5 * y + x));
    // Rotational
    SHA3_ROTL.push((((round + 1) * (round + 2)) / 2) % 64);
    // Iota
    let t = _0n;
    for (let j = 0; j < 7; j++) {
        R = ((R << _1n) ^ ((R >> _7n) * _0x71n)) % _256n;
        if (R & _2n)
            t ^= _1n << ((_1n << BigInt(j)) - _1n);
    }
    _SHA3_IOTA.push(t);
}
const IOTAS = split(_SHA3_IOTA, true);
const SHA3_IOTA_H = IOTAS[0];
const SHA3_IOTA_L = IOTAS[1];
// Left rotation (without 0, 32, 64)
const rotlH = (h, l, s) => (s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s));
const rotlL = (h, l, s) => (s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s));
/** `keccakf1600` internal function, additionally allows to adjust round count. */
function keccakP(s, rounds = 24) {
    const B = new Uint32Array(5 * 2);
    // NOTE: all indices are x2 since we store state as u32 instead of u64 (bigints to slow in js)
    for (let round = 24 - rounds; round < 24; round++) {
        // Theta θ
        for (let x = 0; x < 10; x++) {
            B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
        }
        for (let x = 0; x < 10; x += 2) {
            const idx1 = (x + 8) % 10;
            const idx0 = (x + 2) % 10;
            const B0 = B[idx0];
            const B1 = B[idx0 + 1];
            const Th = rotlH(B0, B1, 1) ^ B[idx1];
            const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
            for (let y = 0; y < 50; y += 10) {
                s[x + y] ^= Th;
                s[x + y + 1] ^= Tl;
            }
        }
        // Rho (ρ) and Pi (π)
        let curH = s[2];
        let curL = s[3];
        for (let t = 0; t < 24; t++) {
            const shift = SHA3_ROTL[t];
            const Th = rotlH(curH, curL, shift);
            const Tl = rotlL(curH, curL, shift);
            const PI = SHA3_PI[t];
            curH = s[PI];
            curL = s[PI + 1];
            s[PI] = Th;
            s[PI + 1] = Tl;
        }
        // Chi (χ)
        for (let y = 0; y < 50; y += 10) {
            for (let x = 0; x < 10; x++)
                B[x] = s[y + x];
            for (let x = 0; x < 10; x++) {
                s[y + x] ^= ~B[(x + 2) % 10] & B[(x + 4) % 10];
            }
        }
        // Iota (ι)
        s[0] ^= SHA3_IOTA_H[round];
        s[1] ^= SHA3_IOTA_L[round];
    }
    clean(B);
}
/** Keccak sponge function. */
class Keccak {
    // NOTE: we accept arguments in bytes instead of bits here.
    constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
        Object.defineProperty(this, "state", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "pos", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 0
        });
        Object.defineProperty(this, "posOut", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 0
        });
        Object.defineProperty(this, "finished", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: false
        });
        Object.defineProperty(this, "state32", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "destroyed", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: false
        });
        Object.defineProperty(this, "blockLen", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "suffix", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "outputLen", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "enableXOF", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: false
        });
        Object.defineProperty(this, "rounds", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        this.blockLen = blockLen;
        this.suffix = suffix;
        this.outputLen = outputLen;
        this.enableXOF = enableXOF;
        this.rounds = rounds;
        // Can be passed from user as dkLen
        utils_anumber(outputLen, "outputLen");
        // 1600 = 5x5 matrix of 64bit.  1600 bits === 200 bytes
        // 0 < blockLen < 200
        if (!(0 < blockLen && blockLen < 200)) {
            throw new Error("only keccak-f1600 function is supported");
        }
        this.state = new Uint8Array(200);
        this.state32 = u32(this.state);
    }
    clone() {
        return this._cloneInto();
    }
    keccak() {
        swap32IfBE(this.state32);
        keccakP(this.state32, this.rounds);
        swap32IfBE(this.state32);
        this.posOut = 0;
        this.pos = 0;
    }
    update(data) {
        aexists(this);
        utils_abytes(data);
        const { blockLen, state } = this;
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            for (let i = 0; i < take; i++)
                state[this.pos++] ^= data[pos++];
            if (this.pos === blockLen)
                this.keccak();
        }
        return this;
    }
    finish() {
        if (this.finished)
            return;
        this.finished = true;
        const { state, suffix, pos, blockLen } = this;
        // Do the padding
        state[pos] ^= suffix;
        if ((suffix & 0x80) !== 0 && pos === blockLen - 1)
            this.keccak();
        state[blockLen - 1] ^= 0x80;
        this.keccak();
    }
    writeInto(out) {
        aexists(this, false);
        utils_abytes(out);
        this.finish();
        const bufferOut = this.state;
        const { blockLen } = this;
        for (let pos = 0, len = out.length; pos < len;) {
            if (this.posOut >= blockLen)
                this.keccak();
            const take = Math.min(blockLen - this.posOut, len - pos);
            out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
            this.posOut += take;
            pos += take;
        }
        return out;
    }
    xofInto(out) {
        // Sha3/Keccak usage with XOF is probably mistake, only SHAKE instances can do XOF
        if (!this.enableXOF) {
            throw new Error("XOF is not possible for this instance");
        }
        return this.writeInto(out);
    }
    xof(bytes) {
        utils_anumber(bytes);
        return this.xofInto(new Uint8Array(bytes));
    }
    digestInto(out) {
        aoutput(out, this);
        if (this.finished)
            throw new Error("digest() was already called");
        this.writeInto(out);
        this.destroy();
        return out;
    }
    digest() {
        return this.digestInto(new Uint8Array(this.outputLen));
    }
    destroy() {
        this.destroyed = true;
        clean(this.state);
    }
    _cloneInto(to) {
        const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
        to ||= new Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
        to.state32.set(this.state32);
        to.pos = this.pos;
        to.posOut = this.posOut;
        to.finished = this.finished;
        to.rounds = rounds;
        // Suffix can change in cSHAKE
        to.suffix = suffix;
        to.outputLen = outputLen;
        to.enableXOF = enableXOF;
        to.destroyed = this.destroyed;
        return to;
    }
}
const genKeccak = (suffix, blockLen, outputLen, info = {}) => createHasher(() => new Keccak(blockLen, suffix, outputLen), info);
// /** SHA3-224 hash function. */
// export const sha3_224: CHash = /* @__PURE__ */ genKeccak(
//   0x06,
//   144,
//   28,
//   /* @__PURE__ */ oidNist(0x07),
// );
/** SHA3-256 hash function. Different from keccak-256. */
const sha3_256 = /* @__PURE__ */ genKeccak(0x06, 136, 32, 
/* @__PURE__ */ oidNist(0x08));
// /** SHA3-384 hash function. */
// export const sha3_384: CHash = /* @__PURE__ */ genKeccak(
//   0x06,
//   104,
//   48,
//   /* @__PURE__ */ oidNist(0x09),
// );
/** SHA3-512 hash function. */
const sha3_512 = /* @__PURE__ */ genKeccak(0x06, 72, 64, 
/* @__PURE__ */ oidNist(0x0a));
/** keccak-224 hash function. */
const keccak_224 = /* @__PURE__ */ (/* unused pure expression or super */ null && (genKeccak(0x01, 144, 28)));
/** keccak-256 hash function. Different from SHA3-256. */
const keccak_256 = /* @__PURE__ */ (/* unused pure expression or super */ null && (genKeccak(0x01, 136, 32)));
/** keccak-384 hash function. */
const keccak_384 = /* @__PURE__ */ (/* unused pure expression or super */ null && (genKeccak(0x01, 104, 48)));
/** keccak-512 hash function. */
const keccak_512 = /* @__PURE__ */ (/* unused pure expression or super */ null && (genKeccak(0x01, 72, 64)));
const genShake = (suffix, blockLen, outputLen, info = {}) => createHasher((opts = {}) => new Keccak(blockLen, suffix, opts.dkLen === undefined ? outputLen : opts.dkLen, true), info);
/** SHAKE128 XOF with 128-bit security. */
const shake128 = 
/* @__PURE__ */
genShake(0x1f, 168, 16, /* @__PURE__ */ oidNist(0x0b));
/** SHAKE256 XOF with 256-bit security. */
const shake256 = 
/* @__PURE__ */
genShake(0x1f, 136, 32, /* @__PURE__ */ oidNist(0x0c));
// /** SHAKE128 XOF with 256-bit output (NIST version). */
// export const shake128_32: CHashXOF<Keccak, ShakeOpts> =
//   /* @__PURE__ */
//   genShake(0x1f, 168, 32, /* @__PURE__ */ oidNist(0x0b));
// /** SHAKE256 XOF with 512-bit output (NIST version). */
// export const shake256_64: CHashXOF<Keccak, ShakeOpts> =
//   /* @__PURE__ */
//   genShake(0x1f, 136, 64, /* @__PURE__ */ oidNist(0x0c));

;// ./node_modules/crystals-kyber-js/esm/src/deps.js


;// ./node_modules/crystals-kyber-js/esm/_dnt.shims.js
const dntGlobals = {};
const dntGlobalThis = createMergeProxy(globalThis, dntGlobals);
function createMergeProxy(baseObj, extObj) {
    return new Proxy(baseObj, {
        get(_target, prop, _receiver) {
            if (prop in extObj) {
                return extObj[prop];
            }
            else {
                return baseObj[prop];
            }
        },
        set(_target, prop, value) {
            if (prop in extObj) {
                delete extObj[prop];
            }
            baseObj[prop] = value;
            return true;
        },
        deleteProperty(_target, prop) {
            let success = false;
            if (prop in extObj) {
                delete extObj[prop];
                success = true;
            }
            if (prop in baseObj) {
                delete baseObj[prop];
                success = true;
            }
            return success;
        },
        ownKeys(_target) {
            const baseKeys = Reflect.ownKeys(baseObj);
            const extKeys = Reflect.ownKeys(extObj);
            const extKeysSet = new Set(extKeys);
            return [...baseKeys.filter((k) => !extKeysSet.has(k)), ...extKeys];
        },
        defineProperty(_target, prop, desc) {
            if (prop in extObj) {
                delete extObj[prop];
            }
            Reflect.defineProperty(baseObj, prop, desc);
            return true;
        },
        getOwnPropertyDescriptor(_target, prop) {
            if (prop in extObj) {
                return Reflect.getOwnPropertyDescriptor(extObj, prop);
            }
            else {
                return Reflect.getOwnPropertyDescriptor(baseObj, prop);
            }
        },
        has(_target, prop) {
            return prop in extObj || prop in baseObj;
        },
    });
}

;// ./node_modules/crystals-kyber-js/esm/src/utils.js


function utils_byte(n) {
    return n % 256;
}
function int16(n) {
    const end = -32768;
    const start = 32767;
    if (n >= end && n <= start) {
        return n;
    }
    if (n < end) {
        n = n + 32769;
        n = n % 65536;
        return start + n;
    }
    // if (n > start) {
    n = n - 32768;
    n = n % 65536;
    return end + n;
}
function uint16(n) {
    return n % 65536;
}
function int32(n) {
    const end = -2147483648;
    const start = 2147483647;
    if (n >= end && n <= start) {
        return n;
    }
    if (n < end) {
        n = n + 2147483649;
        n = n % 4294967296;
        return start + n;
    }
    // if (n > start) {
    n = n - 2147483648;
    n = n % 4294967296;
    return end + n;
}
// any bit operations to be done in uint32 must have >>> 0
// javascript calculates bitwise in SIGNED 32 bit so you need to convert
function uint32(n) {
    return n % 4294967296;
}
/**
 * compares two arrays
 * @returns 1 if they are the same or 0 if not
 */
function constantTimeCompare(x, y) {
    // check array lengths
    if (x.length != y.length) {
        return 0;
    }
    const v = new Uint8Array([0]);
    for (let i = 0; i < x.length; i++) {
        v[0] |= x[i] ^ y[i];
    }
    // constantTimeByteEq
    const z = new Uint8Array([0]);
    z[0] = ~(v[0] ^ z[0]);
    z[0] &= z[0] >> 4;
    z[0] &= z[0] >> 2;
    z[0] &= z[0] >> 1;
    return z[0];
}
function equalUint8Array(x, y) {
    if (x.length != y.length) {
        return false;
    }
    for (let i = 0; i < x.length; i++) {
        if (x[i] !== y[i]) {
            return false;
        }
    }
    return true;
}
async function loadCrypto() {
    if (typeof dntGlobalThis !== "undefined" && globalThis.crypto !== undefined) {
        // Browsers, Node.js >= v19, Cloudflare Workers, Bun, etc.
        return globalThis.crypto;
    }
    // Node.js <= v18
    try {
        // @ts-ignore: to ignore "crypto"
        const { webcrypto } = await Promise.all(/* import() */[__webpack_require__.e(565), __webpack_require__.e(143)]).then(__webpack_require__.t.bind(__webpack_require__, 1565, 19)); // node:crypto
        return webcrypto;
    }
    catch (_e) {
        throw new Error("failed to load Crypto");
    }
}
// prf provides a pseudo-random function (PRF) which returns
// a byte array of length `l`, using the provided key and nonce
// to instantiate the PRF's underlying hash function.
function prf(len, seed, nonce) {
    return shake256.create({ dkLen: len }).update(seed).update(new Uint8Array([nonce])).digest();
}
// byteopsLoad24 returns a 32-bit unsigned integer loaded from byte x.
function byteopsLoad24(x) {
    let r = uint32(x[0]);
    r |= uint32(x[1]) << 8;
    r |= uint32(x[2]) << 16;
    return r;
}
// byteopsLoad32 returns a 32-bit unsigned integer loaded from byte x.
function byteopsLoad32(x) {
    let r = uint32(x[0]);
    r |= uint32(x[1]) << 8;
    r |= uint32(x[2]) << 16;
    r |= uint32(x[3]) << 24;
    return uint32(r);
}

;// ./node_modules/crystals-kyber-js/esm/src/mlKemBase.js
/**
 * This implementation is based on https://github.com/antontutoveanu/crystals-kyber-javascript,
 * which was deveploped under the MIT licence below:
 * https://github.com/antontutoveanu/crystals-kyber-javascript/blob/main/LICENSE
 */




/**
 * Represents the base class for the ML-KEM key encapsulation mechanism.
 *
 * This class provides the base implementation for the ML-KEM key encapsulation mechanism.
 *
 * @remarks
 *
 * This class is not intended to be used directly. Instead, use one of the subclasses:
 *
 * @example
 *
 * ```ts
 * // Using jsr:
 * import { MlKemBase } from "@dajiaji/mlkem";
 * // Using npm:
 * // import { MlKemBase } from "mlkem"; // or "crystals-kyber-js"
 *
 * class MlKem768 extends MlKemBase {
 *   protected _k = 3;
 *   protected _du = 10;
 *   protected _dv = 4;
 *   protected _eta1 = 2;
 *   protected _eta2 = 2;
 *
 *   constructor() {
 *     super();
 *     this._skSize = 12 * this._k * N / 8;
 *     this._pkSize = this._skSize + 32;
 *     this._compressedUSize = this._k * this._du * N / 8;
 *     this._compressedVSize = this._dv * N / 8;
 *   }
 * }
 *
 * const kyber = new MlKem768();
 * ```
 */
class MlKemBase {
    /**
     * Creates a new instance of the MlKemBase class.
     */
    constructor() {
        Object.defineProperty(this, "_api", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: undefined
        });
        Object.defineProperty(this, "_k", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 0
        });
        Object.defineProperty(this, "_du", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 0
        });
        Object.defineProperty(this, "_dv", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 0
        });
        Object.defineProperty(this, "_eta1", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 0
        });
        Object.defineProperty(this, "_eta2", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 0
        });
        Object.defineProperty(this, "_skSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 0
        });
        Object.defineProperty(this, "_pkSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 0
        });
        Object.defineProperty(this, "_compressedUSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 0
        });
        Object.defineProperty(this, "_compressedVSize", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 0
        });
    }
    /**
     * Generates a keypair [publicKey, privateKey].
     *
     * If an error occurred, throws {@link MlKemError}.
     *
     * @returns A kaypair [publicKey, privateKey].
     * @throws {@link MlKemError}
     *
     * @example Generates a {@link MlKem768} keypair.
     *
     * ```ts
     * // Using jsr:
     * import { MlKem768 } from "@dajiaji/mlkem";
     * // Using npm:
     * // import { MlKem768 } from "mlkem"; // or "crystals-kyber-js"
     *
     * const kyber = new MlKem768();
     * const [pk, sk] = await kyber.generateKeyPair();
     * ```
     */
    async generateKeyPair() {
        await this._setup();
        try {
            const rnd = new Uint8Array(64);
            this._api.getRandomValues(rnd);
            return this._deriveKeyPair(rnd);
        }
        catch (e) {
            throw new MlKemError(e);
        }
    }
    /**
     * Derives a keypair [publicKey, privateKey] deterministically from a 64-octet seed.
     *
     * If an error occurred, throws {@link MlKemError}.
     *
     * @param seed A 64-octet seed for the deterministic key generation.
     * @returns A kaypair [publicKey, privateKey].
     * @throws {@link MlKemError}
     *
     * @example Derives a {@link MlKem768} keypair deterministically.
     *
     * ```ts
     * // Using jsr:
     * import { MlKem768 } from "@dajiaji/mlkem";
     * // Using npm:
     * // import { MlKem768 } from "mlkem"; // or "crystals-kyber-js"
     *
     * const kyber = new MlKem768();
     * const seed = new Uint8Array(64);
     * globalThis.crypto.getRandomValues(seed);
     * const [pk, sk] = await kyber.deriveKeyPair(seed);
     * ```
     */
    async deriveKeyPair(seed) {
        await this._setup();
        try {
            if (seed.byteLength !== 64) {
                throw new Error("seed must be 64 bytes in length");
            }
            return this._deriveKeyPair(seed);
        }
        catch (e) {
            throw new MlKemError(e);
        }
    }
    /**
     * Generates a shared secret from the encapsulated ciphertext and the private key.
     *
     * If an error occurred, throws {@link MlKemError}.
     *
     * @param pk A public key.
     * @param seed An optional 32-octet seed for the deterministic shared secret generation.
     * @returns A ciphertext (encapsulated public key) and a shared secret.
     * @throws {@link MlKemError}
     *
     * @example The {@link MlKem768} encapsulation.
     *
     * ```ts
     * // Using jsr:
     * import { MlKem768 } from "@dajiaji/mlkem";
     * // Using npm:
     * // import { MlKem768 } from "mlkem"; // or "crystals-kyber-js"
     *
     * const kyber = new MlKem768();
     * const [pk, sk] = await kyber.generateKeyPair();
     * const [ct, ss] = await kyber.encap(pk);
     * ```
     */
    async encap(pk, seed) {
        await this._setup();
        try {
            // validate key type; the modulo is checked in `_encap`.
            if (pk.length !== 384 * this._k + 32) {
                throw new Error("invalid encapsulation key");
            }
            const m = this._getSeed(seed);
            const [k, r] = g(m, h(pk));
            const ct = this._encap(pk, m, r);
            return [ct, k];
        }
        catch (e) {
            throw new MlKemError(e);
        }
    }
    /**
     * Generates a ciphertext for the public key and a shared secret.
     *
     * If an error occurred, throws {@link MlKemError}.
     *
     * @param ct A ciphertext generated by {@link encap}.
     * @param sk A private key.
     * @returns A shared secret.
     * @throws {@link MlKemError}
     *
     * @example The {@link MlKem768} decapsulation.
     *
     * ```ts
     * // Using jsr:
     * import { MlKem768 } from "@dajiaji/mlkem";
     * // Using npm:
     * // import { MlKem768 } from "mlkem"; // or "crystals-kyber-js"
     *
     * const kyber = new MlKem768();
     * const [pk, sk] = await kyber.generateKeyPair();
     * const [ct, ssS] = await kyber.encap(pk);
     * const ssR = await kyber.decap(ct, sk);
     * // ssS === ssR
     * ```
     */
    async decap(ct, sk) {
        await this._setup();
        try {
            // ciphertext type check
            if (ct.byteLength !== this._compressedUSize + this._compressedVSize) {
                throw new Error("Invalid ct size");
            }
            // decapsulation key type check
            if (sk.length !== 768 * this._k + 96) {
                throw new Error("Invalid decapsulation key");
            }
            const sk2 = sk.subarray(0, this._skSize);
            const pk = sk.subarray(this._skSize, this._skSize + this._pkSize);
            const hpk = sk.subarray(this._skSize + this._pkSize, this._skSize + this._pkSize + 32);
            const z = sk.subarray(this._skSize + this._pkSize + 32, this._skSize + this._pkSize + 64);
            const m2 = this._decap(ct, sk2);
            const [k2, r2] = g(m2, hpk);
            const kBar = kdf(z, ct);
            const ct2 = this._encap(pk, m2, r2);
            return constantTimeCompare(ct, ct2) === 1 ? k2 : kBar;
        }
        catch (e) {
            throw new MlKemError(e);
        }
    }
    /**
     * Sets up the MlKemBase instance by loading the necessary crypto library.
     * If the crypto library is already loaded, this method does nothing.
     * @returns {Promise<void>} A promise that resolves when the setup is complete.
     */
    async _setup() {
        if (this._api !== undefined) {
            return;
        }
        this._api = await loadCrypto();
    }
    /**
     * Returns a Uint8Array seed for cryptographic operations.
     * If no seed is provided, a random seed of length 32 bytes is generated.
     * If a seed is provided, it must be exactly 32 bytes in length.
     *
     * @param seed - Optional seed for cryptographic operations.
     * @returns A Uint8Array seed.
     * @throws Error if the provided seed is not 32 bytes in length.
     */
    _getSeed(seed) {
        if (seed == undefined) {
            const s = new Uint8Array(32);
            this._api.getRandomValues(s);
            return s;
        }
        if (seed.byteLength !== 32) {
            throw new Error("seed must be 32 bytes in length");
        }
        return seed;
    }
    /**
     * Derives a key pair from a given seed.
     *
     * @param seed - The seed used for key derivation.
     * @returns An array containing the public key and secret key.
     */
    _deriveKeyPair(seed) {
        const cpaSeed = seed.subarray(0, 32);
        const z = seed.subarray(32, 64);
        const [pk, skBody] = this._deriveCpaKeyPair(cpaSeed);
        const pkh = h(pk);
        const sk = new Uint8Array(this._skSize + this._pkSize + 64);
        sk.set(skBody, 0);
        sk.set(pk, this._skSize);
        sk.set(pkh, this._skSize + this._pkSize);
        sk.set(z, this._skSize + this._pkSize + 32);
        return [pk, sk];
    }
    // indcpaKeyGen generates public and private keys for the CPA-secure
    // public-key encryption scheme underlying ML-KEM.
    /**
     * Derives a CPA key pair using the provided CPA seed.
     *
     * @param cpaSeed - The CPA seed used for key derivation.
     * @returns An array containing the public key and private key.
     */
    _deriveCpaKeyPair(cpaSeed) {
        const [publicSeed, noiseSeed] = g(cpaSeed, new Uint8Array([this._k]));
        const a = this._sampleMatrix(publicSeed, false);
        const s = this._sampleNoise1(noiseSeed, 0, this._k);
        const e = this._sampleNoise1(noiseSeed, this._k, this._k);
        // perform number theoretic transform on secret s
        for (let i = 0; i < this._k; i++) {
            s[i] = ntt(s[i]);
            s[i] = reduce(s[i]);
            e[i] = ntt(e[i]);
        }
        // KEY COMPUTATION
        // pk = A*s + e
        const pk = new Array(this._k);
        for (let i = 0; i < this._k; i++) {
            pk[i] = polyToMont(multiply(a[i], s));
            pk[i] = mlKemBase_add(pk[i], e[i]);
            pk[i] = reduce(pk[i]);
        }
        // PUBLIC KEY
        // turn polynomials into byte arrays
        const pubKey = new Uint8Array(this._pkSize);
        for (let i = 0; i < this._k; i++) {
            pubKey.set(polyToBytes(pk[i]), i * 384);
        }
        // append public seed
        pubKey.set(publicSeed, this._skSize);
        // PRIVATE KEY
        // turn polynomials into byte arrays
        const privKey = new Uint8Array(this._skSize);
        for (let i = 0; i < this._k; i++) {
            privKey.set(polyToBytes(s[i]), i * 384);
        }
        return [pubKey, privKey];
    }
    // _encap is the encapsulation function of the CPA-secure
    // public-key encryption scheme underlying ML-KEM.
    /**
     * Encapsulates a message using the ML-KEM encryption scheme.
     *
     * @param pk - The public key.
     * @param msg - The message to be encapsulated.
     * @param seed - The seed used for generating random values.
     * @returns The encapsulated message as a Uint8Array.
     */
    _encap(pk, msg, seed) {
        const tHat = new Array(this._k);
        const pkCheck = new Uint8Array(384 * this._k); // to validate the pk modulo (see input validation at NIST draft 6.2)
        for (let i = 0; i < this._k; i++) {
            tHat[i] = polyFromBytes(pk.subarray(i * 384, (i + 1) * 384));
            pkCheck.set(polyToBytes(tHat[i]), i * 384);
        }
        if (!equalUint8Array(pk.subarray(0, pkCheck.length), pkCheck)) {
            throw new Error("invalid encapsulation key");
        }
        const rho = pk.subarray(this._skSize);
        const a = this._sampleMatrix(rho, true);
        const r = this._sampleNoise1(seed, 0, this._k);
        const e1 = this._sampleNoise2(seed, this._k, this._k);
        const e2 = this._sampleNoise2(seed, this._k * 2, 1)[0];
        // perform number theoretic transform on random vector r
        for (let i = 0; i < this._k; i++) {
            r[i] = ntt(r[i]);
            r[i] = reduce(r[i]);
        }
        // u = A*r + e1
        const u = new Array(this._k);
        for (let i = 0; i < this._k; i++) {
            u[i] = multiply(a[i], r);
            u[i] = nttInverse(u[i]);
            u[i] = mlKemBase_add(u[i], e1[i]);
            u[i] = reduce(u[i]);
        }
        // v = tHat*r + e2 + m
        const m = polyFromMsg(msg);
        let v = multiply(tHat, r);
        v = nttInverse(v);
        v = mlKemBase_add(v, e2);
        v = mlKemBase_add(v, m);
        v = reduce(v);
        // compress
        const ret = new Uint8Array(this._compressedUSize + this._compressedVSize);
        this._compressU(ret.subarray(0, this._compressedUSize), u);
        this._compressV(ret.subarray(this._compressedUSize), v);
        return ret;
    }
    // indcpaDecrypt is the decryption function of the CPA-secure
    // public-key encryption scheme underlying ML-KEM.
    /**
     * Decapsulates the ciphertext using the provided secret key.
     *
     * @param ct - The ciphertext to be decapsulated.
     * @param sk - The secret key used for decapsulation.
     * @returns The decapsulated message as a Uint8Array.
     */
    _decap(ct, sk) {
        // extract ciphertext
        const u = this._decompressU(ct.subarray(0, this._compressedUSize));
        const v = this._decompressV(ct.subarray(this._compressedUSize));
        const privateKeyPolyvec = this._polyvecFromBytes(sk);
        for (let i = 0; i < this._k; i++) {
            u[i] = ntt(u[i]);
        }
        let mp = multiply(privateKeyPolyvec, u);
        mp = nttInverse(mp);
        mp = subtract(v, mp);
        mp = reduce(mp);
        return polyToMsg(mp);
    }
    // generateMatrixA deterministically generates a matrix `A` (or the transpose of `A`)
    // from a seed. Entries of the matrix are polynomials that look uniformly random.
    // Performs rejection sampling on the output of an extendable-output function (XOF).
    /**
     * Generates a sample matrix based on the provided seed and transposition flag.
     *
     * @param seed - The seed used for generating the matrix.
     * @param transposed - A flag indicating whether the matrix should be transposed or not.
     * @returns The generated sample matrix.
     */
    _sampleMatrix(seed, transposed) {
        const a = new Array(this._k);
        const transpose = new Uint8Array(2);
        for (let ctr = 0, i = 0; i < this._k; i++) {
            a[i] = new Array(this._k);
            for (let j = 0; j < this._k; j++) {
                // set if transposed matrix or not
                if (transposed) {
                    transpose[0] = i;
                    transpose[1] = j;
                }
                else {
                    transpose[0] = j;
                    transpose[1] = i;
                }
                const output = xof(seed, transpose);
                // run rejection sampling on the output from above
                const result = indcpaRejUniform(output.subarray(0, 504), 504, N);
                a[i][j] = result[0]; // the result here is an NTT-representation
                ctr = result[1]; // keeps track of index of output array from sampling function
                while (ctr < N) { // if the polynomial hasnt been filled yet with mod q entries
                    const outputn = output.subarray(504, 672); // take last 168 bytes of byte array from xof
                    const result1 = indcpaRejUniform(outputn, 168, N - ctr); // run sampling function again
                    const missing = result1[0]; // here is additional mod q polynomial coefficients
                    const ctrn = result1[1]; // how many coefficients were accepted and are in the output
                    // starting at last position of output array from first sampling function until 256 is reached
                    for (let k = ctr; k < N; k++) {
                        a[i][j][k] = missing[k - ctr]; // fill rest of array with the additional coefficients until full
                    }
                    ctr = ctr + ctrn; // update index
                }
            }
        }
        return a;
    }
    /**
     * Generates a 2D array of noise samples.
     *
     * @param sigma - The noise parameter.
     * @param offset - The offset value.
     * @param size - The size of the array.
     * @returns The generated 2D array of noise samples.
     */
    _sampleNoise1(sigma, offset, size) {
        const r = new Array(size);
        for (let i = 0; i < size; i++) {
            r[i] = byteopsCbd(prf(this._eta1 * N / 4, sigma, offset), this._eta1);
            offset++;
        }
        return r;
    }
    /**
     * Generates a 2-dimensional array of noise samples.
     *
     * @param sigma - The noise parameter.
     * @param offset - The offset value.
     * @param size - The size of the array.
     * @returns The generated 2-dimensional array of noise samples.
     */
    _sampleNoise2(sigma, offset, size) {
        const r = new Array(size);
        for (let i = 0; i < size; i++) {
            r[i] = byteopsCbd(prf(this._eta2 * N / 4, sigma, offset), this._eta2);
            offset++;
        }
        return r;
    }
    // polyvecFromBytes deserializes a vector of polynomials.
    /**
     * Converts a Uint8Array to a 2D array of numbers representing a polynomial vector.
     * Each element in the resulting array represents a polynomial.
     * @param a The Uint8Array to convert.
     * @returns The 2D array of numbers representing the polynomial vector.
     */
    _polyvecFromBytes(a) {
        const r = new Array(this._k);
        for (let i = 0; i < this._k; i++) {
            r[i] = polyFromBytes(a.subarray(i * 384, (i + 1) * 384));
        }
        return r;
    }
    // compressU lossily compresses and serializes a vector of polynomials.
    /**
     * Compresses the given array of coefficients into a Uint8Array.
     *
     * @param r - The output Uint8Array.
     * @param u - The array of coefficients.
     * @returns The compressed Uint8Array.
     */
    _compressU(r, u) {
        const t = new Array(4);
        for (let rr = 0, i = 0; i < this._k; i++) {
            for (let j = 0; j < N / 4; j++) {
                for (let k = 0; k < 4; k++) {
                    // parse {0,...,3328} to {0,...,1023}
                    t[k] = (((u[i][4 * j + k] << 10) + Q / 2) / Q) &
                        0b1111111111;
                }
                // converts 4 12-bit coefficients {0,...,3328} to 5 8-bit bytes {0,...,255}
                // 48 bits down to 40 bits per block
                r[rr++] = utils_byte(t[0] >> 0);
                r[rr++] = utils_byte((t[0] >> 8) | (t[1] << 2));
                r[rr++] = utils_byte((t[1] >> 6) | (t[2] << 4));
                r[rr++] = utils_byte((t[2] >> 4) | (t[3] << 6));
                r[rr++] = utils_byte(t[3] >> 2);
            }
        }
        return r;
    }
    // compressV lossily compresses and subsequently serializes a polynomial.
    /**
     * Compresses the given array of numbers into a Uint8Array.
     *
     * @param r - The Uint8Array to store the compressed values.
     * @param v - The array of numbers to compress.
     * @returns The compressed Uint8Array.
     */
    _compressV(r, v) {
        // const r = new Uint8Array(128);
        const t = new Uint8Array(8);
        for (let rr = 0, i = 0; i < N / 8; i++) {
            for (let j = 0; j < 8; j++) {
                t[j] = utils_byte(((v[8 * i + j] << 4) + Q / 2) / Q) & 0b1111;
            }
            r[rr++] = t[0] | (t[1] << 4);
            r[rr++] = t[2] | (t[3] << 4);
            r[rr++] = t[4] | (t[5] << 4);
            r[rr++] = t[6] | (t[7] << 4);
        }
        return r;
    }
    // decompressU de-serializes and decompresses a vector of polynomials and
    // represents the approximate inverse of compress1. Since compression is lossy,
    // the results of decompression will may not match the original vector of polynomials.
    /**
     * Decompresses a Uint8Array into a two-dimensional array of numbers.
     *
     * @param a The Uint8Array to decompress.
     * @returns The decompressed two-dimensional array.
     */
    _decompressU(a) {
        const r = new Array(this._k);
        for (let i = 0; i < this._k; i++) {
            r[i] = new Array(384);
        }
        const t = new Array(4);
        for (let aa = 0, i = 0; i < this._k; i++) {
            for (let j = 0; j < N / 4; j++) {
                t[0] = (uint16(a[aa + 0]) >> 0) | (uint16(a[aa + 1]) << 8);
                t[1] = (uint16(a[aa + 1]) >> 2) | (uint16(a[aa + 2]) << 6);
                t[2] = (uint16(a[aa + 2]) >> 4) | (uint16(a[aa + 3]) << 4);
                t[3] = (uint16(a[aa + 3]) >> 6) | (uint16(a[aa + 4]) << 2);
                aa = aa + 5;
                for (let k = 0; k < 4; k++) {
                    r[i][4 * j + k] = int16((((uint32(t[k] & 0x3FF)) * (uint32(Q))) + 512) >> 10);
                }
            }
        }
        return r;
    }
    // decompressV de-serializes and subsequently decompresses a polynomial,
    // representing the approximate inverse of compress2.
    // Note that compression is lossy, and thus decompression will not match the
    // original input.
    /**
     * Decompresses a Uint8Array into an array of numbers.
     *
     * @param a - The Uint8Array to decompress.
     * @returns An array of numbers.
     */
    _decompressV(a) {
        const r = new Array(384);
        for (let aa = 0, i = 0; i < N / 2; i++, aa++) {
            r[2 * i + 0] = int16(((uint16(a[aa] & 15) * uint16(Q)) + 8) >> 4);
            r[2 * i + 1] = int16(((uint16(a[aa] >> 4) * uint16(Q)) + 8) >> 4);
        }
        return r;
    }
}
/**
 * Computes the hash of the input array `a` and an optional input array `b`.
 * Returns an array containing two Uint8Arrays, representing the first 32 bytes and the next 32 bytes of the hash digest.
 * @param a - The input array to be hashed.
 * @param b - An optional input array to be hashed along with `a`.
 * @returns An array containing two Uint8Arrays representing the hash digest.
 */
function g(a, b) {
    const hash = sha3_512.create().update(a);
    if (b !== undefined) {
        hash.update(b);
    }
    const res = hash.digest();
    return [res.subarray(0, 32), res.subarray(32, 64)];
}
/**
 * Computes the SHA3-256 hash of the given message.
 *
 * @param msg - The input message as a Uint8Array.
 * @returns The computed hash as a Uint8Array.
 */
function h(msg) {
    return sha3_256.create().update(msg).digest();
}
/**
 * Key Derivation Function (KDF) that takes an input array `a` and an optional input array `b`.
 * It uses the SHAKE256 hash function to derive a 32-byte output.
 *
 * @param a - The input array.
 * @param b - The optional input array.
 * @returns The derived key as a Uint8Array.
 */
function kdf(a, b) {
    const hash = shake256.create({ dkLen: 32 }).update(a);
    if (b !== undefined) {
        hash.update(b);
    }
    return hash.digest();
}
/**
 * Computes the extendable-output function (XOF) using the SHAKE128 algorithm.
 *
 * @param seed - The seed value for the XOF.
 * @param transpose - The transpose value for the XOF.
 * @returns The computed XOF value as a Uint8Array.
 */
function xof(seed, transpose) {
    return shake128.create({ dkLen: 672 }).update(seed).update(transpose)
        .digest();
}
// polyToBytes serializes a polynomial into an array of bytes.
/**
 * Converts a polynomial represented by an array of numbers to a Uint8Array.
 * Each coefficient of the polynomial is reduced modulo q.
 *
 * @param a - The array representing the polynomial.
 * @returns The Uint8Array representation of the polynomial.
 */
function polyToBytes(a) {
    let t0 = 0;
    let t1 = 0;
    const r = new Uint8Array(384);
    const a2 = subtractQ(a); // Returns: a - q if a >= q, else a (each coefficient of the polynomial)
    // for 0-127
    for (let i = 0; i < N / 2; i++) {
        // get two coefficient entries in the polynomial
        t0 = uint16(a2[2 * i]);
        t1 = uint16(a2[2 * i + 1]);
        // convert the 2 coefficient into 3 bytes
        r[3 * i + 0] = utils_byte(t0 >> 0); // byte() does mod 256 of the input (output value 0-255)
        r[3 * i + 1] = utils_byte(t0 >> 8) | utils_byte(t1 << 4);
        r[3 * i + 2] = utils_byte(t1 >> 4);
    }
    return r;
}
// polyFromBytes de-serialises an array of bytes into a polynomial,
// and represents the inverse of polyToBytes.
/**
 * Converts a Uint8Array to an array of numbers representing a polynomial.
 * Each element in the array represents a coefficient of the polynomial.
 * The input array `a` should have a length of 384.
 * The function performs bitwise operations to extract the coefficients from the input array.
 * @param a The Uint8Array to convert to a polynomial.
 * @returns An array of numbers representing the polynomial.
 */
function polyFromBytes(a) {
    const r = new Array(384).fill(0);
    for (let i = 0; i < N / 2; i++) {
        r[2 * i] = int16(((uint16(a[3 * i + 0]) >> 0) | (uint16(a[3 * i + 1]) << 8)) & 0xFFF);
        r[2 * i + 1] = int16(((uint16(a[3 * i + 1]) >> 4) | (uint16(a[3 * i + 2]) << 4)) & 0xFFF);
    }
    return r;
}
// polyToMsg converts a polynomial to a 32-byte message
// and represents the inverse of polyFromMsg.
/**
 * Converts a polynomial to a message represented as a Uint8Array.
 * @param a - The polynomial to convert.
 * @returns The message as a Uint8Array.
 */
function polyToMsg(a) {
    const msg = new Uint8Array(32);
    let t;
    const a2 = subtractQ(a);
    for (let i = 0; i < N / 8; i++) {
        msg[i] = 0;
        for (let j = 0; j < 8; j++) {
            t = (((uint16(a2[8 * i + j]) << 1) + uint16(Q / 2)) /
                uint16(Q)) & 1;
            msg[i] |= utils_byte(t << j);
        }
    }
    return msg;
}
// polyFromMsg converts a 32-byte message to a polynomial.
/**
 * Converts a Uint8Array message to an array of numbers representing a polynomial.
 * Each element in the array is an int16 (0-65535).
 *
 * @param msg - The Uint8Array message to convert.
 * @returns An array of numbers representing the polynomial.
 */
function polyFromMsg(msg) {
    const r = new Array(384).fill(0); // each element is int16 (0-65535)
    let mask; // int16
    for (let i = 0; i < N / 8; i++) {
        for (let j = 0; j < 8; j++) {
            mask = -1 * int16((msg[i] >> j) & 1);
            r[8 * i + j] = mask & int16((Q + 1) / 2);
        }
    }
    return r;
}
// indcpaRejUniform runs rejection sampling on uniform random bytes
// to generate uniform random integers modulo `Q`.
/**
 * Generates an array of random numbers from a given buffer, rejecting values greater than a specified threshold.
 *
 * @param buf - The input buffer containing random bytes.
 * @param bufl - The length of the input buffer.
 * @param len - The desired length of the output array.
 * @returns An array of random numbers and the actual length of the output array.
 */
function indcpaRejUniform(buf, bufl, len) {
    const r = new Array(384).fill(0);
    let ctr = 0;
    let val0, val1; // d1, d2 in kyber documentation
    for (let pos = 0; ctr < len && pos + 3 <= bufl;) {
        // compute d1 and d2
        val0 = (uint16((buf[pos]) >> 0) | (uint16(buf[pos + 1]) << 8)) & 0xFFF;
        val1 = (uint16((buf[pos + 1]) >> 4) | (uint16(buf[pos + 2]) << 4)) & 0xFFF;
        // increment input buffer index by 3
        pos = pos + 3;
        // if d1 is less than 3329
        if (val0 < Q) {
            // assign to d1
            r[ctr] = val0;
            // increment position of output array
            ctr = ctr + 1;
        }
        if (ctr < len && val1 < Q) {
            r[ctr] = val1;
            ctr = ctr + 1;
        }
    }
    return [r, ctr];
}
// byteopsCbd computes a polynomial with coefficients distributed
// according to a centered binomial distribution with parameter PARAMS_ETA,
// given an array of uniformly random bytes.
/**
 * Converts a Uint8Array buffer to an array of numbers using the CBD operation.
 * @param buf - The input Uint8Array buffer.
 * @param eta - The value used in the CBD operation.
 * @returns An array of numbers obtained from the CBD operation.
 */
function byteopsCbd(buf, eta) {
    let t, d;
    let a, b;
    const r = new Array(384).fill(0);
    for (let i = 0; i < N / 8; i++) {
        t = byteopsLoad32(buf.subarray(4 * i, buf.length));
        d = t & 0x55555555;
        d = d + ((t >> 1) & 0x55555555);
        for (let j = 0; j < 8; j++) {
            a = int16((d >> (4 * j + 0)) & 0x3);
            b = int16((d >> (4 * j + eta)) & 0x3);
            r[8 * i + j] = a - b;
        }
    }
    return r;
}
// ntt performs an inplace number-theoretic transform (NTT) in `Rq`.
// The input is in standard order, the output is in bit-reversed order.
/**
 * Performs the Number Theoretic Transform (NTT) on an array of numbers.
 *
 * @param r - The input array of numbers.
 * @returns The transformed array of numbers.
 */
function ntt(r) {
    // 128, 64, 32, 16, 8, 4, 2
    for (let j = 0, k = 1, l = 128; l >= 2; l >>= 1) {
        // 0,
        for (let start = 0; start < 256; start = j + l) {
            const zeta = NTT_ZETAS[k];
            k = k + 1;
            // for each element in the subsections (128, 64, 32, 16, 8, 4, 2) starting at an offset
            for (j = start; j < start + l; j++) {
                // compute the modular multiplication of the zeta and each element in the subsection
                const t = nttFqMul(zeta, r[j + l]); // t is mod q
                // overwrite each element in the subsection as the opposite subsection element minus t
                r[j + l] = r[j] - t;
                // add t back again to the opposite subsection
                r[j] = r[j] + t;
            }
        }
    }
    return r;
}
// nttFqMul performs multiplication followed by Montgomery reduction
// and returns a 16-bit integer congruent to `a*b*R^{-1} mod Q`.
/**
 * Performs an NTT (Number Theoretic Transform) multiplication on two numbers in Fq.
 * @param a The first number.
 * @param b The second number.
 * @returns The result of the NTT multiplication.
 */
function nttFqMul(a, b) {
    return byteopsMontgomeryReduce(a * b);
}
// reduce applies Barrett reduction to all coefficients of a polynomial.
/**
 * Reduces each element in the given array using the barrett function.
 *
 * @param r - The array to be reduced.
 * @returns The reduced array.
 */
function reduce(r) {
    for (let i = 0; i < N; i++) {
        r[i] = barrett(r[i]);
    }
    return r;
}
// barrett computes a Barrett reduction; given
// a integer `a`, returns a integer congruent to
// `a mod Q` in {0,...,Q}.
/**
 * Performs the Barrett reduction algorithm on the given number.
 *
 * @param a - The number to be reduced.
 * @returns The result of the reduction.
 */
function barrett(a) {
    const v = ((1 << 24) + Q / 2) / Q;
    let t = v * a >> 24;
    t = t * Q;
    return a - t;
}
// byteopsMontgomeryReduce computes a Montgomery reduction; given
// a 32-bit integer `a`, returns `a * R^-1 mod Q` where `R=2^16`.
/**
 * Performs Montgomery reduction on a given number.
 * @param a - The number to be reduced.
 * @returns The reduced number.
 */
function byteopsMontgomeryReduce(a) {
    const u = int16(int32(a) * Q_INV);
    let t = u * Q;
    t = a - t;
    t >>= 16;
    return int16(t);
}
// polyToMont performs the in-place conversion of all coefficients
// of a polynomial from the normal domain to the Montgomery domain.
/**
 * Converts a polynomial to the Montgomery domain.
 *
 * @param r - The polynomial to be converted.
 * @returns The polynomial in the Montgomery domain.
 */
function polyToMont(r) {
    // let f = int16(((uint64(1) << 32)) % uint64(Q));
    const f = 1353; // if Q changes then this needs to be updated
    for (let i = 0; i < N; i++) {
        r[i] = byteopsMontgomeryReduce(int32(r[i]) * int32(f));
    }
    return r;
}
// pointwise-multiplies elements of polynomial-vectors
// `a` and `b`, accumulates the results into `r`, and then multiplies by `2^-16`.
/**
 * Multiplies two matrices element-wise and returns the result.
 * @param a - The first matrix.
 * @param b - The second matrix.
 * @returns The resulting matrix after element-wise multiplication.
 */
function multiply(a, b) {
    let r = polyBaseMulMontgomery(a[0], b[0]);
    let t;
    for (let i = 1; i < a.length; i++) {
        t = polyBaseMulMontgomery(a[i], b[i]);
        r = mlKemBase_add(r, t);
    }
    return reduce(r);
}
// polyBaseMulMontgomery performs the multiplication of two polynomials
// in the number-theoretic transform (NTT) domain.
/**
 * Performs polynomial base multiplication in Montgomery domain.
 * @param a - The first polynomial array.
 * @param b - The second polynomial array.
 * @returns The result of the polynomial base multiplication.
 */
function polyBaseMulMontgomery(a, b) {
    let rx, ry;
    for (let i = 0; i < N / 4; i++) {
        rx = nttBaseMul(a[4 * i + 0], a[4 * i + 1], b[4 * i + 0], b[4 * i + 1], NTT_ZETAS[64 + i]);
        ry = nttBaseMul(a[4 * i + 2], a[4 * i + 3], b[4 * i + 2], b[4 * i + 3], -NTT_ZETAS[64 + i]);
        a[4 * i + 0] = rx[0];
        a[4 * i + 1] = rx[1];
        a[4 * i + 2] = ry[0];
        a[4 * i + 3] = ry[1];
    }
    return a;
}
// nttBaseMul performs the multiplication of polynomials
// in `Zq[X]/(X^2-zeta)`. Used for multiplication of elements
// in `Rq` in the number-theoretic transformation domain.
/**
 * Performs NTT base multiplication.
 *
 * @param a0 - The first coefficient of the first polynomial.
 * @param a1 - The second coefficient of the first polynomial.
 * @param b0 - The first coefficient of the second polynomial.
 * @param b1 - The second coefficient of the second polynomial.
 * @param zeta - The zeta value used in the multiplication.
 * @returns An array containing the result of the multiplication.
 */
function nttBaseMul(a0, a1, b0, b1, zeta) {
    const r = new Array(2);
    r[0] = nttFqMul(a1, b1);
    r[0] = nttFqMul(r[0], zeta);
    r[0] += nttFqMul(a0, b0);
    r[1] = nttFqMul(a0, b1);
    r[1] += nttFqMul(a1, b0);
    return r;
}
// adds two polynomials.
/**
 * Adds two arrays element-wise.
 * @param a - The first array.
 * @param b - The second array.
 * @returns The resulting array after element-wise addition.
 */
function mlKemBase_add(a, b) {
    const c = new Array(384);
    for (let i = 0; i < N; i++) {
        c[i] = a[i] + b[i];
    }
    return c;
}
// subtracts two polynomials.
/**
 * Subtracts the elements of array b from array a.
 *
 * @param a - The array from which to subtract.
 * @param b - The array to subtract.
 * @returns The resulting array after subtraction.
 */
function subtract(a, b) {
    for (let i = 0; i < N; i++) {
        a[i] -= b[i];
    }
    return a;
}
// nttInverse performs an inplace inverse number-theoretic transform (NTT)
// in `Rq` and multiplication by Montgomery factor 2^16.
// The input is in bit-reversed order, the output is in standard order.
/**
 * Performs the inverse Number Theoretic Transform (NTT) on the given array.
 *
 * @param r - The input array to perform the inverse NTT on.
 * @returns The array after performing the inverse NTT.
 */
function nttInverse(r) {
    let j = 0;
    for (let k = 0, l = 2; l <= 128; l <<= 1) {
        for (let start = 0; start < 256; start = j + l) {
            const zeta = NTT_ZETAS_INV[k];
            k = k + 1;
            for (j = start; j < start + l; j++) {
                const t = r[j];
                r[j] = barrett(t + r[j + l]);
                r[j + l] = t - r[j + l];
                r[j + l] = nttFqMul(zeta, r[j + l]);
            }
        }
    }
    for (j = 0; j < 256; j++) {
        r[j] = nttFqMul(r[j], NTT_ZETAS_INV[127]);
    }
    return r;
}
// subtractQ applies the conditional subtraction of q to each coefficient of a polynomial.
// if a is 3329 then convert to 0
// Returns:     a - q if a >= q, else a
/**
 * Subtracts the value of Q from each element in the given array.
 * The result should be a negative integer for each element.
 * If the leftmost bit is 0 (positive number), the value of Q is added back.
 *
 * @param r - The array to subtract Q from.
 * @returns The resulting array after the subtraction.
 */
function subtractQ(r) {
    for (let i = 0; i < N; i++) {
        r[i] -= Q; // should result in a negative integer
        // push left most signed bit to right most position
        // javascript does bitwise operations in signed 32 bit
        // add q back again if left most bit was 0 (positive number)
        r[i] += (r[i] >> 31) & Q;
    }
    return r;
}

;// ./node_modules/crystals-kyber-js/esm/src/mlKem512.js
/**
 * This implementation is based on https://github.com/antontutoveanu/crystals-kyber-javascript,
 * which was deveploped under the MIT licence below:
 * https://github.com/antontutoveanu/crystals-kyber-javascript/blob/main/LICENSE
 */



/**
 * Represents the MlKem512 class.
 *
 * This class extends the MlKemBase class and provides specific implementation for MlKem512.
 *
 * @remarks
 *
 * MlKem512 is a specific implementation of the ML-KEM key encapsulation mechanism.
 *
 * @example
 *
 * ```ts
 * // Using jsr:
 * import { MlKem512 } from "@dajiaji/mlkem";
 * // Using npm:
 * // import { MlKem512 } from "mlkem"; // or "crystals-kyber-js"
 *
 * const recipient = new MlKem512();
 * const [pkR, skR] = await recipient.generateKeyPair();
 *
 * const sender = new MlKem512();
 * const [ct, ssS] = await sender.encap(pkR);
 *
 * const ssR = await recipient.decap(ct, skR);
 * // ssS === ssR
 * ```
 */
class MlKem512 extends MlKemBase {
    /**
     * Constructs a new instance of the MlKem512 class.
     */
    constructor() {
        super();
        Object.defineProperty(this, "_k", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 2
        });
        Object.defineProperty(this, "_du", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 10
        });
        Object.defineProperty(this, "_dv", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 4
        });
        Object.defineProperty(this, "_eta1", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 3
        });
        Object.defineProperty(this, "_eta2", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 2
        });
        this._skSize = 12 * this._k * N / 8;
        this._pkSize = this._skSize + 32;
        this._compressedUSize = this._k * this._du * N / 8;
        this._compressedVSize = this._dv * N / 8;
    }
    /**
     * Samples a vector of polynomials from a seed.
     * @internal
     * @param sigma - The seed.
     * @param offset - The offset.
     * @param size - The size.
     * @returns The sampled vector of polynomials.
     */
    _sampleNoise1(sigma, offset, size) {
        const r = new Array(size);
        for (let i = 0; i < size; i++) {
            r[i] = mlKem512_byteopsCbd(prf(this._eta1 * N / 4, sigma, offset), this._eta1);
            offset++;
        }
        return r;
    }
}
/**
 * Performs the byte operations for the Cbd function.
 *
 * @param buf - The input buffer.
 * @param eta - The value of eta.
 * @returns An array of numbers representing the result of the byte operations.
 */
function mlKem512_byteopsCbd(buf, eta) {
    let t, d;
    let a, b;
    const r = new Array(384).fill(0);
    for (let i = 0; i < N / 4; i++) {
        t = byteopsLoad24(buf.subarray(3 * i, buf.length));
        d = t & 0x00249249;
        d = d + ((t >> 1) & 0x00249249);
        d = d + ((t >> 2) & 0x00249249);
        for (let j = 0; j < 4; j++) {
            a = int16((d >> (6 * j + 0)) & 0x7);
            b = int16((d >> (6 * j + eta)) & 0x7);
            r[4 * i + j] = a - b;
        }
    }
    return r;
}

;// ./node_modules/crystals-kyber-js/esm/src/mlKem768.js
/**
 * This implementation is based on https://github.com/antontutoveanu/crystals-kyber-javascript,
 * which was deveploped under the MIT licence below:
 * https://github.com/antontutoveanu/crystals-kyber-javascript/blob/main/LICENSE
 */


/**
 * Represents the MlKem768 class, which extends the MlKemBase class.
 *
 * This class extends the MlKemBase class and provides specific implementation for MlKem768.
 *
 * @remarks
 *
 * MlKem768 is a specific implementation of the ML-KEM key encapsulation mechanism.
 *
 * @example
 *
 * ```ts
 * // Using jsr:
 * import { MlKem768 } from "@dajiaji/mlkem";
 * // Using npm:
 * // import { MlKem768 } from "mlkem"; // or "crystals-kyber-js"
 *
 * const recipient = new MlKem768();
 * const [pkR, skR] = await recipient.generateKeyPair();
 *
 * const sender = new MlKem768();
 * const [ct, ssS] = await sender.encap(pkR);
 *
 * const ssR = await recipient.decap(ct, skR);
 * // ssS === ssR
 * ```
 */
class MlKem768 extends MlKemBase {
    constructor() {
        super();
        Object.defineProperty(this, "_k", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 3
        });
        Object.defineProperty(this, "_du", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 10
        });
        Object.defineProperty(this, "_dv", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 4
        });
        Object.defineProperty(this, "_eta1", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 2
        });
        Object.defineProperty(this, "_eta2", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 2
        });
        this._skSize = 12 * this._k * N / 8;
        this._pkSize = this._skSize + 32;
        this._compressedUSize = this._k * this._du * N / 8;
        this._compressedVSize = this._dv * N / 8;
    }
}

;// ./node_modules/crystals-kyber-js/esm/src/mlKem1024.js
/**
 * This implementation is based on https://github.com/antontutoveanu/crystals-kyber-javascript,
 * which was deveploped under the MIT licence below:
 * https://github.com/antontutoveanu/crystals-kyber-javascript/blob/main/LICENSE
 */



/**
 * Represents the MlKem1024 class, which extends the MlKemBase class.
 *
 * This class extends the MlKemBase class and provides specific implementation for MlKem1024.
 *
 * @remarks
 *
 * MlKem1024 is a specific implementation of the ML-KEM key encapsulation mechanism.
 *
 * @example
 *
 * ```ts
 * // Using jsr:
 * import { MlKem1024 } from "@dajiaji/mlkem";
 * // Using npm:
 * // import { MlKem1024 } from "mlkem"; // or "crystals-kyber-js"
 *
 * const recipient = new MlKem1024();
 * const [pkR, skR] = await recipient.generateKeyPair();
 *
 * const sender = new MlKem1024();
 * const [ct, ssS] = await sender.encap(pkR);
 *
 * const ssR = await recipient.decap(ct, skR);
 * // ssS === ssR
 * ```
 */
class MlKem1024 extends MlKemBase {
    /**
     * Constructs a new instance of the MlKem1024 class.
     */
    constructor() {
        super();
        Object.defineProperty(this, "_k", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 4
        });
        Object.defineProperty(this, "_du", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 11
        });
        Object.defineProperty(this, "_dv", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 5
        });
        Object.defineProperty(this, "_eta1", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 2
        });
        Object.defineProperty(this, "_eta2", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: 2
        });
        this._skSize = 12 * this._k * N / 8;
        this._pkSize = this._skSize + 32;
        this._compressedUSize = this._k * this._du * N / 8;
        this._compressedVSize = this._dv * N / 8;
    }
    // compressU lossily compresses and serializes a vector of polynomials.
    /**
     * Lossily compresses and serializes a vector of polynomials.
     *
     * @param u - The vector of polynomials to compress.
     * @returns The compressed and serialized data as a Uint8Array.
     */
    _compressU(r, u) {
        const t = new Array(8);
        for (let rr = 0, i = 0; i < this._k; i++) {
            for (let j = 0; j < N / 8; j++) {
                for (let k = 0; k < 8; k++) {
                    t[k] = uint16((((uint32(u[i][8 * j + k]) << 11) + uint32(Q / 2)) /
                        uint32(Q)) & 0x7ff);
                }
                r[rr++] = utils_byte(t[0] >> 0);
                r[rr++] = utils_byte((t[0] >> 8) | (t[1] << 3));
                r[rr++] = utils_byte((t[1] >> 5) | (t[2] << 6));
                r[rr++] = utils_byte(t[2] >> 2);
                r[rr++] = utils_byte((t[2] >> 10) | (t[3] << 1));
                r[rr++] = utils_byte((t[3] >> 7) | (t[4] << 4));
                r[rr++] = utils_byte((t[4] >> 4) | (t[5] << 7));
                r[rr++] = utils_byte(t[5] >> 1);
                r[rr++] = utils_byte((t[5] >> 9) | (t[6] << 2));
                r[rr++] = utils_byte((t[6] >> 6) | (t[7] << 5));
                r[rr++] = utils_byte(t[7] >> 3);
            }
        }
        return r;
    }
    // compressV lossily compresses and subsequently serializes a polynomial.
    /**
     * Lossily compresses and serializes a polynomial.
     *
     * @param r - The output buffer to store the compressed data.
     * @param v - The polynomial to compress.
     * @returns The compressed and serialized data as a Uint8Array.
     */
    _compressV(r, v) {
        const t = new Uint8Array(8);
        for (let rr = 0, i = 0; i < N / 8; i++) {
            for (let j = 0; j < 8; j++) {
                t[j] = utils_byte(((uint32(v[8 * i + j]) << 5) + uint32(Q / 2)) / uint32(Q)) & 31;
            }
            r[rr++] = utils_byte((t[0] >> 0) | (t[1] << 5));
            r[rr++] = utils_byte((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
            r[rr++] = utils_byte((t[3] >> 1) | (t[4] << 4));
            r[rr++] = utils_byte((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
            r[rr++] = utils_byte((t[6] >> 2) | (t[7] << 3));
        }
        return r;
    }
    // decompressU de-serializes and decompresses a vector of polynomials and
    // represents the approximate inverse of compress1. Since compression is lossy,
    // the results of decompression will may not match the original vector of polynomials.
    /**
     * Deserializes and decompresses a vector of polynomials.
     * This is the approximate inverse of the `_compressU` method.
     * Since compression is lossy, the decompressed data may not match the original vector of polynomials.
     *
     * @param a - The compressed and serialized data as a Uint8Array.
     * @returns The decompressed vector of polynomials.
     */
    _decompressU(a) {
        const r = new Array(this._k);
        for (let i = 0; i < this._k; i++) {
            r[i] = new Array(384);
        }
        const t = new Array(8);
        for (let aa = 0, i = 0; i < this._k; i++) {
            for (let j = 0; j < N / 8; j++) {
                t[0] = (uint16(a[aa + 0]) >> 0) | (uint16(a[aa + 1]) << 8);
                t[1] = (uint16(a[aa + 1]) >> 3) | (uint16(a[aa + 2]) << 5);
                t[2] = (uint16(a[aa + 2]) >> 6) | (uint16(a[aa + 3]) << 2) |
                    (uint16(a[aa + 4]) << 10);
                t[3] = (uint16(a[aa + 4]) >> 1) | (uint16(a[aa + 5]) << 7);
                t[4] = (uint16(a[aa + 5]) >> 4) | (uint16(a[aa + 6]) << 4);
                t[5] = (uint16(a[aa + 6]) >> 7) | (uint16(a[aa + 7]) << 1) |
                    (uint16(a[aa + 8]) << 9);
                t[6] = (uint16(a[aa + 8]) >> 2) | (uint16(a[aa + 9]) << 6);
                t[7] = (uint16(a[aa + 9]) >> 5) | (uint16(a[aa + 10]) << 3);
                aa = aa + 11;
                for (let k = 0; k < 8; k++) {
                    r[i][8 * j + k] = (uint32(t[k] & 0x7FF) * Q + 1024) >> 11;
                }
            }
        }
        return r;
    }
    // decompressV de-serializes and subsequently decompresses a polynomial,
    // representing the approximate inverse of compress2.
    // Note that compression is lossy, and thus decompression will not match the
    // original input.
    /**
     * Decompresses a given polynomial, representing the approximate inverse of
     * compress2, in Uint8Array into an array of numbers.
     *
     * Note that compression is lossy, and thus decompression will not match the
     * original input.
     *
     * @param a - The Uint8Array to decompress.
     * @returns An array of numbers obtained from the decompression process.
     */
    _decompressV(a) {
        const r = new Array(384);
        const t = new Array(8);
        for (let aa = 0, i = 0; i < N / 8; i++) {
            t[0] = a[aa + 0] >> 0;
            t[1] = (a[aa + 0] >> 5) | (a[aa + 1] << 3);
            t[2] = a[aa + 1] >> 2;
            t[3] = (a[aa + 1] >> 7) | (a[aa + 2] << 1);
            t[4] = (a[aa + 2] >> 4) | (a[aa + 3] << 4);
            t[5] = a[aa + 3] >> 1;
            t[6] = (a[aa + 3] >> 6) | (a[aa + 4] << 2);
            t[7] = a[aa + 4] >> 3;
            aa = aa + 5;
            for (let j = 0; j < 8; j++) {
                r[8 * i + j] = int16(((uint32(t[j] & 31) * uint32(Q)) + 16) >> 5);
            }
        }
        return r;
    }
}

;// ./node_modules/crystals-kyber-js/esm/mod.js






;// ./node_modules/base64-arraybuffer/dist/base64-arraybuffer.es5.js
/*
 * base64-arraybuffer 1.0.2 <https://github.com/niklasvh/base64-arraybuffer>
 * Copyright (c) 2022 Niklas von Hertzen <https://hertzen.com>
 * Released under MIT License
 */
var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
// Use a lookup table to find the index.
var lookup = typeof Uint8Array === 'undefined' ? [] : new Uint8Array(256);
for (var i = 0; i < chars.length; i++) {
    lookup[chars.charCodeAt(i)] = i;
}
var encode = function (arraybuffer) {
    var bytes = new Uint8Array(arraybuffer), i, len = bytes.length, base64 = '';
    for (i = 0; i < len; i += 3) {
        base64 += chars[bytes[i] >> 2];
        base64 += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
        base64 += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
        base64 += chars[bytes[i + 2] & 63];
    }
    if (len % 3 === 2) {
        base64 = base64.substring(0, base64.length - 1) + '=';
    }
    else if (len % 3 === 1) {
        base64 = base64.substring(0, base64.length - 2) + '==';
    }
    return base64;
};
var decode = function (base64) {
    var bufferLength = base64.length * 0.75, len = base64.length, i, p = 0, encoded1, encoded2, encoded3, encoded4;
    if (base64[base64.length - 1] === '=') {
        bufferLength--;
        if (base64[base64.length - 2] === '=') {
            bufferLength--;
        }
    }
    var arraybuffer = new ArrayBuffer(bufferLength), bytes = new Uint8Array(arraybuffer);
    for (i = 0; i < len; i += 4) {
        encoded1 = lookup[base64.charCodeAt(i)];
        encoded2 = lookup[base64.charCodeAt(i + 1)];
        encoded3 = lookup[base64.charCodeAt(i + 2)];
        encoded4 = lookup[base64.charCodeAt(i + 3)];
        bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
        bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
        bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
    }
    return arraybuffer;
};


//# sourceMappingURL=base64-arraybuffer.es5.js.map

// EXTERNAL MODULE: ./node_modules/js-chacha20/src/jschacha20.js
var jschacha20 = __webpack_require__(4329);
var jschacha20_default = /*#__PURE__*/__webpack_require__.n(jschacha20);
;// ./node_modules/@noble/ciphers/utils.js
/**
 * Utilities for hex, bytes, CSPRNG.
 * @module
 */
/*! noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com) */
/** Checks if something is Uint8Array. Be careful: nodejs Buffer will return true. */
function utils_isBytes(a) {
    return a instanceof Uint8Array || (ArrayBuffer.isView(a) && a.constructor.name === 'Uint8Array');
}
/** Asserts something is boolean. */
function abool(b) {
    if (typeof b !== 'boolean')
        throw new Error(`boolean expected, not ${b}`);
}
/** Asserts something is positive integer. */
function ciphers_utils_anumber(n) {
    if (!Number.isSafeInteger(n) || n < 0)
        throw new Error('positive integer expected, got ' + n);
}
/** Asserts something is Uint8Array. */
function ciphers_utils_abytes(value, length, title = '') {
    const bytes = utils_isBytes(value);
    const len = value?.length;
    const needsLen = length !== undefined;
    if (!bytes || (needsLen && len !== length)) {
        const prefix = title && `"${title}" `;
        const ofLen = needsLen ? ` of length ${length}` : '';
        const got = bytes ? `length=${len}` : `type=${typeof value}`;
        throw new Error(prefix + 'expected Uint8Array' + ofLen + ', got ' + got);
    }
    return value;
}
/** Asserts a hash instance has not been destroyed / finished */
function utils_aexists(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
/** Asserts output is properly-sized byte array */
function utils_aoutput(out, instance) {
    ciphers_utils_abytes(out, undefined, 'output');
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error('digestInto() expects output buffer of length at least ' + min);
    }
}
/** Cast u8 / u16 / u32 to u8. */
function u8(arr) {
    return new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
}
/** Cast u8 / u16 / u32 to u32. */
function utils_u32(arr) {
    return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
/** Zeroize a byte array. Warning: JS provides no guarantees. */
function utils_clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
        arrays[i].fill(0);
    }
}
/** Create DataView of an array for easy byte-level manipulation. */
function createView(arr) {
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
/** Is current platform little-endian? Most are. Big-Endian platform: IBM */
const utils_isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44)();
// Built-in hex conversion https://caniuse.com/mdn-javascript_builtins_uint8array_fromhex
const utils_hasHexBuiltin = /* @__PURE__ */ (/* unused pure expression or super */ null && ((() => 
// @ts-ignore
typeof Uint8Array.from([]).toHex === 'function' && typeof Uint8Array.fromHex === 'function')()));
// Array where index 0xf0 (240) is mapped to string 'f0'
const hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'));
/**
 * Convert byte array to hex string. Uses built-in function, when available.
 * @example bytesToHex(Uint8Array.from([0xca, 0xfe, 0x01, 0x23])) // 'cafe0123'
 */
function utils_bytesToHex(bytes) {
    ciphers_utils_abytes(bytes);
    // @ts-ignore
    if (utils_hasHexBuiltin)
        return bytes.toHex();
    // pre-caching improves the speed 6x
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
        hex += hexes[bytes[i]];
    }
    return hex;
}
// We use optimized technique to convert hex string to byte array
const utils_asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
function utils_asciiToBase16(ch) {
    if (ch >= utils_asciis._0 && ch <= utils_asciis._9)
        return ch - utils_asciis._0; // '2' => 50-48
    if (ch >= utils_asciis.A && ch <= utils_asciis.F)
        return ch - (utils_asciis.A - 10); // 'B' => 66-(65-10)
    if (ch >= utils_asciis.a && ch <= utils_asciis.f)
        return ch - (utils_asciis.a - 10); // 'b' => 98-(97-10)
    return;
}
/**
 * Convert hex string to byte array. Uses built-in function, when available.
 * @example hexToBytes('cafe0123') // Uint8Array.from([0xca, 0xfe, 0x01, 0x23])
 */
function utils_hexToBytes(hex) {
    if (typeof hex !== 'string')
        throw new Error('hex string expected, got ' + typeof hex);
    // @ts-ignore
    if (utils_hasHexBuiltin)
        return Uint8Array.fromHex(hex);
    const hl = hex.length;
    const al = hl / 2;
    if (hl % 2)
        throw new Error('hex string expected, got unpadded hex of length ' + hl);
    const array = new Uint8Array(al);
    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
        const n1 = utils_asciiToBase16(hex.charCodeAt(hi));
        const n2 = utils_asciiToBase16(hex.charCodeAt(hi + 1));
        if (n1 === undefined || n2 === undefined) {
            const char = hex[hi] + hex[hi + 1];
            throw new Error('hex string expected, got non-hex character "' + char + '" at index ' + hi);
        }
        array[ai] = n1 * 16 + n2; // multiply first octet, e.g. 'a3' => 10*16+3 => 160 + 3 => 163
    }
    return array;
}
// Used in micro
function utils_hexToNumber(hex) {
    if (typeof hex !== 'string')
        throw new Error('hex string expected, got ' + typeof hex);
    return BigInt(hex === '' ? '0' : '0x' + hex); // Big Endian
}
// Used in ff1
// BE: Big Endian, LE: Little Endian
function bytesToNumberBE(bytes) {
    return utils_hexToNumber(utils_bytesToHex(bytes));
}
// Used in micro, ff1
function utils_numberToBytesBE(n, len) {
    return utils_hexToBytes(n.toString(16).padStart(len * 2, '0'));
}
/**
 * Converts string to bytes using UTF8 encoding.
 * @example utf8ToBytes('abc') // new Uint8Array([97, 98, 99])
 */
function utils_utf8ToBytes(str) {
    if (typeof str !== 'string')
        throw new Error('string expected');
    return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
}
/**
 * Converts bytes to string using UTF8 encoding.
 * @example bytesToUtf8(new Uint8Array([97, 98, 99])) // 'abc'
 */
function utils_bytesToUtf8(bytes) {
    return new TextDecoder().decode(bytes);
}
/**
 * Checks if two U8A use same underlying buffer and overlaps.
 * This is invalid and can corrupt data.
 */
function overlapBytes(a, b) {
    return (a.buffer === b.buffer && // best we can do, may fail with an obscure Proxy
        a.byteOffset < b.byteOffset + b.byteLength && // a starts before b end
        b.byteOffset < a.byteOffset + a.byteLength // b starts before a end
    );
}
/**
 * If input and output overlap and input starts before output, we will overwrite end of input before
 * we start processing it, so this is not supported for most ciphers (except chacha/salse, which designed with this)
 */
function complexOverlapBytes(input, output) {
    // This is very cursed. It works somehow, but I'm completely unsure,
    // reasoning about overlapping aligned windows is very hard.
    if (overlapBytes(input, output) && input.byteOffset < output.byteOffset)
        throw new Error('complex overlap of input and output is not supported');
}
/**
 * Copies several Uint8Arrays into one.
 */
function ciphers_utils_concatBytes(...arrays) {
    let sum = 0;
    for (let i = 0; i < arrays.length; i++) {
        const a = arrays[i];
        ciphers_utils_abytes(a);
        sum += a.length;
    }
    const res = new Uint8Array(sum);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
        const a = arrays[i];
        res.set(a, pad);
        pad += a.length;
    }
    return res;
}
function checkOpts(defaults, opts) {
    if (opts == null || typeof opts !== 'object')
        throw new Error('options must be defined');
    const merged = Object.assign(defaults, opts);
    return merged;
}
/** Compares 2 uint8array-s in kinda constant time. */
function equalBytes(a, b) {
    if (a.length !== b.length)
        return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++)
        diff |= a[i] ^ b[i];
    return diff === 0;
}
/**
 * Wraps a cipher: validates args, ensures encrypt() can only be called once.
 * @__NO_SIDE_EFFECTS__
 */
const wrapCipher = (params, constructor) => {
    function wrappedCipher(key, ...args) {
        // Validate key
        ciphers_utils_abytes(key, undefined, 'key');
        // Big-Endian hardware is rare. Just in case someone still decides to run ciphers:
        if (!utils_isLE)
            throw new Error('Non little-endian hardware is not yet supported');
        // Validate nonce if nonceLength is present
        if (params.nonceLength !== undefined) {
            const nonce = args[0];
            ciphers_utils_abytes(nonce, params.varSizeNonce ? undefined : params.nonceLength, 'nonce');
        }
        // Validate AAD if tagLength present
        const tagl = params.tagLength;
        if (tagl && args[1] !== undefined)
            ciphers_utils_abytes(args[1], undefined, 'AAD');
        const cipher = constructor(key, ...args);
        const checkOutput = (fnLength, output) => {
            if (output !== undefined) {
                if (fnLength !== 2)
                    throw new Error('cipher output not supported');
                ciphers_utils_abytes(output, undefined, 'output');
            }
        };
        // Create wrapped cipher with validation and single-use encryption
        let called = false;
        const wrCipher = {
            encrypt(data, output) {
                if (called)
                    throw new Error('cannot encrypt() twice with same key + nonce');
                called = true;
                ciphers_utils_abytes(data);
                checkOutput(cipher.encrypt.length, output);
                return cipher.encrypt(data, output);
            },
            decrypt(data, output) {
                ciphers_utils_abytes(data);
                if (tagl && data.length < tagl)
                    throw new Error('"ciphertext" expected length bigger than tagLength=' + tagl);
                checkOutput(cipher.decrypt.length, output);
                return cipher.decrypt(data, output);
            },
        };
        return wrCipher;
    }
    Object.assign(wrappedCipher, params);
    return wrappedCipher;
};
/**
 * By default, returns u8a of length.
 * When out is available, it checks it for validity and uses it.
 */
function getOutput(expectedLength, out, onlyAligned = true) {
    if (out === undefined)
        return new Uint8Array(expectedLength);
    if (out.length !== expectedLength)
        throw new Error('"output" expected Uint8Array of length ' + expectedLength + ', got: ' + out.length);
    if (onlyAligned && !isAligned32(out))
        throw new Error('invalid output, must be aligned');
    return out;
}
function u64Lengths(dataLength, aadLength, isLE) {
    abool(isLE);
    const num = new Uint8Array(16);
    const view = createView(num);
    view.setBigUint64(0, BigInt(aadLength), isLE);
    view.setBigUint64(8, BigInt(dataLength), isLE);
    return num;
}
// Is byte array aligned to 4 byte offset (u32)?
function isAligned32(bytes) {
    return bytes.byteOffset % 4 === 0;
}
// copy bytes to new u8a (aligned). Because Buffer.slice is broken.
function copyBytes(bytes) {
    return Uint8Array.from(bytes);
}
/** Cryptographically secure PRNG. Uses internal OS-level `crypto.getRandomValues`. */
function utils_randomBytes(bytesLength = 32) {
    const cr = typeof globalThis === 'object' ? globalThis.crypto : null;
    if (typeof cr?.getRandomValues !== 'function')
        throw new Error('crypto.getRandomValues must be defined');
    return cr.getRandomValues(new Uint8Array(bytesLength));
}
/**
 * Uses CSPRG for nonce, nonce injected in ciphertext.
 * For `encrypt`, a `nonceBytes`-length buffer is fetched from CSPRNG and
 * prepended to encrypted ciphertext. For `decrypt`, first `nonceBytes` of ciphertext
 * are treated as nonce.
 *
 * NOTE: Under the same key, using random nonces (e.g. `managedNonce`) with AES-GCM and ChaCha
 * should be limited to `2**23` (8M) messages to get a collision chance of `2**-50`. Stretching to  * `2**32` (4B) messages, chance would become `2**-33` - still negligible, but creeping up.
 * @example
 * const gcm = managedNonce(aes.gcm);
 * const ciphr = gcm(key).encrypt(data);
 * const plain = gcm(key).decrypt(ciph);
 */
function managedNonce(fn, randomBytes_ = utils_randomBytes) {
    const { nonceLength } = fn;
    ciphers_utils_anumber(nonceLength);
    const addNonce = (nonce, ciphertext) => {
        const out = ciphers_utils_concatBytes(nonce, ciphertext);
        ciphertext.fill(0);
        return out;
    };
    // NOTE: we cannot support DST here, it would be mistake:
    // - we don't know how much dst length cipher requires
    // - nonce may unalign dst and break everything
    // - we create new u8a anyway (concatBytes)
    // - previously we passed all args to cipher, but that was mistake!
    return ((key, ...args) => ({
        encrypt(plaintext) {
            ciphers_utils_abytes(plaintext);
            const nonce = randomBytes_(nonceLength);
            const encrypted = fn(key, nonce, ...args).encrypt(plaintext);
            // @ts-ignore
            if (encrypted instanceof Promise)
                return encrypted.then((ct) => addNonce(nonce, ct));
            return addNonce(nonce, encrypted);
        },
        decrypt(ciphertext) {
            ciphers_utils_abytes(ciphertext);
            const nonce = ciphertext.subarray(0, nonceLength);
            const decrypted = ciphertext.subarray(nonceLength);
            return fn(key, nonce, ...args).decrypt(decrypted);
        },
    }));
}
//# sourceMappingURL=utils.js.map
;// ./node_modules/@noble/ciphers/_arx.js
/**
 * Basic utils for ARX (add-rotate-xor) salsa and chacha ciphers.

RFC8439 requires multi-step cipher stream, where
authKey starts with counter: 0, actual msg with counter: 1.

For this, we need a way to re-use nonce / counter:

    const counter = new Uint8Array(4);
    chacha(..., counter, ...); // counter is now 1
    chacha(..., counter, ...); // counter is now 2

This is complicated:

- 32-bit counters are enough, no need for 64-bit: max ArrayBuffer size in JS is 4GB
- Original papers don't allow mutating counters
- Counter overflow is undefined [^1]
- Idea A: allow providing (nonce | counter) instead of just nonce, re-use it
- Caveat: Cannot be re-used through all cases:
- * chacha has (counter | nonce)
- * xchacha has (nonce16 | counter | nonce16)
- Idea B: separate nonce / counter and provide separate API for counter re-use
- Caveat: there are different counter sizes depending on an algorithm.
- salsa & chacha also differ in structures of key & sigma:
  salsa20:      s[0] | k(4) | s[1] | nonce(2) | cnt(2) | s[2] | k(4) | s[3]
  chacha:       s(4) | k(8) | cnt(1) | nonce(3)
  chacha20orig: s(4) | k(8) | cnt(2) | nonce(2)
- Idea C: helper method such as `setSalsaState(key, nonce, sigma, data)`
- Caveat: we can't re-use counter array

xchacha [^2] uses the subkey and remaining 8 byte nonce with ChaCha20 as normal
(prefixed by 4 NUL bytes, since [RFC8439] specifies a 12-byte nonce).

[^1]: https://mailarchive.ietf.org/arch/msg/cfrg/gsOnTJzcbgG6OqD8Sc0GO5aR_tU/
[^2]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#appendix-A.2

 * @module
 */

// Replaces `TextEncoder`, which is not available in all environments
const encodeStr = (str) => Uint8Array.from(str.split(''), (c) => c.charCodeAt(0));
const sigma16 = encodeStr('expand 16-byte k');
const sigma32 = encodeStr('expand 32-byte k');
const sigma16_32 = utils_u32(sigma16);
const sigma32_32 = utils_u32(sigma32);
/** Rotate left. */
function _arx_rotl(a, b) {
    return (a << b) | (a >>> (32 - b));
}
// Is byte array aligned to 4 byte offset (u32)?
function _arx_isAligned32(b) {
    return b.byteOffset % 4 === 0;
}
// Salsa and Chacha block length is always 512-bit
const BLOCK_LEN = 64;
const BLOCK_LEN32 = 16;
// new Uint32Array([2**32])   // => Uint32Array(1) [ 0 ]
// new Uint32Array([2**32-1]) // => Uint32Array(1) [ 4294967295 ]
const MAX_COUNTER = 2 ** 32 - 1;
const U32_EMPTY = Uint32Array.of();
function runCipher(core, sigma, key, nonce, data, output, counter, rounds) {
    const len = data.length;
    const block = new Uint8Array(BLOCK_LEN);
    const b32 = utils_u32(block);
    // Make sure that buffers aligned to 4 bytes
    const isAligned = _arx_isAligned32(data) && _arx_isAligned32(output);
    const d32 = isAligned ? utils_u32(data) : U32_EMPTY;
    const o32 = isAligned ? utils_u32(output) : U32_EMPTY;
    for (let pos = 0; pos < len; counter++) {
        core(sigma, key, nonce, b32, counter, rounds);
        if (counter >= MAX_COUNTER)
            throw new Error('arx: counter overflow');
        const take = Math.min(BLOCK_LEN, len - pos);
        // aligned to 4 bytes
        if (isAligned && take === BLOCK_LEN) {
            const pos32 = pos / 4;
            if (pos % 4 !== 0)
                throw new Error('arx: invalid block position');
            for (let j = 0, posj; j < BLOCK_LEN32; j++) {
                posj = pos32 + j;
                o32[posj] = d32[posj] ^ b32[j];
            }
            pos += BLOCK_LEN;
            continue;
        }
        for (let j = 0, posj; j < take; j++) {
            posj = pos + j;
            output[posj] = data[posj] ^ block[j];
        }
        pos += take;
    }
}
/** Creates ARX-like (ChaCha, Salsa) cipher stream from core function. */
function createCipher(core, opts) {
    const { allowShortKeys, extendNonceFn, counterLength, counterRight, rounds } = checkOpts({ allowShortKeys: false, counterLength: 8, counterRight: false, rounds: 20 }, opts);
    if (typeof core !== 'function')
        throw new Error('core must be a function');
    ciphers_utils_anumber(counterLength);
    ciphers_utils_anumber(rounds);
    abool(counterRight);
    abool(allowShortKeys);
    return (key, nonce, data, output, counter = 0) => {
        ciphers_utils_abytes(key, undefined, 'key');
        ciphers_utils_abytes(nonce, undefined, 'nonce');
        ciphers_utils_abytes(data, undefined, 'data');
        const len = data.length;
        if (output === undefined)
            output = new Uint8Array(len);
        ciphers_utils_abytes(output, undefined, 'output');
        ciphers_utils_anumber(counter);
        if (counter < 0 || counter >= MAX_COUNTER)
            throw new Error('arx: counter overflow');
        if (output.length < len)
            throw new Error(`arx: output (${output.length}) is shorter than data (${len})`);
        const toClean = [];
        // Key & sigma
        // key=16 -> sigma16, k=key|key
        // key=32 -> sigma32, k=key
        let l = key.length;
        let k;
        let sigma;
        if (l === 32) {
            toClean.push((k = copyBytes(key)));
            sigma = sigma32_32;
        }
        else if (l === 16 && allowShortKeys) {
            k = new Uint8Array(32);
            k.set(key);
            k.set(key, 16);
            sigma = sigma16_32;
            toClean.push(k);
        }
        else {
            ciphers_utils_abytes(key, 32, 'arx key');
            throw new Error('invalid key size');
            // throw new Error(`"arx key" expected Uint8Array of length 32, got length=${l}`);
        }
        // Nonce
        // salsa20:      8   (8-byte counter)
        // chacha20orig: 8   (8-byte counter)
        // chacha20:     12  (4-byte counter)
        // xsalsa20:     24  (16 -> hsalsa,  8 -> old nonce)
        // xchacha20:    24  (16 -> hchacha, 8 -> old nonce)
        // Align nonce to 4 bytes
        if (!_arx_isAligned32(nonce))
            toClean.push((nonce = copyBytes(nonce)));
        const k32 = utils_u32(k);
        // hsalsa & hchacha: handle extended nonce
        if (extendNonceFn) {
            if (nonce.length !== 24)
                throw new Error(`arx: extended nonce must be 24 bytes`);
            extendNonceFn(sigma, k32, utils_u32(nonce.subarray(0, 16)), k32);
            nonce = nonce.subarray(16);
        }
        // Handle nonce counter
        const nonceNcLen = 16 - counterLength;
        if (nonceNcLen !== nonce.length)
            throw new Error(`arx: nonce must be ${nonceNcLen} or 16 bytes`);
        // Pad counter when nonce is 64 bit
        if (nonceNcLen !== 12) {
            const nc = new Uint8Array(12);
            nc.set(nonce, counterRight ? 0 : 12 - nonce.length);
            nonce = nc;
            toClean.push(nonce);
        }
        const n32 = utils_u32(nonce);
        runCipher(core, sigma, k32, n32, data, output, counter, rounds);
        utils_clean(...toClean);
        return output;
    };
}
/** Internal class which wraps chacha20 or chacha8 to create CSPRNG. */
class _XorStreamPRG {
    blockLen;
    keyLen;
    nonceLen;
    state;
    buf;
    key;
    nonce;
    pos;
    ctr;
    cipher;
    constructor(cipher, blockLen, keyLen, nonceLen, seed) {
        this.cipher = cipher;
        this.blockLen = blockLen;
        this.keyLen = keyLen;
        this.nonceLen = nonceLen;
        this.state = new Uint8Array(this.keyLen + this.nonceLen);
        this.reseed(seed);
        this.ctr = 0;
        this.pos = this.blockLen;
        this.buf = new Uint8Array(this.blockLen);
        this.key = this.state.subarray(0, this.keyLen);
        this.nonce = this.state.subarray(this.keyLen);
    }
    reseed(seed) {
        abytes(seed);
        if (!seed || seed.length === 0)
            throw new Error('entropy required');
        for (let i = 0; i < seed.length; i++)
            this.state[i % this.state.length] ^= seed[i];
        this.ctr = 0;
        this.pos = this.blockLen;
    }
    addEntropy(seed) {
        this.state.set(this.randomBytes(this.state.length));
        this.reseed(seed);
    }
    randomBytes(len) {
        anumber(len);
        if (len === 0)
            return new Uint8Array(0);
        const out = new Uint8Array(len);
        let outPos = 0;
        // Leftovers
        if (this.pos < this.blockLen) {
            const take = Math.min(len, this.blockLen - this.pos);
            out.set(this.buf.subarray(this.pos, this.pos + take), 0);
            this.pos += take;
            outPos += take;
            if (outPos === len)
                return out; // fast path
        }
        // Full blocks directly to out
        const blocks = Math.floor((len - outPos) / this.blockLen);
        if (blocks > 0) {
            const blockBytes = blocks * this.blockLen;
            const b = out.subarray(outPos, outPos + blockBytes);
            this.cipher(this.key, this.nonce, b, b, this.ctr);
            this.ctr += blocks;
            outPos += blockBytes;
        }
        // Save leftovers
        const left = len - outPos;
        if (left > 0) {
            this.buf.fill(0);
            // NOTE: cipher will handle overflow
            this.cipher(this.key, this.nonce, this.buf, this.buf, this.ctr++);
            out.set(this.buf.subarray(0, left), outPos);
            this.pos = left;
        }
        return out;
    }
    clone() {
        return new _XorStreamPRG(this.cipher, this.blockLen, this.keyLen, this.nonceLen, this.randomBytes(this.state.length));
    }
    clean() {
        this.pos = 0;
        this.ctr = 0;
        this.buf.fill(0);
        this.state.fill(0);
    }
}
const _arx_createPRG = (cipher, blockLen, keyLen, nonceLen) => {
    return (seed = randomBytes(32)) => new _XorStreamPRG(cipher, blockLen, keyLen, nonceLen, seed);
};
//# sourceMappingURL=_arx.js.map
;// ./node_modules/@noble/ciphers/_poly1305.js
/**
 * Poly1305 ([PDF](https://cr.yp.to/mac/poly1305-20050329.pdf),
 * [wiki](https://en.wikipedia.org/wiki/Poly1305))
 * is a fast and parallel secret-key message-authentication code suitable for
 * a wide variety of applications. It was standardized in
 * [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) and is now used in TLS 1.3.
 *
 * Polynomial MACs are not perfect for every situation:
 * they lack Random Key Robustness: the MAC can be forged, and can't be used in PAKE schemes.
 * See [invisible salamanders attack](https://keymaterial.net/2020/09/07/invisible-salamanders-in-aes-gcm-siv/).
 * To combat invisible salamanders, `hash(key)` can be included in ciphertext,
 * however, this would violate ciphertext indistinguishability:
 * an attacker would know which key was used - so `HKDF(key, i)`
 * could be used instead.
 *
 * Check out [original website](https://cr.yp.to/mac.html).
 * Based on Public Domain [poly1305-donna](https://github.com/floodyberry/poly1305-donna).
 * @module
 */
// prettier-ignore

function u8to16(a, i) {
    return (a[i++] & 0xff) | ((a[i++] & 0xff) << 8);
}
function bytesToNumberLE(bytes) {
    return hexToNumber(bytesToHex(Uint8Array.from(bytes).reverse()));
}
/** Small version of `poly1305` without loop unrolling. Unused, provided for auditability. */
function poly1305_small(msg, key) {
    abytes(msg);
    abytes(key, 32, 'key');
    const POW_2_130_5 = BigInt(2) ** BigInt(130) - BigInt(5); // 2^130-5
    const POW_2_128_1 = BigInt(2) ** BigInt(128) - BigInt(1); // 2^128-1
    const CLAMP_R = BigInt('0x0ffffffc0ffffffc0ffffffc0fffffff');
    const r = bytesToNumberLE(key.subarray(0, 16)) & CLAMP_R;
    const s = bytesToNumberLE(key.subarray(16));
    // Process by 16 byte chunks
    let acc = BigInt(0);
    for (let i = 0; i < msg.length; i += 16) {
        const m = msg.subarray(i, i + 16);
        const n = bytesToNumberLE(m) | (BigInt(1) << BigInt(8 * m.length));
        acc = ((acc + n) * r) % POW_2_130_5;
    }
    const res = (acc + s) & POW_2_128_1;
    return numberToBytesBE(res, 16).reverse(); // LE
}
// Can be used to replace `computeTag` in chacha.ts. Unused, provided for auditability.
// @ts-expect-error
function poly1305_computeTag_small(authKey, lengths, ciphertext, AAD) {
    const res = [];
    const updatePadded2 = (msg) => {
        res.push(msg);
        const leftover = msg.length % 16;
        if (leftover)
            res.push(new Uint8Array(16).slice(leftover));
    };
    if (AAD)
        updatePadded2(AAD);
    updatePadded2(ciphertext);
    res.push(lengths);
    return poly1305_small(concatBytes(...res), authKey);
}
/** Poly1305 class. Prefer poly1305() function instead. */
class Poly1305 {
    blockLen = 16;
    outputLen = 16;
    buffer = new Uint8Array(16);
    r = new Uint16Array(10); // Allocating 1 array with .subarray() here is slower than 3
    h = new Uint16Array(10);
    pad = new Uint16Array(8);
    pos = 0;
    finished = false;
    // Can be speed-up using BigUint64Array, at the cost of complexity
    constructor(key) {
        key = copyBytes(ciphers_utils_abytes(key, 32, 'key'));
        const t0 = u8to16(key, 0);
        const t1 = u8to16(key, 2);
        const t2 = u8to16(key, 4);
        const t3 = u8to16(key, 6);
        const t4 = u8to16(key, 8);
        const t5 = u8to16(key, 10);
        const t6 = u8to16(key, 12);
        const t7 = u8to16(key, 14);
        // https://github.com/floodyberry/poly1305-donna/blob/e6ad6e091d30d7f4ec2d4f978be1fcfcbce72781/poly1305-donna-16.h#L47
        this.r[0] = t0 & 0x1fff;
        this.r[1] = ((t0 >>> 13) | (t1 << 3)) & 0x1fff;
        this.r[2] = ((t1 >>> 10) | (t2 << 6)) & 0x1f03;
        this.r[3] = ((t2 >>> 7) | (t3 << 9)) & 0x1fff;
        this.r[4] = ((t3 >>> 4) | (t4 << 12)) & 0x00ff;
        this.r[5] = (t4 >>> 1) & 0x1ffe;
        this.r[6] = ((t4 >>> 14) | (t5 << 2)) & 0x1fff;
        this.r[7] = ((t5 >>> 11) | (t6 << 5)) & 0x1f81;
        this.r[8] = ((t6 >>> 8) | (t7 << 8)) & 0x1fff;
        this.r[9] = (t7 >>> 5) & 0x007f;
        for (let i = 0; i < 8; i++)
            this.pad[i] = u8to16(key, 16 + 2 * i);
    }
    process(data, offset, isLast = false) {
        const hibit = isLast ? 0 : 1 << 11;
        const { h, r } = this;
        const r0 = r[0];
        const r1 = r[1];
        const r2 = r[2];
        const r3 = r[3];
        const r4 = r[4];
        const r5 = r[5];
        const r6 = r[6];
        const r7 = r[7];
        const r8 = r[8];
        const r9 = r[9];
        const t0 = u8to16(data, offset + 0);
        const t1 = u8to16(data, offset + 2);
        const t2 = u8to16(data, offset + 4);
        const t3 = u8to16(data, offset + 6);
        const t4 = u8to16(data, offset + 8);
        const t5 = u8to16(data, offset + 10);
        const t6 = u8to16(data, offset + 12);
        const t7 = u8to16(data, offset + 14);
        let h0 = h[0] + (t0 & 0x1fff);
        let h1 = h[1] + (((t0 >>> 13) | (t1 << 3)) & 0x1fff);
        let h2 = h[2] + (((t1 >>> 10) | (t2 << 6)) & 0x1fff);
        let h3 = h[3] + (((t2 >>> 7) | (t3 << 9)) & 0x1fff);
        let h4 = h[4] + (((t3 >>> 4) | (t4 << 12)) & 0x1fff);
        let h5 = h[5] + ((t4 >>> 1) & 0x1fff);
        let h6 = h[6] + (((t4 >>> 14) | (t5 << 2)) & 0x1fff);
        let h7 = h[7] + (((t5 >>> 11) | (t6 << 5)) & 0x1fff);
        let h8 = h[8] + (((t6 >>> 8) | (t7 << 8)) & 0x1fff);
        let h9 = h[9] + ((t7 >>> 5) | hibit);
        let c = 0;
        let d0 = c + h0 * r0 + h1 * (5 * r9) + h2 * (5 * r8) + h3 * (5 * r7) + h4 * (5 * r6);
        c = d0 >>> 13;
        d0 &= 0x1fff;
        d0 += h5 * (5 * r5) + h6 * (5 * r4) + h7 * (5 * r3) + h8 * (5 * r2) + h9 * (5 * r1);
        c += d0 >>> 13;
        d0 &= 0x1fff;
        let d1 = c + h0 * r1 + h1 * r0 + h2 * (5 * r9) + h3 * (5 * r8) + h4 * (5 * r7);
        c = d1 >>> 13;
        d1 &= 0x1fff;
        d1 += h5 * (5 * r6) + h6 * (5 * r5) + h7 * (5 * r4) + h8 * (5 * r3) + h9 * (5 * r2);
        c += d1 >>> 13;
        d1 &= 0x1fff;
        let d2 = c + h0 * r2 + h1 * r1 + h2 * r0 + h3 * (5 * r9) + h4 * (5 * r8);
        c = d2 >>> 13;
        d2 &= 0x1fff;
        d2 += h5 * (5 * r7) + h6 * (5 * r6) + h7 * (5 * r5) + h8 * (5 * r4) + h9 * (5 * r3);
        c += d2 >>> 13;
        d2 &= 0x1fff;
        let d3 = c + h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * (5 * r9);
        c = d3 >>> 13;
        d3 &= 0x1fff;
        d3 += h5 * (5 * r8) + h6 * (5 * r7) + h7 * (5 * r6) + h8 * (5 * r5) + h9 * (5 * r4);
        c += d3 >>> 13;
        d3 &= 0x1fff;
        let d4 = c + h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
        c = d4 >>> 13;
        d4 &= 0x1fff;
        d4 += h5 * (5 * r9) + h6 * (5 * r8) + h7 * (5 * r7) + h8 * (5 * r6) + h9 * (5 * r5);
        c += d4 >>> 13;
        d4 &= 0x1fff;
        let d5 = c + h0 * r5 + h1 * r4 + h2 * r3 + h3 * r2 + h4 * r1;
        c = d5 >>> 13;
        d5 &= 0x1fff;
        d5 += h5 * r0 + h6 * (5 * r9) + h7 * (5 * r8) + h8 * (5 * r7) + h9 * (5 * r6);
        c += d5 >>> 13;
        d5 &= 0x1fff;
        let d6 = c + h0 * r6 + h1 * r5 + h2 * r4 + h3 * r3 + h4 * r2;
        c = d6 >>> 13;
        d6 &= 0x1fff;
        d6 += h5 * r1 + h6 * r0 + h7 * (5 * r9) + h8 * (5 * r8) + h9 * (5 * r7);
        c += d6 >>> 13;
        d6 &= 0x1fff;
        let d7 = c + h0 * r7 + h1 * r6 + h2 * r5 + h3 * r4 + h4 * r3;
        c = d7 >>> 13;
        d7 &= 0x1fff;
        d7 += h5 * r2 + h6 * r1 + h7 * r0 + h8 * (5 * r9) + h9 * (5 * r8);
        c += d7 >>> 13;
        d7 &= 0x1fff;
        let d8 = c + h0 * r8 + h1 * r7 + h2 * r6 + h3 * r5 + h4 * r4;
        c = d8 >>> 13;
        d8 &= 0x1fff;
        d8 += h5 * r3 + h6 * r2 + h7 * r1 + h8 * r0 + h9 * (5 * r9);
        c += d8 >>> 13;
        d8 &= 0x1fff;
        let d9 = c + h0 * r9 + h1 * r8 + h2 * r7 + h3 * r6 + h4 * r5;
        c = d9 >>> 13;
        d9 &= 0x1fff;
        d9 += h5 * r4 + h6 * r3 + h7 * r2 + h8 * r1 + h9 * r0;
        c += d9 >>> 13;
        d9 &= 0x1fff;
        c = ((c << 2) + c) | 0;
        c = (c + d0) | 0;
        d0 = c & 0x1fff;
        c = c >>> 13;
        d1 += c;
        h[0] = d0;
        h[1] = d1;
        h[2] = d2;
        h[3] = d3;
        h[4] = d4;
        h[5] = d5;
        h[6] = d6;
        h[7] = d7;
        h[8] = d8;
        h[9] = d9;
    }
    finalize() {
        const { h, pad } = this;
        const g = new Uint16Array(10);
        let c = h[1] >>> 13;
        h[1] &= 0x1fff;
        for (let i = 2; i < 10; i++) {
            h[i] += c;
            c = h[i] >>> 13;
            h[i] &= 0x1fff;
        }
        h[0] += c * 5;
        c = h[0] >>> 13;
        h[0] &= 0x1fff;
        h[1] += c;
        c = h[1] >>> 13;
        h[1] &= 0x1fff;
        h[2] += c;
        g[0] = h[0] + 5;
        c = g[0] >>> 13;
        g[0] &= 0x1fff;
        for (let i = 1; i < 10; i++) {
            g[i] = h[i] + c;
            c = g[i] >>> 13;
            g[i] &= 0x1fff;
        }
        g[9] -= 1 << 13;
        let mask = (c ^ 1) - 1;
        for (let i = 0; i < 10; i++)
            g[i] &= mask;
        mask = ~mask;
        for (let i = 0; i < 10; i++)
            h[i] = (h[i] & mask) | g[i];
        h[0] = (h[0] | (h[1] << 13)) & 0xffff;
        h[1] = ((h[1] >>> 3) | (h[2] << 10)) & 0xffff;
        h[2] = ((h[2] >>> 6) | (h[3] << 7)) & 0xffff;
        h[3] = ((h[3] >>> 9) | (h[4] << 4)) & 0xffff;
        h[4] = ((h[4] >>> 12) | (h[5] << 1) | (h[6] << 14)) & 0xffff;
        h[5] = ((h[6] >>> 2) | (h[7] << 11)) & 0xffff;
        h[6] = ((h[7] >>> 5) | (h[8] << 8)) & 0xffff;
        h[7] = ((h[8] >>> 8) | (h[9] << 5)) & 0xffff;
        let f = h[0] + pad[0];
        h[0] = f & 0xffff;
        for (let i = 1; i < 8; i++) {
            f = (((h[i] + pad[i]) | 0) + (f >>> 16)) | 0;
            h[i] = f & 0xffff;
        }
        utils_clean(g);
    }
    update(data) {
        utils_aexists(this);
        ciphers_utils_abytes(data);
        data = copyBytes(data);
        const { buffer, blockLen } = this;
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            // Fast path: we have at least one block in input
            if (take === blockLen) {
                for (; blockLen <= len - pos; pos += blockLen)
                    this.process(data, pos);
                continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
                this.process(buffer, 0, false);
                this.pos = 0;
            }
        }
        return this;
    }
    destroy() {
        utils_clean(this.h, this.r, this.buffer, this.pad);
    }
    digestInto(out) {
        utils_aexists(this);
        utils_aoutput(out, this);
        this.finished = true;
        const { buffer, h } = this;
        let { pos } = this;
        if (pos) {
            buffer[pos++] = 1;
            for (; pos < 16; pos++)
                buffer[pos] = 0;
            this.process(buffer, 0, true);
        }
        this.finalize();
        let opos = 0;
        for (let i = 0; i < 8; i++) {
            out[opos++] = h[i] >>> 0;
            out[opos++] = h[i] >>> 8;
        }
        return out;
    }
    digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
    }
}
function wrapConstructorWithKey(hashCons) {
    const hashC = (msg, key) => hashCons(key).update(msg).digest();
    const tmp = hashCons(new Uint8Array(32)); // tmp array, used just once below
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = (key) => hashCons(key);
    return hashC;
}
/** Poly1305 MAC from RFC 8439. */
const poly1305 = /** @__PURE__ */ (() => wrapConstructorWithKey((key) => new Poly1305(key)))();
//# sourceMappingURL=_poly1305.js.map
;// ./node_modules/@noble/ciphers/chacha.js
/**
 * ChaCha stream cipher, released
 * in 2008. Developed after Salsa20, ChaCha aims to increase diffusion per round.
 * It was standardized in [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) and
 * is now used in TLS 1.3.
 *
 * [XChaCha20](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha)
 * extended-nonce variant is also provided. Similar to XSalsa, it's safe to use with
 * randomly-generated nonces.
 *
 * Check out [PDF](http://cr.yp.to/chacha/chacha-20080128.pdf) and
 * [wiki](https://en.wikipedia.org/wiki/Salsa20) and
 * [website](https://cr.yp.to/chacha.html).
 *
 * @module
 */



/**
 * ChaCha core function. It is implemented twice:
 * 1. Simple loop (chachaCore_small, hchacha_small)
 * 2. Unrolled loop (chachaCore, hchacha) - 4x faster, but larger & harder to read
 * The specific implementation is selected in `createCipher` below.
 */
/** quarter-round */
// prettier-ignore
function chachaQR(x, a, b, c, d) {
    x[a] = (x[a] + x[b]) | 0;
    x[d] = rotl(x[d] ^ x[a], 16);
    x[c] = (x[c] + x[d]) | 0;
    x[b] = rotl(x[b] ^ x[c], 12);
    x[a] = (x[a] + x[b]) | 0;
    x[d] = rotl(x[d] ^ x[a], 8);
    x[c] = (x[c] + x[d]) | 0;
    x[b] = rotl(x[b] ^ x[c], 7);
}
/** single round */
function chachaRound(x, rounds = 20) {
    for (let r = 0; r < rounds; r += 2) {
        chachaQR(x, 0, 4, 8, 12);
        chachaQR(x, 1, 5, 9, 13);
        chachaQR(x, 2, 6, 10, 14);
        chachaQR(x, 3, 7, 11, 15);
        chachaQR(x, 0, 5, 10, 15);
        chachaQR(x, 1, 6, 11, 12);
        chachaQR(x, 2, 7, 8, 13);
        chachaQR(x, 3, 4, 9, 14);
    }
}
const ctmp = /* @__PURE__ */ new Uint32Array(16);
/** Small version of chacha without loop unrolling. Unused, provided for auditability. */
// prettier-ignore
function chacha(s, k, i, out, isHChacha = true, rounds = 20) {
    // Create initial array using common pattern
    const y = Uint32Array.from([
        s[0], s[1], s[2], s[3], // "expa"   "nd 3"  "2-by"  "te k"
        k[0], k[1], k[2], k[3], // Key      Key     Key     Key
        k[4], k[5], k[6], k[7], // Key      Key     Key     Key
        i[0], i[1], i[2], i[3], // Counter  Counter Nonce   Nonce
    ]);
    const x = ctmp;
    x.set(y);
    chachaRound(x, rounds);
    // hchacha extracts 8 specific bytes, chacha adds orig to result
    if (isHChacha) {
        const xindexes = [0, 1, 2, 3, 12, 13, 14, 15];
        for (let i = 0; i < 8; i++)
            out[i] = x[xindexes[i]];
    }
    else {
        for (let i = 0; i < 16; i++)
            out[i] = (y[i] + x[i]) | 0;
    }
}
/** Identical to `chachaCore`. Unused. */
// @ts-ignore
const chachaCore_small = (s, k, n, out, cnt, rounds) => chacha(s, k, Uint32Array.from([n[0], n[1], cnt, 0]), out, false, rounds);
/** Identical to `hchacha`. Unused. */
// @ts-ignore
const hchacha_small = (/* unused pure expression or super */ null && (chacha));
/** Identical to `chachaCore_small`. Unused. */
// prettier-ignore
function chachaCore(s, k, n, out, cnt, rounds = 20) {
    let y00 = s[0], y01 = s[1], y02 = s[2], y03 = s[3], // "expa"   "nd 3"  "2-by"  "te k"
    y04 = k[0], y05 = k[1], y06 = k[2], y07 = k[3], // Key      Key     Key     Key
    y08 = k[4], y09 = k[5], y10 = k[6], y11 = k[7], // Key      Key     Key     Key
    y12 = cnt, y13 = n[0], y14 = n[1], y15 = n[2]; // Counter  Counter	Nonce   Nonce
    // Save state to temporary variables
    let x00 = y00, x01 = y01, x02 = y02, x03 = y03, x04 = y04, x05 = y05, x06 = y06, x07 = y07, x08 = y08, x09 = y09, x10 = y10, x11 = y11, x12 = y12, x13 = y13, x14 = y14, x15 = y15;
    for (let r = 0; r < rounds; r += 2) {
        x00 = (x00 + x04) | 0;
        x12 = _arx_rotl(x12 ^ x00, 16);
        x08 = (x08 + x12) | 0;
        x04 = _arx_rotl(x04 ^ x08, 12);
        x00 = (x00 + x04) | 0;
        x12 = _arx_rotl(x12 ^ x00, 8);
        x08 = (x08 + x12) | 0;
        x04 = _arx_rotl(x04 ^ x08, 7);
        x01 = (x01 + x05) | 0;
        x13 = _arx_rotl(x13 ^ x01, 16);
        x09 = (x09 + x13) | 0;
        x05 = _arx_rotl(x05 ^ x09, 12);
        x01 = (x01 + x05) | 0;
        x13 = _arx_rotl(x13 ^ x01, 8);
        x09 = (x09 + x13) | 0;
        x05 = _arx_rotl(x05 ^ x09, 7);
        x02 = (x02 + x06) | 0;
        x14 = _arx_rotl(x14 ^ x02, 16);
        x10 = (x10 + x14) | 0;
        x06 = _arx_rotl(x06 ^ x10, 12);
        x02 = (x02 + x06) | 0;
        x14 = _arx_rotl(x14 ^ x02, 8);
        x10 = (x10 + x14) | 0;
        x06 = _arx_rotl(x06 ^ x10, 7);
        x03 = (x03 + x07) | 0;
        x15 = _arx_rotl(x15 ^ x03, 16);
        x11 = (x11 + x15) | 0;
        x07 = _arx_rotl(x07 ^ x11, 12);
        x03 = (x03 + x07) | 0;
        x15 = _arx_rotl(x15 ^ x03, 8);
        x11 = (x11 + x15) | 0;
        x07 = _arx_rotl(x07 ^ x11, 7);
        x00 = (x00 + x05) | 0;
        x15 = _arx_rotl(x15 ^ x00, 16);
        x10 = (x10 + x15) | 0;
        x05 = _arx_rotl(x05 ^ x10, 12);
        x00 = (x00 + x05) | 0;
        x15 = _arx_rotl(x15 ^ x00, 8);
        x10 = (x10 + x15) | 0;
        x05 = _arx_rotl(x05 ^ x10, 7);
        x01 = (x01 + x06) | 0;
        x12 = _arx_rotl(x12 ^ x01, 16);
        x11 = (x11 + x12) | 0;
        x06 = _arx_rotl(x06 ^ x11, 12);
        x01 = (x01 + x06) | 0;
        x12 = _arx_rotl(x12 ^ x01, 8);
        x11 = (x11 + x12) | 0;
        x06 = _arx_rotl(x06 ^ x11, 7);
        x02 = (x02 + x07) | 0;
        x13 = _arx_rotl(x13 ^ x02, 16);
        x08 = (x08 + x13) | 0;
        x07 = _arx_rotl(x07 ^ x08, 12);
        x02 = (x02 + x07) | 0;
        x13 = _arx_rotl(x13 ^ x02, 8);
        x08 = (x08 + x13) | 0;
        x07 = _arx_rotl(x07 ^ x08, 7);
        x03 = (x03 + x04) | 0;
        x14 = _arx_rotl(x14 ^ x03, 16);
        x09 = (x09 + x14) | 0;
        x04 = _arx_rotl(x04 ^ x09, 12);
        x03 = (x03 + x04) | 0;
        x14 = _arx_rotl(x14 ^ x03, 8);
        x09 = (x09 + x14) | 0;
        x04 = _arx_rotl(x04 ^ x09, 7);
    }
    // Write output
    let oi = 0;
    out[oi++] = (y00 + x00) | 0;
    out[oi++] = (y01 + x01) | 0;
    out[oi++] = (y02 + x02) | 0;
    out[oi++] = (y03 + x03) | 0;
    out[oi++] = (y04 + x04) | 0;
    out[oi++] = (y05 + x05) | 0;
    out[oi++] = (y06 + x06) | 0;
    out[oi++] = (y07 + x07) | 0;
    out[oi++] = (y08 + x08) | 0;
    out[oi++] = (y09 + x09) | 0;
    out[oi++] = (y10 + x10) | 0;
    out[oi++] = (y11 + x11) | 0;
    out[oi++] = (y12 + x12) | 0;
    out[oi++] = (y13 + x13) | 0;
    out[oi++] = (y14 + x14) | 0;
    out[oi++] = (y15 + x15) | 0;
}
/**
 * hchacha hashes key and nonce into key' and nonce' for xchacha20.
 * Identical to `hchacha_small`.
 * Need to find a way to merge it with `chachaCore` without 25% performance hit.
 */
// prettier-ignore
function hchacha(s, k, i, out) {
    let x00 = s[0], x01 = s[1], x02 = s[2], x03 = s[3], x04 = k[0], x05 = k[1], x06 = k[2], x07 = k[3], x08 = k[4], x09 = k[5], x10 = k[6], x11 = k[7], x12 = i[0], x13 = i[1], x14 = i[2], x15 = i[3];
    for (let r = 0; r < 20; r += 2) {
        x00 = (x00 + x04) | 0;
        x12 = _arx_rotl(x12 ^ x00, 16);
        x08 = (x08 + x12) | 0;
        x04 = _arx_rotl(x04 ^ x08, 12);
        x00 = (x00 + x04) | 0;
        x12 = _arx_rotl(x12 ^ x00, 8);
        x08 = (x08 + x12) | 0;
        x04 = _arx_rotl(x04 ^ x08, 7);
        x01 = (x01 + x05) | 0;
        x13 = _arx_rotl(x13 ^ x01, 16);
        x09 = (x09 + x13) | 0;
        x05 = _arx_rotl(x05 ^ x09, 12);
        x01 = (x01 + x05) | 0;
        x13 = _arx_rotl(x13 ^ x01, 8);
        x09 = (x09 + x13) | 0;
        x05 = _arx_rotl(x05 ^ x09, 7);
        x02 = (x02 + x06) | 0;
        x14 = _arx_rotl(x14 ^ x02, 16);
        x10 = (x10 + x14) | 0;
        x06 = _arx_rotl(x06 ^ x10, 12);
        x02 = (x02 + x06) | 0;
        x14 = _arx_rotl(x14 ^ x02, 8);
        x10 = (x10 + x14) | 0;
        x06 = _arx_rotl(x06 ^ x10, 7);
        x03 = (x03 + x07) | 0;
        x15 = _arx_rotl(x15 ^ x03, 16);
        x11 = (x11 + x15) | 0;
        x07 = _arx_rotl(x07 ^ x11, 12);
        x03 = (x03 + x07) | 0;
        x15 = _arx_rotl(x15 ^ x03, 8);
        x11 = (x11 + x15) | 0;
        x07 = _arx_rotl(x07 ^ x11, 7);
        x00 = (x00 + x05) | 0;
        x15 = _arx_rotl(x15 ^ x00, 16);
        x10 = (x10 + x15) | 0;
        x05 = _arx_rotl(x05 ^ x10, 12);
        x00 = (x00 + x05) | 0;
        x15 = _arx_rotl(x15 ^ x00, 8);
        x10 = (x10 + x15) | 0;
        x05 = _arx_rotl(x05 ^ x10, 7);
        x01 = (x01 + x06) | 0;
        x12 = _arx_rotl(x12 ^ x01, 16);
        x11 = (x11 + x12) | 0;
        x06 = _arx_rotl(x06 ^ x11, 12);
        x01 = (x01 + x06) | 0;
        x12 = _arx_rotl(x12 ^ x01, 8);
        x11 = (x11 + x12) | 0;
        x06 = _arx_rotl(x06 ^ x11, 7);
        x02 = (x02 + x07) | 0;
        x13 = _arx_rotl(x13 ^ x02, 16);
        x08 = (x08 + x13) | 0;
        x07 = _arx_rotl(x07 ^ x08, 12);
        x02 = (x02 + x07) | 0;
        x13 = _arx_rotl(x13 ^ x02, 8);
        x08 = (x08 + x13) | 0;
        x07 = _arx_rotl(x07 ^ x08, 7);
        x03 = (x03 + x04) | 0;
        x14 = _arx_rotl(x14 ^ x03, 16);
        x09 = (x09 + x14) | 0;
        x04 = _arx_rotl(x04 ^ x09, 12);
        x03 = (x03 + x04) | 0;
        x14 = _arx_rotl(x14 ^ x03, 8);
        x09 = (x09 + x14) | 0;
        x04 = _arx_rotl(x04 ^ x09, 7);
    }
    let oi = 0;
    out[oi++] = x00;
    out[oi++] = x01;
    out[oi++] = x02;
    out[oi++] = x03;
    out[oi++] = x12;
    out[oi++] = x13;
    out[oi++] = x14;
    out[oi++] = x15;
}
/** Original, non-RFC chacha20 from DJB. 8-byte nonce, 8-byte counter. */
const chacha20orig = /* @__PURE__ */ createCipher(chachaCore, {
    counterRight: false,
    counterLength: 8,
    allowShortKeys: true,
});
/**
 * ChaCha stream cipher. Conforms to RFC 8439 (IETF, TLS). 12-byte nonce, 4-byte counter.
 * With smaller nonce, it's not safe to make it random (CSPRNG), due to collision chance.
 */
const chacha20 = /* @__PURE__ */ createCipher(chachaCore, {
    counterRight: false,
    counterLength: 4,
    allowShortKeys: false,
});
/**
 * XChaCha eXtended-nonce ChaCha. With 24-byte nonce, it's safe to make it random (CSPRNG).
 * See [IRTF draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha).
 */
const xchacha20 = /* @__PURE__ */ createCipher(chachaCore, {
    counterRight: false,
    counterLength: 8,
    extendNonceFn: hchacha,
    allowShortKeys: false,
});
/** Reduced 8-round chacha, described in original paper. */
const chacha8 = /* @__PURE__ */ createCipher(chachaCore, {
    counterRight: false,
    counterLength: 4,
    rounds: 8,
});
/** Reduced 12-round chacha, described in original paper. */
const chacha12 = /* @__PURE__ */ createCipher(chachaCore, {
    counterRight: false,
    counterLength: 4,
    rounds: 12,
});
const ZEROS16 = /* @__PURE__ */ new Uint8Array(16);
// Pad to digest size with zeros
const updatePadded = (h, msg) => {
    h.update(msg);
    const leftover = msg.length % 16;
    if (leftover)
        h.update(ZEROS16.subarray(leftover));
};
const ZEROS32 = /* @__PURE__ */ new Uint8Array(32);
function computeTag(fn, key, nonce, ciphertext, AAD) {
    if (AAD !== undefined)
        ciphers_utils_abytes(AAD, undefined, 'AAD');
    const authKey = fn(key, nonce, ZEROS32);
    const lengths = u64Lengths(ciphertext.length, AAD ? AAD.length : 0, true);
    // Methods below can be replaced with
    // return poly1305_computeTag_small(authKey, lengths, ciphertext, AAD)
    const h = poly1305.create(authKey);
    if (AAD)
        updatePadded(h, AAD);
    updatePadded(h, ciphertext);
    h.update(lengths);
    const res = h.digest();
    utils_clean(authKey, lengths);
    return res;
}
/**
 * AEAD algorithm from RFC 8439.
 * Salsa20 and chacha (RFC 8439) use poly1305 differently.
 * We could have composed them, but it's hard because of authKey:
 * In salsa20, authKey changes position in salsa stream.
 * In chacha, authKey can't be computed inside computeTag, it modifies the counter.
 */
const _poly1305_aead = (xorStream) => (key, nonce, AAD) => {
    const tagLength = 16;
    return {
        encrypt(plaintext, output) {
            const plength = plaintext.length;
            output = getOutput(plength + tagLength, output, false);
            output.set(plaintext);
            const oPlain = output.subarray(0, -tagLength);
            // Actual encryption
            xorStream(key, nonce, oPlain, oPlain, 1);
            const tag = computeTag(xorStream, key, nonce, oPlain, AAD);
            output.set(tag, plength); // append tag
            utils_clean(tag);
            return output;
        },
        decrypt(ciphertext, output) {
            output = getOutput(ciphertext.length - tagLength, output, false);
            const data = ciphertext.subarray(0, -tagLength);
            const passedTag = ciphertext.subarray(-tagLength);
            const tag = computeTag(xorStream, key, nonce, data, AAD);
            if (!equalBytes(passedTag, tag))
                throw new Error('invalid tag');
            output.set(ciphertext.subarray(0, -tagLength));
            // Actual decryption
            xorStream(key, nonce, output, output, 1); // start stream with i=1
            utils_clean(tag);
            return output;
        },
    };
};
/**
 * ChaCha20-Poly1305 from RFC 8439.
 *
 * Unsafe to use random nonces under the same key, due to collision chance.
 * Prefer XChaCha instead.
 */
const chacha20poly1305 = /* @__PURE__ */ wrapCipher({ blockSize: 64, nonceLength: 12, tagLength: 16 }, _poly1305_aead(chacha20));
/**
 * XChaCha20-Poly1305 extended-nonce chacha.
 *
 * Can be safely used with random nonces (CSPRNG).
 * See [IRTF draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha).
 */
const xchacha20poly1305 = /* @__PURE__ */ wrapCipher({ blockSize: 64, nonceLength: 24, tagLength: 16 }, _poly1305_aead(xchacha20));
/**
 * Chacha20 CSPRNG (cryptographically secure pseudorandom number generator).
 * It's best to limit usage to non-production, non-critical cases: for example, test-only.
 * Compatible with libtomcrypt. It does not have a specification, so unclear how secure it is.
 */
const rngChacha20 = /* @__PURE__ */ (/* unused pure expression or super */ null && (createPRG(chacha20orig, 64, 32, 8)));
/**
 * Chacha20/8 CSPRNG (cryptographically secure pseudorandom number generator).
 * It's best to limit usage to non-production, non-critical cases: for example, test-only.
 * Faster than `rngChacha20`.
 */
const rngChacha8 = /* @__PURE__ */ (/* unused pure expression or super */ null && (createPRG(chacha8, 64, 32, 12)));
//# sourceMappingURL=chacha.js.map
// EXTERNAL MODULE: ./node_modules/buffer/index.js
var buffer = __webpack_require__(8287);
;// ./src/index.js






// === CONFIG ===
const API_BASE_URL = 'https://quantumsure.onrender.com/api'; // Update if needed
//const API_BASE_URL = 'https://quantumsure.onrender.com/api';

// === CRYPTO HELPERS ===
function src_randomBytes(length) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return buffer.Buffer.from(array);
}

async function computeMac(data, key) {
  const dataBytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const keyBytes = typeof key === 'string' ? new TextEncoder().encode(key) : key;
  const combined = buffer.Buffer.concat([buffer.Buffer.from(dataBytes), buffer.Buffer.from(keyBytes)]);
  const hash = await crypto.subtle.digest('SHA-256', combined);
  return buffer.Buffer.from(hash);
}

function postQuantumEncrypt(data, key) {
  const nonce = src_randomBytes(12);
  const dataBytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const chacha = new (jschacha20_default())(key, nonce);
  const encrypted = chacha.encrypt(dataBytes);
  return {
    encrypted: encode(encrypted),
    nonce: encode(nonce),
  };
}

async function postQuantumDecrypt(encryptedB64, nonceB64, key, authTagB64) {
  const encrypted = buffer.Buffer.from(decode(encryptedB64));
  const nonce = buffer.Buffer.from(decode(nonceB64));
  const combinedData = new TextEncoder().encode(`${nonceB64}${encryptedB64}`);
  const computedMac = await computeMac(combinedData, key);
  if (!computedMac.equals(buffer.Buffer.from(decode(authTagB64)))) {
    throw new Error('Invalid MAC');
  }
  const chacha = new (jschacha20_default())(key, nonce);
  const decrypted = chacha.decrypt(encrypted);
  return new TextDecoder().decode(decrypted);
}

async function quantumResistantEncrypt(inputData, pubKeyB64) {
  const publicKey = buffer.Buffer.from(decode(pubKeyB64));
  const sender = new MlKem1024();
  const [ciphertext, sharedSecret] = await sender.encap(publicKey);
  const { encrypted, nonce } = postQuantumEncrypt(inputData, sharedSecret);
  const combinedData = new TextEncoder().encode(`${nonce}${encrypted}`);
  const authTag = await computeMac(combinedData, sharedSecret);
  return {
    encrypted_data: `${encode(ciphertext)}:${nonce}:${encrypted}:${encode(authTag)}`,
  };
}

async function quantumResistantDecrypt(encryptedData, privateKeyB64) {
  const [ciphertextB64, nonceB64, encryptedB64, authTagB64] = encryptedData.split(':');
  if (!ciphertextB64 || !nonceB64 || !encryptedB64 || !authTagB64) {
    throw new Error('Invalid encrypted data format');
  }
  const privateKey = buffer.Buffer.from(decode(privateKeyB64));
  const recipient = new MlKem1024();
  const sharedSecret = await recipient.decap(buffer.Buffer.from(decode(ciphertextB64)), privateKey);
  return await postQuantumDecrypt(encryptedB64, nonceB64, sharedSecret, authTagB64);
}

async function encryptPrivateKey(privateKey, masterPassword) {
  const key = buffer.Buffer.from(masterPassword.padEnd(32, '0').slice(0, 32));
  const nonce = src_randomBytes(12);
  const chacha = new (jschacha20_default())(key, nonce);
  const encrypted = chacha.encrypt(buffer.Buffer.from(privateKey));
  const combinedData = new TextEncoder().encode(`${encode(nonce)}${encode(encrypted)}`);
  const authTag = await computeMac(combinedData, key);
  return `${encode(nonce)}.${encode(encrypted)}.${encode(authTag)}`;
}

async function decryptPrivateKey(encryptedPrivateKey, masterPassword) {
  const [nonceB64, encryptedB64, authTagB64] = encryptedPrivateKey.split('.');
  if (!nonceB64 || !encryptedB64 || !authTagB64) {
    throw new Error('Invalid encrypted private key format');
  }
  const key = buffer.Buffer.from(masterPassword.padEnd(32, '0').slice(0, 32));
  const combinedData = new TextEncoder().encode(`${nonceB64}${encryptedB64}`);
  const computedMac = await computeMac(combinedData, key);
  if (!computedMac.equals(buffer.Buffer.from(decode(authTagB64)))) {
    throw new Error('Invalid MAC');
  }
  const nonce = buffer.Buffer.from(decode(nonceB64));
  const encrypted = buffer.Buffer.from(decode(encryptedB64));
  const chacha = new (jschacha20_default())(key, nonce);
  const decrypted = chacha.decrypt(encrypted);
  return new TextDecoder().decode(decrypted);
}

// === USER SESSION MANAGER ===
const USER_SESSIONS = 'qs_user_sessions';
let currentSession = null;

function saveSession(apiKey, encryptedPrivateKey, alias = 'User') {
  const sessions = JSON.parse(localStorage.getItem(USER_SESSIONS) || '[]');
  const existing = sessions.find(s => s.apiKey === apiKey);
  if (existing) {
    existing.encryptedPrivateKey = encryptedPrivateKey;
    existing.alias = alias;
  } else {
    sessions.push({ apiKey, encryptedPrivateKey, alias });
  }
  localStorage.setItem(USER_SESSIONS, JSON.stringify(sessions));
  switchToSession(apiKey);
}

function switchToSession(apiKey) {
  const sessions = JSON.parse(localStorage.getItem(USER_SESSIONS) || '[]');
  const session = sessions.find(s => s.apiKey === apiKey);
  if (!session) return;

  currentSession = session;
  localStorage.setItem('apiKey', session.apiKey);
  localStorage.setItem('encryptedPrivateKey', session.encryptedPrivateKey);

  document.getElementById('current-user').innerText = `${session.alias} (${session.apiKey.slice(0, 8)}...)`;
  //document.getElementById('user-switcher').style.display = 'block';
}

async function logoutUser() {
  localStorage.removeItem('apiKey');
  localStorage.removeItem('encryptedPrivateKey');
  currentSession = null;
  document.getElementById('current-user').innerText = 'None';
  document.getElementById('output').innerText = 'Logged out. Create or switch user.';
}
window.logoutUser = logoutUser;

function switchUser() {
  const sessions = JSON.parse(localStorage.getItem(USER_SESSIONS) || '[]');
  if (sessions.length === 0) {
    alert('No users to switch.');
    return;
  }

  const options = sessions.map((s, i) => `${i + 1}. ${s.alias} (${s.apiKey.slice(0, 8)}...)`).join('\n');
  const choice = prompt(`Switch to:\n${options}\n\nEnter number:`, '1');
  const index = parseInt(choice) - 1;
  if (index >= 0 && index < sessions.length) {
    switchToSession(sessions[index].apiKey);
    document.getElementById('output').innerText = `Switched to ${sessions[index].alias}`;
  }
}
window.switchUser = switchUser;

// === API CALLS ===
async function createAccount(secretPhrase, masterPassword, alias) {
  const recipient = new MlKem1024();
  const [publicKey, privateKey] = await recipient.generateKeyPair();
  const publicKeyB64 = encode(publicKey);
  const privateKeyB64 = encode(privateKey);
  const encryptedPrivateKey = await encryptPrivateKey(privateKeyB64, masterPassword);

  const response = await fetch(`${API_BASE_URL}/user/create`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      data: { public_key: publicKeyB64, secret_phrase: secretPhrase }
    }),
  });

  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const result = await response.json();
  saveSession(result.api_key, encryptedPrivateKey, alias);
  return result;
}


async function getPublicKey(targetApiKey) {
  const myApiKey = localStorage.getItem('apiKey');
  const response = await fetch(`${API_BASE_URL}/user/public-key/${targetApiKey}`, {
    method: 'GET',
    headers: {
      'api_key': myApiKey,  // ← Auth as ME
      'Content-Type': 'application/json'
    },
  });
  if (!response.ok) throw new Error(`Failed to get public key: ${await response.text()}`);
  const { public_key } = await response.json();
  return public_key;
}

// storePassword() — get MY public key
async function getMyPublicKey() {
  const apiKey = localStorage.getItem('apiKey');
  const res = await fetch(`${API_BASE_URL}/user/public-key`, {
    method: 'GET',
    headers: { 'api_key': apiKey }
  });
  const { public_key } = await res.json();
  return public_key;
}

async function storePassword(apiKey, site, username, password) {
  const publicKey = await getMyPublicKey();
  const { encrypted_data } = await quantumResistantEncrypt(password, publicKey);
  const response = await fetch(`${API_BASE_URL}/password/store`, {
    method: 'POST',
    headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      data: { site, username, encrypted_text: encrypted_data }
    }),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return await response.json();
}

async function listPasswords(apiKey) {
  const response = await fetch(`${API_BASE_URL}/password/list`, {
    method: 'GET',
    headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return await response.json();
}

async function getPassword(apiKey, passwordId, masterPassword, encryptedPrivateKey) {
  const response = await fetch(`${API_BASE_URL}/password/get`, {
    method: 'POST',
    headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({ data: { password_id: passwordId } }),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const { encrypted_text, site, username } = await response.json();
  const privateKeyB64 = await decryptPrivateKey(encryptedPrivateKey, masterPassword);
  const password = await quantumResistantDecrypt(encrypted_text, privateKeyB64);
  return { site, username, password };
}

async function shareWithUsers(apiKey, passwordId, masterPassword, encryptedPrivateKey, recipientApiKeys) {
  const privateKeyB64 = await decryptPrivateKey(encryptedPrivateKey, masterPassword);
  const getRes = await fetch(`${API_BASE_URL}/password/get`, {
    method: 'POST',
    headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({ data: { password_id: passwordId } }),
  });
  const { encrypted_text } = await getRes.json();
  const plaintext = await quantumResistantDecrypt(encrypted_text, privateKeyB64);

  const encryptedTokens = [];
  for (const recApiKey of recipientApiKeys) {
    const pubKey = await getPublicKey(recApiKey);
    const { encrypted_data } = await quantumResistantEncrypt(plaintext, pubKey);
    encryptedTokens.push(encrypted_data);
  }

  const shareRes = await fetch(`${API_BASE_URL}/share`, {
    method: 'POST',
    headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      data: {
        qpassword_id: passwordId,
        user_api_keys: recipientApiKeys,
        encrypted_access_tokens: encryptedTokens,
        expires_in_hours: 24
      }
    }),
  });
  if (!shareRes.ok) throw new Error(`HTTP ${shareRes.status}`);
  return await shareRes.json();
}

async function revokeSharedPassword(apiKey, shareId) {
  const response = await fetch(`${API_BASE_URL}/share/revoke`, {
    method: 'POST',
    headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      data: { share_id: shareId }
    }),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return await response.json();
}


async function deleteSharedPassword(apiKey, shareId) {
  const response = await fetch(`${API_BASE_URL}/share/delete`, {
    method: 'POST',
    headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      data: { share_id: shareId }
    }),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return await response.json();
}

async function useSharedPassword(apiKey, shareId, masterPassword, encryptedPrivateKey) {
  const privateKeyB64 = await decryptPrivateKey(encryptedPrivateKey, masterPassword);
  const res = await fetch(`${API_BASE_URL}/share/use`, {
    method: 'POST',
    headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      data: { share_id: shareId, private_key_b64: privateKeyB64 }
    }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const response = await res.json();
  const { encrypted_blob, share_type } = response;
  if (!encrypted_blob){
    throw new Error('No encrypted data found!');
  }
  const decrypted = await quantumResistantDecrypt(encrypted_blob, privateKeyB64);
  if (share_type.includes('password')){
    return {password: decrypted};
  }
  else if (share_type.includes('oauth')){
    return {access_token: decrypted};
  }
  else {
    throw new Error('Unknown share type: '.concat(share_type));
  }

}

async function createShareGroup1(apiKey, groupName){
    const response = await fetch(`${API_BASE_URL}/sharegroup/create`, {
        method: 'POST',
        headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: { name: groupName } }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
}

async function addShareGroupMember(apiKey, groupId, memberApi){
    const response = await fetch(`${API_BASE_URL}/sharegroup/add`, {
        method: 'POST',
        headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: { group_id: groupId, member_api_keys: [memberApi] } }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
}

async function removeShareGroupMember(apiKey, groupId, memberApi){
    const response = await fetch(`${API_BASE_URL}/sharegroup/remove`, {
        method: 'POST',
        headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: { group_id: groupId, member_api_keys: [memberApi] } }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
}

async function revokeShareGroup1(apiKey, groupId){
    const response = await fetch(`${API_BASE_URL}/sharegroup/revoke`, {
        method: 'POST',
        headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: { group_id: groupId } }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
}

async function deleteShareGroup1(apiKey, groupId){
    const response = await fetch(`${API_BASE_URL}/sharegroup/delete`, {
        method: 'POST',
        headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: { group_id: groupId } }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
}

function generatePassword(length = 16) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
  const bytes = src_randomBytes(length);
  return Array.from(bytes).map(b => chars[b % chars.length]).join('');
}

// === UI ===
window.createAccount = async () => {
  const mp = document.getElementById('create-master-password').value;
  const sp = document.getElementById('secret-phrase').value;
  const alias = prompt('Name this user (e.g., Alice, Bob):', 'User') || 'User';

  if (!mp || !sp) {
    alert('Master password and secret phrase required.');
    return;
  }

  try {
    const r = await createAccount(sp, mp, alias);
    document.getElementById('output').innerText =
      `Account created!\nName: ${alias}\nAPI Key: ${r.api_key}`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.storePassword = async () => {
  const apiKey = localStorage.getItem('apiKey');
  if (!apiKey) return alert('No user logged in.');
  const site = document.getElementById('site').value;
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  if (!site || !username || !password) return alert('Fill all fields.');

  try {
    const r = await storePassword(apiKey, site, username, password);
    document.getElementById('output').innerText = `Stored! ID: ${r.password_id}`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.listPasswords = async () => {
  const apiKey = localStorage.getItem('apiKey');
  if (!apiKey) return alert('No user logged in.');
  try {
    const r = await listPasswords(apiKey);
    const ul = document.getElementById('password-list');
    ul.innerHTML = '';
    r.passwords.forEach(p => {
      const li = document.createElement('li');
      li.innerText = `${p.site} - ${p.username} (ID: ${p.id})`;
      ul.appendChild(li);
    });
    document.getElementById('output').innerText = `Loaded ${r.passwords.length} passwords.`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.getPassword = async () => {
  const apiKey = localStorage.getItem('apiKey');
  const id = document.getElementById('password-id').value;
  const mp = document.getElementById('retrieve-master-password').value;
  const epk = localStorage.getItem('encryptedPrivateKey');
  if (!apiKey || !id || !mp || !epk) return alert('Missing data.');

  try {
    const r = await getPassword(apiKey, id, mp, epk);
    document.getElementById('output').innerText = `Password: ${r.password}`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.sharePassword = async () => {
  const apiKey = localStorage.getItem('apiKey');
  const id = document.getElementById('share-password-id').value;
  const mp = document.getElementById('share-master-password').value;
  const st = document.getElementById('share-type').value;
  const epk = localStorage.getItem('encryptedPrivateKey');
  const recipients = document.getElementById('recipient-api-keys').value.split(',').map(s => s.trim()).filter(Boolean);

  if (!apiKey || !id || !mp || !epk || !st || recipients.length === 0) {
    return alert('Fill all fields');
  }

  try {
    // 1. Get encrypted password
    const getRes = await fetch(`${API_BASE_URL}/password/get`, {
      method: 'POST',
      headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: { password_id: id } })
    });
    const { encrypted_text } = await getRes.json();

    // 2. Decrypt locally
    const privateKeyB64 = await decryptPrivateKey(epk, mp);
    const plaintext = await quantumResistantDecrypt(encrypted_text, privateKeyB64);

    // 3. Re-encrypt for each recipient
    const encryptedTokens = [];
    for (const recKey of recipients) {
      const pubKey = await getPublicKey(recKey);
      const { encrypted_data } = await quantumResistantEncrypt(plaintext, pubKey);
      encryptedTokens.push(encrypted_data);
    }

    // 4. Send to server
    const shareRes = await fetch(`${API_BASE_URL}/share`, {
      method: 'POST',
      headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        data: {
          qpassword_id: id,
          user_api_keys: recipients,
          encrypted_access_tokens: encryptedTokens,
          expires_in_hours: 24,
          share_type: st
        }
      })
    });

    const result = await shareRes.json();
    document.getElementById('output').innerText = `Shared! Check console.`;
    console.log('Shares:', result.shares);
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};


window.useShared = async () => {
  const shareId = document.getElementById('share-id').value;
  const mp = document.getElementById('access-master-password').value;
  const epk = localStorage.getItem('encryptedPrivateKey');
  const apiKey = localStorage.getItem("apiKey");
  if (!shareId || !mp || !epk) return alert('Fill all fields.');

  try {
    const r = await useSharedPassword(apiKey, shareId, mp, epk);
    document.getElementById('output').innerText = `Shared Password: ${r.password}`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};


window.revokeShared = async () => {
  const shareId = document.getElementById('share-id2').value;
  const apiKey = localStorage.getItem("apiKey");
  if (!shareId) return alert('Fill all fields.');

  try {
    const r = await revokeSharedPassword(apiKey, shareId);
    document.getElementById('output').innerText = `Successfully Revoked Shared Token.`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.deleteShared = async () => {
  const shareId = document.getElementById('share-id3').value;
  const apiKey = localStorage.getItem("apiKey");
  if (!shareId) return alert('Fill all fields.');

  try {
    const r = await deleteSharedPassword(apiKey, shareId);
    document.getElementById('output').innerText = `Successfully Deleted Shared Token.`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.createShareGroup = async () => {
  const groupName = document.getElementById('group-name').value;
  const apiKey = localStorage.getItem("apiKey");
  if (!groupName) return alert('Fill all fields.');

  try {
    const r = await createShareGroup1(apiKey, groupName);
    console.log(r);
    document.getElementById('output').innerText = `Share Group Created. Group id: `.concat(r.group_id);
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.addGroupMember = async () => {
  const groupId = document.getElementById('add-group-id').value;
  const memberApi = document.getElementById('add-member-key').value;
  const apiKey = localStorage.getItem("apiKey");
  if (!groupId || !memberApi) return alert('Fill all fields.');

  try {
    const r = await addShareGroupMember(apiKey, groupId, memberApi);
    document.getElementById('output').innerText = `Added Member.`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.removeGroupMember = async () => {
  const groupId = document.getElementById('remove-group-id').value;
  const memberApi = document.getElementById('remove-member-key').value;
  const apiKey = localStorage.getItem("apiKey");
  if (!groupId || !memberApi) return alert('Fill all fields.');

  try {
    const r = await removeShareGroupMember(apiKey, groupId, memberApi);
    document.getElementById('output').innerText = `Removed Member.`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.revokeShareGroup = async () => {
  const groupId = document.getElementById('revoke-group-id').value;
  const apiKey = localStorage.getItem("apiKey");
  if (!groupId) return alert('Fill all fields.');

  try {
    const r = await revokeShareGroup1(apiKey, groupId);
    document.getElementById('output').innerText = `Share Group Revoked.`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.deleteShareGroup = async () => {
  const groupId = document.getElementById('delete-group-id').value;
  const apiKey = localStorage.getItem("apiKey");
  if (!groupId) return alert('Fill all fields.');

  try {
    const r = await deleteShareGroup1(apiKey, groupId);
    document.getElementById('output').innerText = `Share Group Deleted.`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.shareWithGroup = async () => {
  const groupId = document.getElementById('share-group-id').value.trim();
  const pwdId = document.getElementById('share-pwd-id').value.trim();
  const shareType = document.getElementById('share-pwd-type').value.trim();
  const mp = document.getElementById('share-mp').value;
  const epk = localStorage.getItem('encryptedPrivateKey');
  const apiKey = localStorage.getItem('apiKey');

  if (!groupId || !pwdId || !shareType || !mp){
    throw new Error('No field is optional!');
  }


  try {
    // Reuse logic from Step 3 above
    const privateKeyB64 = await decryptPrivateKey(epk, mp);
    const getRes = await fetch(`${API_BASE_URL}/password/get`, {
      method: 'POST',
      headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: { password_id: pwdId } })
    });
    const { encrypted_text } = await getRes.json();
    const plaintext = await quantumResistantDecrypt(encrypted_text, privateKeyB64);

    const groupRes = await fetch(`${API_BASE_URL}/sharegroup/list`, { headers: { 'api_key': apiKey } });
    const groups = await groupRes.json();
    const group = groups.groups.find(g => g.group_id === groupId);

    const memberKeys = group.member_api_keys;

    const encryptedBlobs = [];
    for (const key of memberKeys) {
      const pub = await getPublicKey(key);
      const { encrypted_data } = await quantumResistantEncrypt(plaintext, pub);
      encryptedBlobs.push(encrypted_data);
    }

    const shareRes = await fetch(`${API_BASE_URL}/share`, {
      method: 'POST',
      headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        data: {
          qpassword_id: pwdId,
          group_id: groupId,
          user_api_keys: memberKeys,
          encrypted_access_tokens: encryptedBlobs,
          share_type: shareType,
          expires_in_hours: 24
        }
      })
    });
    const result = await shareRes.json();
    document.getElementById('output').innerText =
      `Shared!\nShares: ${result.shares.map(s => s.share_id).join(', ')}`;
     console.log('Shares:', result.shares);

  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.generatePassword = () => {
  document.getElementById('password').value = generatePassword();
};

// === ON LOAD ===
window.loadplan = async () => {
  const lastApiKey = localStorage.getItem('apiKey');
  const sessions = JSON.parse(localStorage.getItem(USER_SESSIONS) || '[]');
  if (sessions.length !== 0) {
    const options = sessions.map((s, i) => `${i + 1}. ${s.alias} (${s.apiKey.slice(0, 8)}...)`).join('\n');
    //document.getElementById('user-switcher').style.display = 'block';

  }



  if (lastApiKey) {
    switchToSession(lastApiKey);
  }

  await showFlow(1);

};

async function loginUser(){
  let sessions = JSON.parse(localStorage.getItem(USER_SESSIONS) || '[]');
  console.log(sessions);
  const modal = document.getElementById('myModal');
  modal.style.display = 'flex';
}
window.loginUser = loginUser;

async function closeForm(){
  const modal = document.getElementById('myModal');
  modal.style.display = 'none';
}
window.closeForm = closeForm;

async function addAccount(){
    const form = document.getElementById('keyForm');
    const modal = document.getElementById('myModal');
    const apiKey = document.getElementById('apiKey').value.trim();
    const encryptedKey = document.getElementById('encryptedKey').value.trim();
    const alias = document.getElementById('alias').value.trim();
    const sessions = JSON.parse(localStorage.getItem(USER_SESSIONS) || '[]');
    var i = 0;
    //console.log(sessions[0].apiKey);
    //console.log(sessions[0].encryptedPrivateKey);
    while (i < sessions.length){
      let key = sessions[i].apiKey;
      if (key == apiKey){
        modal.style.display = 'none';
        form.reset();
        alert('You are already logged in on this device this this account');
        return;
      }
      i++;
    }
    const response = await fetch(`${API_BASE_URL}/user/public-key/${apiKey}`, {
      method: 'GET',
      headers: {
        'api_key': apiKey,  // ← Auth as ME
        'Content-Type': 'application/json'
      },
    });
    if (!response.ok){
      modal.style.display = 'none';
      form.reset();
      alert('Invalid api key. Please choose one that actually exists.');
      return;
    };

    saveSession(apiKey, encryptedKey, alias);
    modal.style.display = 'none';
    form.reset();
}
window.addAccount = addAccount;

async function toggleFlowMenu() {
  const dropdown = document.getElementById('flow-dropdown');
  dropdown.style.display = dropdown.style.display === 'block' ? 'none' : 'block';
}
window.toggleFlowMenu = toggleFlowMenu;

async function showFlow(k){
  var i = 1;
  document.querySelectorAll('.content-wrapper').forEach(sec => {
    if (k != i){
      sec.style.display = 'none';
    }
    else {
      sec.style.display = 'block';
    }
    i++;
  });
  const dropdown = document.getElementById('flow-dropdown');
  dropdown.style.display = 'none';
}
window.showFlow = showFlow;


async function expandGuide(k){
  switch (k){
    case 1: {
      document.getElementById('dd1').style.display = document.getElementById('dd1').style.display !== 'block' ? 'block': 'none';
      break;
    }
    case 2: {
      document.getElementById('dd2').style.display = document.getElementById('dd2').style.display !== 'block' ? 'block': 'none';
      break;
    }
    case 3: {
      document.getElementById('dd3').style.display = document.getElementById('dd3').style.display !== 'block' ? 'block': 'none';
      break;
    }
    case 4: {
      document.getElementById('ee1').style.display = document.getElementById('ee1').style.display !== 'block' ? 'block': 'none';
      break;
    }
    case 5: {
      document.getElementById('ee2').style.display = document.getElementById('ee2').style.display !== 'block' ? 'block': 'none';
      break;
    }
    case 6: {
      document.getElementById('ee3').style.display = document.getElementById('ee3').style.display !== 'block' ? 'block': 'none';
      break;
    }
    case 7: {
      document.getElementById('ee4').style.display = document.getElementById('ee4').style.display !== 'block' ? 'block': 'none';
      break;
    }
    case 8: {
      document.getElementById('ee5').style.display = document.getElementById('ee5').style.display !== 'block' ? 'block': 'none';
      break;
    }
    case 9: {
      document.getElementById('ee6').style.display = document.getElementById('ee6').style.display !== 'block' ? 'block': 'none';
      break;
    }
    default: {}
  }
}
window.expandGuide = expandGuide;


// === Export Credentials ===


function downloadTxtFile(filename, text) {
  const a = document.createElement('a');
  a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(text);
  a.download = filename;
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}


function generateCredentials(ak, epk) {


  // Format the text content clearly
  const text = `Your Account Credentials
  ================================

  API Key: ${ak}

  Encrypted Private Key: ${epk}

  ================================
  IMPORTANT:
  - Save this file in a safe place.
  - Do not share these credentials with anyone.
  - This file was generated on your device and was never sent to any server.
  - You will not be able to view these credentials again after closing this page.

  Generated on: ${new Date().toLocaleString()}
  `;

  // Trigger download
  downloadTxtFile("quantumsure_".concat(ak).concat(".txt"), text);
}

async function exportAccount(){
  const apiKey = localStorage.getItem('apiKey');
  const epk = localStorage.getItem('encryptedPrivateKey');
  if (!apiKey || !epk){
    alert("You are not logged in to any account.");
    return;
  }
  else {
    generateCredentials(apiKey, epk);
  }
}
window.exportAccount = exportAccount;


// === Clear Account ===

async function clearAccount(){
  const apiKey = localStorage.getItem('apiKey');
  let sessions = JSON.parse(localStorage.getItem(USER_SESSIONS) || '[]');
  const ind = sessions.findIndex(s => s.apiKey === apiKey);
  if (ind != -1) {
    sessions.splice(ind, 1);
  } else {
    alert('Invalid Key');
    return;
  }
  localStorage.setItem(USER_SESSIONS, JSON.stringify(sessions));
  await logoutUser();
  alert('Account data cleared.');
}
window.clearAccount = clearAccount;


// === Files ===

async function encryptFile() {
    const fileInput = document.getElementById('encrypt-file');
    const file = fileInput.files?.[0];
    if (!file) {
      alert('Please select a file first.');
      return;
    }

    let statusDiv = document.getElementById('encrypt-status');
    if (!statusDiv) {
      statusDiv = document.createElement('div');
      statusDiv.id = 'encrypt-status';
      fileInput.parentElement.appendChild(statusDiv);
    }
    statusDiv.textContent = 'Encrypting...';
    statusDiv.style.color = 'blue';

    try {
      const publicKey = getPublicKey();  // Uint8Array

      // Read file
      const fileBytes = new Uint8Array(await file.arrayBuffer());

      // ML-KEM-1024 encapsulate → get ciphertext + shared secret (our symmetric key)
      const { ciphertext: kemCiphertext, sharedSecret: fileKey } =
        await MlKem1024.encap(publicKey);

      // Encrypt file content with XChaCha20-Poly1305
      const nonce = src_randomBytes(24);
      const encryptedFile = xchacha20poly1305(fileKey, nonce).encrypt(fileBytes);

      // Bundle: version (2B) | kemLen (2B) | kemCiphertext | nonce (24B) | encryptedFile
      const version = new Uint8Array([1, 0]);
      const kemLenBytes = new Uint8Array([
        (kemCiphertext.length >> 8) & 0xff,
        kemCiphertext.length & 0xff
      ]);

      const bundle = concatBytes(
        version,
        kemLenBytes,
        kemCiphertext,
        nonce,
        encryptedFile
      );

      // Download
      const blob = new Blob([bundle], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.name + '.qsecure';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      statusDiv.textContent = 'Encryption complete — file downloaded as .qsecure';
      statusDiv.style.color = 'green';
    } catch (err) {
      console.error(err);
      statusDiv.textContent = 'Encryption failed: ' + (err.message || 'Unknown error');
      statusDiv.style.color = 'red';
    }
}
window.encryptFile = encryptFile;


})();

/******/ })()
;