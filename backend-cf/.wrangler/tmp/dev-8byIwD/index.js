var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// .wrangler/tmp/bundle-eygzm5/checked-fetch.js
function checkURL(request, init) {
  const url = request instanceof URL ? request : new URL(
    (typeof request === "string" ? new Request(request, init) : request).url
  );
  if (url.port && url.port !== "443" && url.protocol === "https:") {
    if (!urls.has(url.toString())) {
      urls.add(url.toString());
      console.warn(
        `WARNING: known issue with \`fetch()\` requests to custom HTTPS ports in published Workers:
 - ${url.toString()} - the custom port will be ignored when the Worker is published using the \`wrangler deploy\` command.
`
      );
    }
  }
}
var urls;
var init_checked_fetch = __esm({
  ".wrangler/tmp/bundle-eygzm5/checked-fetch.js"() {
    "use strict";
    urls = /* @__PURE__ */ new Set();
    __name(checkURL, "checkURL");
    globalThis.fetch = new Proxy(globalThis.fetch, {
      apply(target, thisArg, argArray) {
        const [request, init] = argArray;
        checkURL(request, init);
        return Reflect.apply(target, thisArg, argArray);
      }
    });
  }
});

// .wrangler/tmp/bundle-eygzm5/strip-cf-connecting-ip-header.js
function stripCfConnectingIPHeader(input, init) {
  const request = new Request(input, init);
  request.headers.delete("CF-Connecting-IP");
  return request;
}
var init_strip_cf_connecting_ip_header = __esm({
  ".wrangler/tmp/bundle-eygzm5/strip-cf-connecting-ip-header.js"() {
    "use strict";
    __name(stripCfConnectingIPHeader, "stripCfConnectingIPHeader");
    globalThis.fetch = new Proxy(globalThis.fetch, {
      apply(target, thisArg, argArray) {
        return Reflect.apply(target, thisArg, [
          stripCfConnectingIPHeader.apply(null, argArray)
        ]);
      }
    });
  }
});

// wrangler-modules-watch:wrangler:modules-watch
var init_wrangler_modules_watch = __esm({
  "wrangler-modules-watch:wrangler:modules-watch"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
  }
});

// node_modules/wrangler/templates/modules-watch-stub.js
var init_modules_watch_stub = __esm({
  "node_modules/wrangler/templates/modules-watch-stub.js"() {
    init_wrangler_modules_watch();
  }
});

// node_modules/jose/dist/browser/runtime/webcrypto.js
var webcrypto_default, isCryptoKey;
var init_webcrypto = __esm({
  "node_modules/jose/dist/browser/runtime/webcrypto.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    webcrypto_default = crypto;
    isCryptoKey = /* @__PURE__ */ __name((key) => key instanceof CryptoKey, "isCryptoKey");
  }
});

// node_modules/jose/dist/browser/runtime/digest.js
var digest, digest_default;
var init_digest = __esm({
  "node_modules/jose/dist/browser/runtime/digest.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_webcrypto();
    digest = /* @__PURE__ */ __name(async (algorithm, data) => {
      const subtleDigest = `SHA-${algorithm.slice(-3)}`;
      return new Uint8Array(await webcrypto_default.subtle.digest(subtleDigest, data));
    }, "digest");
    digest_default = digest;
  }
});

// node_modules/jose/dist/browser/lib/buffer_utils.js
function concat(...buffers) {
  const size = buffers.reduce((acc, { length }) => acc + length, 0);
  const buf = new Uint8Array(size);
  let i = 0;
  for (const buffer of buffers) {
    buf.set(buffer, i);
    i += buffer.length;
  }
  return buf;
}
function p2s(alg, p2sInput) {
  return concat(encoder.encode(alg), new Uint8Array([0]), p2sInput);
}
function writeUInt32BE(buf, value, offset) {
  if (value < 0 || value >= MAX_INT32) {
    throw new RangeError(`value must be >= 0 and <= ${MAX_INT32 - 1}. Received ${value}`);
  }
  buf.set([value >>> 24, value >>> 16, value >>> 8, value & 255], offset);
}
function uint64be(value) {
  const high = Math.floor(value / MAX_INT32);
  const low = value % MAX_INT32;
  const buf = new Uint8Array(8);
  writeUInt32BE(buf, high, 0);
  writeUInt32BE(buf, low, 4);
  return buf;
}
function uint32be(value) {
  const buf = new Uint8Array(4);
  writeUInt32BE(buf, value);
  return buf;
}
function lengthAndInput(input) {
  return concat(uint32be(input.length), input);
}
async function concatKdf(secret, bits, value) {
  const iterations = Math.ceil((bits >> 3) / 32);
  const res = new Uint8Array(iterations * 32);
  for (let iter = 0; iter < iterations; iter++) {
    const buf = new Uint8Array(4 + secret.length + value.length);
    buf.set(uint32be(iter + 1));
    buf.set(secret, 4);
    buf.set(value, 4 + secret.length);
    res.set(await digest_default("sha256", buf), iter * 32);
  }
  return res.slice(0, bits >> 3);
}
var encoder, decoder, MAX_INT32;
var init_buffer_utils = __esm({
  "node_modules/jose/dist/browser/lib/buffer_utils.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_digest();
    encoder = new TextEncoder();
    decoder = new TextDecoder();
    MAX_INT32 = 2 ** 32;
    __name(concat, "concat");
    __name(p2s, "p2s");
    __name(writeUInt32BE, "writeUInt32BE");
    __name(uint64be, "uint64be");
    __name(uint32be, "uint32be");
    __name(lengthAndInput, "lengthAndInput");
    __name(concatKdf, "concatKdf");
  }
});

// node_modules/jose/dist/browser/runtime/base64url.js
var encodeBase64, encode, decodeBase64, decode;
var init_base64url = __esm({
  "node_modules/jose/dist/browser/runtime/base64url.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_buffer_utils();
    encodeBase64 = /* @__PURE__ */ __name((input) => {
      let unencoded = input;
      if (typeof unencoded === "string") {
        unencoded = encoder.encode(unencoded);
      }
      const CHUNK_SIZE = 32768;
      const arr = [];
      for (let i = 0; i < unencoded.length; i += CHUNK_SIZE) {
        arr.push(String.fromCharCode.apply(null, unencoded.subarray(i, i + CHUNK_SIZE)));
      }
      return btoa(arr.join(""));
    }, "encodeBase64");
    encode = /* @__PURE__ */ __name((input) => {
      return encodeBase64(input).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    }, "encode");
    decodeBase64 = /* @__PURE__ */ __name((encoded) => {
      const binary = atob(encoded);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    }, "decodeBase64");
    decode = /* @__PURE__ */ __name((input) => {
      let encoded = input;
      if (encoded instanceof Uint8Array) {
        encoded = decoder.decode(encoded);
      }
      encoded = encoded.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, "");
      try {
        return decodeBase64(encoded);
      } catch {
        throw new TypeError("The input to be decoded is not correctly encoded.");
      }
    }, "decode");
  }
});

// node_modules/jose/dist/browser/util/errors.js
var errors_exports = {};
__export(errors_exports, {
  JOSEAlgNotAllowed: () => JOSEAlgNotAllowed,
  JOSEError: () => JOSEError,
  JOSENotSupported: () => JOSENotSupported,
  JWEDecryptionFailed: () => JWEDecryptionFailed,
  JWEInvalid: () => JWEInvalid,
  JWKInvalid: () => JWKInvalid,
  JWKSInvalid: () => JWKSInvalid,
  JWKSMultipleMatchingKeys: () => JWKSMultipleMatchingKeys,
  JWKSNoMatchingKey: () => JWKSNoMatchingKey,
  JWKSTimeout: () => JWKSTimeout,
  JWSInvalid: () => JWSInvalid,
  JWSSignatureVerificationFailed: () => JWSSignatureVerificationFailed,
  JWTClaimValidationFailed: () => JWTClaimValidationFailed,
  JWTExpired: () => JWTExpired,
  JWTInvalid: () => JWTInvalid
});
var JOSEError, JWTClaimValidationFailed, JWTExpired, JOSEAlgNotAllowed, JOSENotSupported, JWEDecryptionFailed, JWEInvalid, JWSInvalid, JWTInvalid, JWKInvalid, JWKSInvalid, JWKSNoMatchingKey, JWKSMultipleMatchingKeys, JWKSTimeout, JWSSignatureVerificationFailed;
var init_errors = __esm({
  "node_modules/jose/dist/browser/util/errors.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    JOSEError = class extends Error {
      static {
        __name(this, "JOSEError");
      }
      constructor(message2, options) {
        super(message2, options);
        this.code = "ERR_JOSE_GENERIC";
        this.name = this.constructor.name;
        Error.captureStackTrace?.(this, this.constructor);
      }
    };
    JOSEError.code = "ERR_JOSE_GENERIC";
    JWTClaimValidationFailed = class extends JOSEError {
      static {
        __name(this, "JWTClaimValidationFailed");
      }
      constructor(message2, payload, claim = "unspecified", reason = "unspecified") {
        super(message2, { cause: { claim, reason, payload } });
        this.code = "ERR_JWT_CLAIM_VALIDATION_FAILED";
        this.claim = claim;
        this.reason = reason;
        this.payload = payload;
      }
    };
    JWTClaimValidationFailed.code = "ERR_JWT_CLAIM_VALIDATION_FAILED";
    JWTExpired = class extends JOSEError {
      static {
        __name(this, "JWTExpired");
      }
      constructor(message2, payload, claim = "unspecified", reason = "unspecified") {
        super(message2, { cause: { claim, reason, payload } });
        this.code = "ERR_JWT_EXPIRED";
        this.claim = claim;
        this.reason = reason;
        this.payload = payload;
      }
    };
    JWTExpired.code = "ERR_JWT_EXPIRED";
    JOSEAlgNotAllowed = class extends JOSEError {
      static {
        __name(this, "JOSEAlgNotAllowed");
      }
      constructor() {
        super(...arguments);
        this.code = "ERR_JOSE_ALG_NOT_ALLOWED";
      }
    };
    JOSEAlgNotAllowed.code = "ERR_JOSE_ALG_NOT_ALLOWED";
    JOSENotSupported = class extends JOSEError {
      static {
        __name(this, "JOSENotSupported");
      }
      constructor() {
        super(...arguments);
        this.code = "ERR_JOSE_NOT_SUPPORTED";
      }
    };
    JOSENotSupported.code = "ERR_JOSE_NOT_SUPPORTED";
    JWEDecryptionFailed = class extends JOSEError {
      static {
        __name(this, "JWEDecryptionFailed");
      }
      constructor(message2 = "decryption operation failed", options) {
        super(message2, options);
        this.code = "ERR_JWE_DECRYPTION_FAILED";
      }
    };
    JWEDecryptionFailed.code = "ERR_JWE_DECRYPTION_FAILED";
    JWEInvalid = class extends JOSEError {
      static {
        __name(this, "JWEInvalid");
      }
      constructor() {
        super(...arguments);
        this.code = "ERR_JWE_INVALID";
      }
    };
    JWEInvalid.code = "ERR_JWE_INVALID";
    JWSInvalid = class extends JOSEError {
      static {
        __name(this, "JWSInvalid");
      }
      constructor() {
        super(...arguments);
        this.code = "ERR_JWS_INVALID";
      }
    };
    JWSInvalid.code = "ERR_JWS_INVALID";
    JWTInvalid = class extends JOSEError {
      static {
        __name(this, "JWTInvalid");
      }
      constructor() {
        super(...arguments);
        this.code = "ERR_JWT_INVALID";
      }
    };
    JWTInvalid.code = "ERR_JWT_INVALID";
    JWKInvalid = class extends JOSEError {
      static {
        __name(this, "JWKInvalid");
      }
      constructor() {
        super(...arguments);
        this.code = "ERR_JWK_INVALID";
      }
    };
    JWKInvalid.code = "ERR_JWK_INVALID";
    JWKSInvalid = class extends JOSEError {
      static {
        __name(this, "JWKSInvalid");
      }
      constructor() {
        super(...arguments);
        this.code = "ERR_JWKS_INVALID";
      }
    };
    JWKSInvalid.code = "ERR_JWKS_INVALID";
    JWKSNoMatchingKey = class extends JOSEError {
      static {
        __name(this, "JWKSNoMatchingKey");
      }
      constructor(message2 = "no applicable key found in the JSON Web Key Set", options) {
        super(message2, options);
        this.code = "ERR_JWKS_NO_MATCHING_KEY";
      }
    };
    JWKSNoMatchingKey.code = "ERR_JWKS_NO_MATCHING_KEY";
    JWKSMultipleMatchingKeys = class extends JOSEError {
      static {
        __name(this, "JWKSMultipleMatchingKeys");
      }
      constructor(message2 = "multiple matching keys found in the JSON Web Key Set", options) {
        super(message2, options);
        this.code = "ERR_JWKS_MULTIPLE_MATCHING_KEYS";
      }
    };
    JWKSMultipleMatchingKeys.code = "ERR_JWKS_MULTIPLE_MATCHING_KEYS";
    JWKSTimeout = class extends JOSEError {
      static {
        __name(this, "JWKSTimeout");
      }
      constructor(message2 = "request timed out", options) {
        super(message2, options);
        this.code = "ERR_JWKS_TIMEOUT";
      }
    };
    JWKSTimeout.code = "ERR_JWKS_TIMEOUT";
    JWSSignatureVerificationFailed = class extends JOSEError {
      static {
        __name(this, "JWSSignatureVerificationFailed");
      }
      constructor(message2 = "signature verification failed", options) {
        super(message2, options);
        this.code = "ERR_JWS_SIGNATURE_VERIFICATION_FAILED";
      }
    };
    JWSSignatureVerificationFailed.code = "ERR_JWS_SIGNATURE_VERIFICATION_FAILED";
  }
});

// node_modules/jose/dist/browser/runtime/random.js
var random_default;
var init_random = __esm({
  "node_modules/jose/dist/browser/runtime/random.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_webcrypto();
    random_default = webcrypto_default.getRandomValues.bind(webcrypto_default);
  }
});

// node_modules/jose/dist/browser/lib/iv.js
function bitLength(alg) {
  switch (alg) {
    case "A128GCM":
    case "A128GCMKW":
    case "A192GCM":
    case "A192GCMKW":
    case "A256GCM":
    case "A256GCMKW":
      return 96;
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512":
      return 128;
    default:
      throw new JOSENotSupported(`Unsupported JWE Algorithm: ${alg}`);
  }
}
var iv_default;
var init_iv = __esm({
  "node_modules/jose/dist/browser/lib/iv.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_errors();
    init_random();
    __name(bitLength, "bitLength");
    iv_default = /* @__PURE__ */ __name((alg) => random_default(new Uint8Array(bitLength(alg) >> 3)), "default");
  }
});

// node_modules/jose/dist/browser/lib/check_iv_length.js
var checkIvLength, check_iv_length_default;
var init_check_iv_length = __esm({
  "node_modules/jose/dist/browser/lib/check_iv_length.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_errors();
    init_iv();
    checkIvLength = /* @__PURE__ */ __name((enc, iv) => {
      if (iv.length << 3 !== bitLength(enc)) {
        throw new JWEInvalid("Invalid Initialization Vector length");
      }
    }, "checkIvLength");
    check_iv_length_default = checkIvLength;
  }
});

// node_modules/jose/dist/browser/runtime/check_cek_length.js
var checkCekLength, check_cek_length_default;
var init_check_cek_length = __esm({
  "node_modules/jose/dist/browser/runtime/check_cek_length.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_errors();
    checkCekLength = /* @__PURE__ */ __name((cek, expected) => {
      const actual = cek.byteLength << 3;
      if (actual !== expected) {
        throw new JWEInvalid(`Invalid Content Encryption Key length. Expected ${expected} bits, got ${actual} bits`);
      }
    }, "checkCekLength");
    check_cek_length_default = checkCekLength;
  }
});

// node_modules/jose/dist/browser/runtime/timing_safe_equal.js
var timingSafeEqual, timing_safe_equal_default;
var init_timing_safe_equal = __esm({
  "node_modules/jose/dist/browser/runtime/timing_safe_equal.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    timingSafeEqual = /* @__PURE__ */ __name((a, b) => {
      if (!(a instanceof Uint8Array)) {
        throw new TypeError("First argument must be a buffer");
      }
      if (!(b instanceof Uint8Array)) {
        throw new TypeError("Second argument must be a buffer");
      }
      if (a.length !== b.length) {
        throw new TypeError("Input buffers must have the same length");
      }
      const len = a.length;
      let out = 0;
      let i = -1;
      while (++i < len) {
        out |= a[i] ^ b[i];
      }
      return out === 0;
    }, "timingSafeEqual");
    timing_safe_equal_default = timingSafeEqual;
  }
});

// node_modules/jose/dist/browser/lib/crypto_key.js
function unusable(name, prop = "algorithm.name") {
  return new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
}
function isAlgorithm(algorithm, name) {
  return algorithm.name === name;
}
function getHashLength(hash) {
  return parseInt(hash.name.slice(4), 10);
}
function getNamedCurve(alg) {
  switch (alg) {
    case "ES256":
      return "P-256";
    case "ES384":
      return "P-384";
    case "ES512":
      return "P-521";
    default:
      throw new Error("unreachable");
  }
}
function checkUsage(key, usages) {
  if (usages.length && !usages.some((expected) => key.usages.includes(expected))) {
    let msg = "CryptoKey does not support this operation, its usages must include ";
    if (usages.length > 2) {
      const last = usages.pop();
      msg += `one of ${usages.join(", ")}, or ${last}.`;
    } else if (usages.length === 2) {
      msg += `one of ${usages[0]} or ${usages[1]}.`;
    } else {
      msg += `${usages[0]}.`;
    }
    throw new TypeError(msg);
  }
}
function checkSigCryptoKey(key, alg, ...usages) {
  switch (alg) {
    case "HS256":
    case "HS384":
    case "HS512": {
      if (!isAlgorithm(key.algorithm, "HMAC"))
        throw unusable("HMAC");
      const expected = parseInt(alg.slice(2), 10);
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected)
        throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    case "RS256":
    case "RS384":
    case "RS512": {
      if (!isAlgorithm(key.algorithm, "RSASSA-PKCS1-v1_5"))
        throw unusable("RSASSA-PKCS1-v1_5");
      const expected = parseInt(alg.slice(2), 10);
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected)
        throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    case "PS256":
    case "PS384":
    case "PS512": {
      if (!isAlgorithm(key.algorithm, "RSA-PSS"))
        throw unusable("RSA-PSS");
      const expected = parseInt(alg.slice(2), 10);
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected)
        throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    case "EdDSA": {
      if (key.algorithm.name !== "Ed25519" && key.algorithm.name !== "Ed448") {
        throw unusable("Ed25519 or Ed448");
      }
      break;
    }
    case "Ed25519": {
      if (!isAlgorithm(key.algorithm, "Ed25519"))
        throw unusable("Ed25519");
      break;
    }
    case "ES256":
    case "ES384":
    case "ES512": {
      if (!isAlgorithm(key.algorithm, "ECDSA"))
        throw unusable("ECDSA");
      const expected = getNamedCurve(alg);
      const actual = key.algorithm.namedCurve;
      if (actual !== expected)
        throw unusable(expected, "algorithm.namedCurve");
      break;
    }
    default:
      throw new TypeError("CryptoKey does not support this operation");
  }
  checkUsage(key, usages);
}
function checkEncCryptoKey(key, alg, ...usages) {
  switch (alg) {
    case "A128GCM":
    case "A192GCM":
    case "A256GCM": {
      if (!isAlgorithm(key.algorithm, "AES-GCM"))
        throw unusable("AES-GCM");
      const expected = parseInt(alg.slice(1, 4), 10);
      const actual = key.algorithm.length;
      if (actual !== expected)
        throw unusable(expected, "algorithm.length");
      break;
    }
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      if (!isAlgorithm(key.algorithm, "AES-KW"))
        throw unusable("AES-KW");
      const expected = parseInt(alg.slice(1, 4), 10);
      const actual = key.algorithm.length;
      if (actual !== expected)
        throw unusable(expected, "algorithm.length");
      break;
    }
    case "ECDH": {
      switch (key.algorithm.name) {
        case "ECDH":
        case "X25519":
        case "X448":
          break;
        default:
          throw unusable("ECDH, X25519, or X448");
      }
      break;
    }
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW":
      if (!isAlgorithm(key.algorithm, "PBKDF2"))
        throw unusable("PBKDF2");
      break;
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      if (!isAlgorithm(key.algorithm, "RSA-OAEP"))
        throw unusable("RSA-OAEP");
      const expected = parseInt(alg.slice(9), 10) || 1;
      const actual = getHashLength(key.algorithm.hash);
      if (actual !== expected)
        throw unusable(`SHA-${expected}`, "algorithm.hash");
      break;
    }
    default:
      throw new TypeError("CryptoKey does not support this operation");
  }
  checkUsage(key, usages);
}
var init_crypto_key = __esm({
  "node_modules/jose/dist/browser/lib/crypto_key.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    __name(unusable, "unusable");
    __name(isAlgorithm, "isAlgorithm");
    __name(getHashLength, "getHashLength");
    __name(getNamedCurve, "getNamedCurve");
    __name(checkUsage, "checkUsage");
    __name(checkSigCryptoKey, "checkSigCryptoKey");
    __name(checkEncCryptoKey, "checkEncCryptoKey");
  }
});

// node_modules/jose/dist/browser/lib/invalid_key_input.js
function message(msg, actual, ...types2) {
  types2 = types2.filter(Boolean);
  if (types2.length > 2) {
    const last = types2.pop();
    msg += `one of type ${types2.join(", ")}, or ${last}.`;
  } else if (types2.length === 2) {
    msg += `one of type ${types2[0]} or ${types2[1]}.`;
  } else {
    msg += `of type ${types2[0]}.`;
  }
  if (actual == null) {
    msg += ` Received ${actual}`;
  } else if (typeof actual === "function" && actual.name) {
    msg += ` Received function ${actual.name}`;
  } else if (typeof actual === "object" && actual != null) {
    if (actual.constructor?.name) {
      msg += ` Received an instance of ${actual.constructor.name}`;
    }
  }
  return msg;
}
function withAlg(alg, actual, ...types2) {
  return message(`Key for the ${alg} algorithm must be `, actual, ...types2);
}
var invalid_key_input_default;
var init_invalid_key_input = __esm({
  "node_modules/jose/dist/browser/lib/invalid_key_input.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    __name(message, "message");
    invalid_key_input_default = /* @__PURE__ */ __name((actual, ...types2) => {
      return message("Key must be ", actual, ...types2);
    }, "default");
    __name(withAlg, "withAlg");
  }
});

// node_modules/jose/dist/browser/runtime/is_key_like.js
var is_key_like_default, types;
var init_is_key_like = __esm({
  "node_modules/jose/dist/browser/runtime/is_key_like.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_webcrypto();
    is_key_like_default = /* @__PURE__ */ __name((key) => {
      if (isCryptoKey(key)) {
        return true;
      }
      return key?.[Symbol.toStringTag] === "KeyObject";
    }, "default");
    types = ["CryptoKey"];
  }
});

// node_modules/jose/dist/browser/runtime/decrypt.js
async function cbcDecrypt(enc, cek, ciphertext, iv, tag2, aad) {
  if (!(cek instanceof Uint8Array)) {
    throw new TypeError(invalid_key_input_default(cek, "Uint8Array"));
  }
  const keySize = parseInt(enc.slice(1, 4), 10);
  const encKey = await webcrypto_default.subtle.importKey("raw", cek.subarray(keySize >> 3), "AES-CBC", false, ["decrypt"]);
  const macKey = await webcrypto_default.subtle.importKey("raw", cek.subarray(0, keySize >> 3), {
    hash: `SHA-${keySize << 1}`,
    name: "HMAC"
  }, false, ["sign"]);
  const macData = concat(aad, iv, ciphertext, uint64be(aad.length << 3));
  const expectedTag = new Uint8Array((await webcrypto_default.subtle.sign("HMAC", macKey, macData)).slice(0, keySize >> 3));
  let macCheckPassed;
  try {
    macCheckPassed = timing_safe_equal_default(tag2, expectedTag);
  } catch {
  }
  if (!macCheckPassed) {
    throw new JWEDecryptionFailed();
  }
  let plaintext;
  try {
    plaintext = new Uint8Array(await webcrypto_default.subtle.decrypt({ iv, name: "AES-CBC" }, encKey, ciphertext));
  } catch {
  }
  if (!plaintext) {
    throw new JWEDecryptionFailed();
  }
  return plaintext;
}
async function gcmDecrypt(enc, cek, ciphertext, iv, tag2, aad) {
  let encKey;
  if (cek instanceof Uint8Array) {
    encKey = await webcrypto_default.subtle.importKey("raw", cek, "AES-GCM", false, ["decrypt"]);
  } else {
    checkEncCryptoKey(cek, enc, "decrypt");
    encKey = cek;
  }
  try {
    return new Uint8Array(await webcrypto_default.subtle.decrypt({
      additionalData: aad,
      iv,
      name: "AES-GCM",
      tagLength: 128
    }, encKey, concat(ciphertext, tag2)));
  } catch {
    throw new JWEDecryptionFailed();
  }
}
var decrypt, decrypt_default;
var init_decrypt = __esm({
  "node_modules/jose/dist/browser/runtime/decrypt.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_buffer_utils();
    init_check_iv_length();
    init_check_cek_length();
    init_timing_safe_equal();
    init_errors();
    init_webcrypto();
    init_crypto_key();
    init_invalid_key_input();
    init_is_key_like();
    __name(cbcDecrypt, "cbcDecrypt");
    __name(gcmDecrypt, "gcmDecrypt");
    decrypt = /* @__PURE__ */ __name(async (enc, cek, ciphertext, iv, tag2, aad) => {
      if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
        throw new TypeError(invalid_key_input_default(cek, ...types, "Uint8Array"));
      }
      if (!iv) {
        throw new JWEInvalid("JWE Initialization Vector missing");
      }
      if (!tag2) {
        throw new JWEInvalid("JWE Authentication Tag missing");
      }
      check_iv_length_default(enc, iv);
      switch (enc) {
        case "A128CBC-HS256":
        case "A192CBC-HS384":
        case "A256CBC-HS512":
          if (cek instanceof Uint8Array)
            check_cek_length_default(cek, parseInt(enc.slice(-3), 10));
          return cbcDecrypt(enc, cek, ciphertext, iv, tag2, aad);
        case "A128GCM":
        case "A192GCM":
        case "A256GCM":
          if (cek instanceof Uint8Array)
            check_cek_length_default(cek, parseInt(enc.slice(1, 4), 10));
          return gcmDecrypt(enc, cek, ciphertext, iv, tag2, aad);
        default:
          throw new JOSENotSupported("Unsupported JWE Content Encryption Algorithm");
      }
    }, "decrypt");
    decrypt_default = decrypt;
  }
});

// node_modules/jose/dist/browser/lib/is_disjoint.js
var isDisjoint, is_disjoint_default;
var init_is_disjoint = __esm({
  "node_modules/jose/dist/browser/lib/is_disjoint.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    isDisjoint = /* @__PURE__ */ __name((...headers) => {
      const sources = headers.filter(Boolean);
      if (sources.length === 0 || sources.length === 1) {
        return true;
      }
      let acc;
      for (const header of sources) {
        const parameters = Object.keys(header);
        if (!acc || acc.size === 0) {
          acc = new Set(parameters);
          continue;
        }
        for (const parameter of parameters) {
          if (acc.has(parameter)) {
            return false;
          }
          acc.add(parameter);
        }
      }
      return true;
    }, "isDisjoint");
    is_disjoint_default = isDisjoint;
  }
});

// node_modules/jose/dist/browser/lib/is_object.js
function isObjectLike(value) {
  return typeof value === "object" && value !== null;
}
function isObject(input) {
  if (!isObjectLike(input) || Object.prototype.toString.call(input) !== "[object Object]") {
    return false;
  }
  if (Object.getPrototypeOf(input) === null) {
    return true;
  }
  let proto = input;
  while (Object.getPrototypeOf(proto) !== null) {
    proto = Object.getPrototypeOf(proto);
  }
  return Object.getPrototypeOf(input) === proto;
}
var init_is_object = __esm({
  "node_modules/jose/dist/browser/lib/is_object.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    __name(isObjectLike, "isObjectLike");
    __name(isObject, "isObject");
  }
});

// node_modules/jose/dist/browser/runtime/bogus.js
var bogusWebCrypto, bogus_default;
var init_bogus = __esm({
  "node_modules/jose/dist/browser/runtime/bogus.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    bogusWebCrypto = [
      { hash: "SHA-256", name: "HMAC" },
      true,
      ["sign"]
    ];
    bogus_default = bogusWebCrypto;
  }
});

// node_modules/jose/dist/browser/runtime/aeskw.js
function checkKeySize(key, alg) {
  if (key.algorithm.length !== parseInt(alg.slice(1, 4), 10)) {
    throw new TypeError(`Invalid key size for alg: ${alg}`);
  }
}
function getCryptoKey(key, alg, usage) {
  if (isCryptoKey(key)) {
    checkEncCryptoKey(key, alg, usage);
    return key;
  }
  if (key instanceof Uint8Array) {
    return webcrypto_default.subtle.importKey("raw", key, "AES-KW", true, [usage]);
  }
  throw new TypeError(invalid_key_input_default(key, ...types, "Uint8Array"));
}
var wrap, unwrap;
var init_aeskw = __esm({
  "node_modules/jose/dist/browser/runtime/aeskw.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_bogus();
    init_webcrypto();
    init_crypto_key();
    init_invalid_key_input();
    init_is_key_like();
    __name(checkKeySize, "checkKeySize");
    __name(getCryptoKey, "getCryptoKey");
    wrap = /* @__PURE__ */ __name(async (alg, key, cek) => {
      const cryptoKey = await getCryptoKey(key, alg, "wrapKey");
      checkKeySize(cryptoKey, alg);
      const cryptoKeyCek = await webcrypto_default.subtle.importKey("raw", cek, ...bogus_default);
      return new Uint8Array(await webcrypto_default.subtle.wrapKey("raw", cryptoKeyCek, cryptoKey, "AES-KW"));
    }, "wrap");
    unwrap = /* @__PURE__ */ __name(async (alg, key, encryptedKey) => {
      const cryptoKey = await getCryptoKey(key, alg, "unwrapKey");
      checkKeySize(cryptoKey, alg);
      const cryptoKeyCek = await webcrypto_default.subtle.unwrapKey("raw", encryptedKey, cryptoKey, "AES-KW", ...bogus_default);
      return new Uint8Array(await webcrypto_default.subtle.exportKey("raw", cryptoKeyCek));
    }, "unwrap");
  }
});

// node_modules/jose/dist/browser/runtime/ecdhes.js
async function deriveKey(publicKey, privateKey, algorithm, keyLength, apu = new Uint8Array(0), apv = new Uint8Array(0)) {
  if (!isCryptoKey(publicKey)) {
    throw new TypeError(invalid_key_input_default(publicKey, ...types));
  }
  checkEncCryptoKey(publicKey, "ECDH");
  if (!isCryptoKey(privateKey)) {
    throw new TypeError(invalid_key_input_default(privateKey, ...types));
  }
  checkEncCryptoKey(privateKey, "ECDH", "deriveBits");
  const value = concat(lengthAndInput(encoder.encode(algorithm)), lengthAndInput(apu), lengthAndInput(apv), uint32be(keyLength));
  let length;
  if (publicKey.algorithm.name === "X25519") {
    length = 256;
  } else if (publicKey.algorithm.name === "X448") {
    length = 448;
  } else {
    length = Math.ceil(parseInt(publicKey.algorithm.namedCurve.substr(-3), 10) / 8) << 3;
  }
  const sharedSecret = new Uint8Array(await webcrypto_default.subtle.deriveBits({
    name: publicKey.algorithm.name,
    public: publicKey
  }, privateKey, length));
  return concatKdf(sharedSecret, keyLength, value);
}
async function generateEpk(key) {
  if (!isCryptoKey(key)) {
    throw new TypeError(invalid_key_input_default(key, ...types));
  }
  return webcrypto_default.subtle.generateKey(key.algorithm, true, ["deriveBits"]);
}
function ecdhAllowed(key) {
  if (!isCryptoKey(key)) {
    throw new TypeError(invalid_key_input_default(key, ...types));
  }
  return ["P-256", "P-384", "P-521"].includes(key.algorithm.namedCurve) || key.algorithm.name === "X25519" || key.algorithm.name === "X448";
}
var init_ecdhes = __esm({
  "node_modules/jose/dist/browser/runtime/ecdhes.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_buffer_utils();
    init_webcrypto();
    init_crypto_key();
    init_invalid_key_input();
    init_is_key_like();
    __name(deriveKey, "deriveKey");
    __name(generateEpk, "generateEpk");
    __name(ecdhAllowed, "ecdhAllowed");
  }
});

// node_modules/jose/dist/browser/lib/check_p2s.js
function checkP2s(p2s2) {
  if (!(p2s2 instanceof Uint8Array) || p2s2.length < 8) {
    throw new JWEInvalid("PBES2 Salt Input must be 8 or more octets");
  }
}
var init_check_p2s = __esm({
  "node_modules/jose/dist/browser/lib/check_p2s.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_errors();
    __name(checkP2s, "checkP2s");
  }
});

// node_modules/jose/dist/browser/runtime/pbes2kw.js
function getCryptoKey2(key, alg) {
  if (key instanceof Uint8Array) {
    return webcrypto_default.subtle.importKey("raw", key, "PBKDF2", false, ["deriveBits"]);
  }
  if (isCryptoKey(key)) {
    checkEncCryptoKey(key, alg, "deriveBits", "deriveKey");
    return key;
  }
  throw new TypeError(invalid_key_input_default(key, ...types, "Uint8Array"));
}
async function deriveKey2(p2s2, alg, p2c, key) {
  checkP2s(p2s2);
  const salt = p2s(alg, p2s2);
  const keylen = parseInt(alg.slice(13, 16), 10);
  const subtleAlg = {
    hash: `SHA-${alg.slice(8, 11)}`,
    iterations: p2c,
    name: "PBKDF2",
    salt
  };
  const wrapAlg = {
    length: keylen,
    name: "AES-KW"
  };
  const cryptoKey = await getCryptoKey2(key, alg);
  if (cryptoKey.usages.includes("deriveBits")) {
    return new Uint8Array(await webcrypto_default.subtle.deriveBits(subtleAlg, cryptoKey, keylen));
  }
  if (cryptoKey.usages.includes("deriveKey")) {
    return webcrypto_default.subtle.deriveKey(subtleAlg, cryptoKey, wrapAlg, false, ["wrapKey", "unwrapKey"]);
  }
  throw new TypeError('PBKDF2 key "usages" must include "deriveBits" or "deriveKey"');
}
var encrypt, decrypt2;
var init_pbes2kw = __esm({
  "node_modules/jose/dist/browser/runtime/pbes2kw.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_random();
    init_buffer_utils();
    init_base64url();
    init_aeskw();
    init_check_p2s();
    init_webcrypto();
    init_crypto_key();
    init_invalid_key_input();
    init_is_key_like();
    __name(getCryptoKey2, "getCryptoKey");
    __name(deriveKey2, "deriveKey");
    encrypt = /* @__PURE__ */ __name(async (alg, key, cek, p2c = 2048, p2s2 = random_default(new Uint8Array(16))) => {
      const derived = await deriveKey2(p2s2, alg, p2c, key);
      const encryptedKey = await wrap(alg.slice(-6), derived, cek);
      return { encryptedKey, p2c, p2s: encode(p2s2) };
    }, "encrypt");
    decrypt2 = /* @__PURE__ */ __name(async (alg, key, encryptedKey, p2c, p2s2) => {
      const derived = await deriveKey2(p2s2, alg, p2c, key);
      return unwrap(alg.slice(-6), derived, encryptedKey);
    }, "decrypt");
  }
});

// node_modules/jose/dist/browser/runtime/subtle_rsaes.js
function subtleRsaEs(alg) {
  switch (alg) {
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512":
      return "RSA-OAEP";
    default:
      throw new JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
  }
}
var init_subtle_rsaes = __esm({
  "node_modules/jose/dist/browser/runtime/subtle_rsaes.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_errors();
    __name(subtleRsaEs, "subtleRsaEs");
  }
});

// node_modules/jose/dist/browser/runtime/check_key_length.js
var check_key_length_default;
var init_check_key_length = __esm({
  "node_modules/jose/dist/browser/runtime/check_key_length.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    check_key_length_default = /* @__PURE__ */ __name((alg, key) => {
      if (alg.startsWith("RS") || alg.startsWith("PS")) {
        const { modulusLength } = key.algorithm;
        if (typeof modulusLength !== "number" || modulusLength < 2048) {
          throw new TypeError(`${alg} requires key modulusLength to be 2048 bits or larger`);
        }
      }
    }, "default");
  }
});

// node_modules/jose/dist/browser/runtime/rsaes.js
var encrypt2, decrypt3;
var init_rsaes = __esm({
  "node_modules/jose/dist/browser/runtime/rsaes.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_subtle_rsaes();
    init_bogus();
    init_webcrypto();
    init_crypto_key();
    init_check_key_length();
    init_invalid_key_input();
    init_is_key_like();
    encrypt2 = /* @__PURE__ */ __name(async (alg, key, cek) => {
      if (!isCryptoKey(key)) {
        throw new TypeError(invalid_key_input_default(key, ...types));
      }
      checkEncCryptoKey(key, alg, "encrypt", "wrapKey");
      check_key_length_default(alg, key);
      if (key.usages.includes("encrypt")) {
        return new Uint8Array(await webcrypto_default.subtle.encrypt(subtleRsaEs(alg), key, cek));
      }
      if (key.usages.includes("wrapKey")) {
        const cryptoKeyCek = await webcrypto_default.subtle.importKey("raw", cek, ...bogus_default);
        return new Uint8Array(await webcrypto_default.subtle.wrapKey("raw", cryptoKeyCek, key, subtleRsaEs(alg)));
      }
      throw new TypeError('RSA-OAEP key "usages" must include "encrypt" or "wrapKey" for this operation');
    }, "encrypt");
    decrypt3 = /* @__PURE__ */ __name(async (alg, key, encryptedKey) => {
      if (!isCryptoKey(key)) {
        throw new TypeError(invalid_key_input_default(key, ...types));
      }
      checkEncCryptoKey(key, alg, "decrypt", "unwrapKey");
      check_key_length_default(alg, key);
      if (key.usages.includes("decrypt")) {
        return new Uint8Array(await webcrypto_default.subtle.decrypt(subtleRsaEs(alg), key, encryptedKey));
      }
      if (key.usages.includes("unwrapKey")) {
        const cryptoKeyCek = await webcrypto_default.subtle.unwrapKey("raw", encryptedKey, key, subtleRsaEs(alg), ...bogus_default);
        return new Uint8Array(await webcrypto_default.subtle.exportKey("raw", cryptoKeyCek));
      }
      throw new TypeError('RSA-OAEP key "usages" must include "decrypt" or "unwrapKey" for this operation');
    }, "decrypt");
  }
});

// node_modules/jose/dist/browser/lib/is_jwk.js
function isJWK(key) {
  return isObject(key) && typeof key.kty === "string";
}
function isPrivateJWK(key) {
  return key.kty !== "oct" && typeof key.d === "string";
}
function isPublicJWK(key) {
  return key.kty !== "oct" && typeof key.d === "undefined";
}
function isSecretJWK(key) {
  return isJWK(key) && key.kty === "oct" && typeof key.k === "string";
}
var init_is_jwk = __esm({
  "node_modules/jose/dist/browser/lib/is_jwk.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_is_object();
    __name(isJWK, "isJWK");
    __name(isPrivateJWK, "isPrivateJWK");
    __name(isPublicJWK, "isPublicJWK");
    __name(isSecretJWK, "isSecretJWK");
  }
});

// node_modules/jose/dist/browser/runtime/jwk_to_key.js
function subtleMapping(jwk) {
  let algorithm;
  let keyUsages;
  switch (jwk.kty) {
    case "RSA": {
      switch (jwk.alg) {
        case "PS256":
        case "PS384":
        case "PS512":
          algorithm = { name: "RSA-PSS", hash: `SHA-${jwk.alg.slice(-3)}` };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "RS256":
        case "RS384":
        case "RS512":
          algorithm = { name: "RSASSA-PKCS1-v1_5", hash: `SHA-${jwk.alg.slice(-3)}` };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "RSA-OAEP":
        case "RSA-OAEP-256":
        case "RSA-OAEP-384":
        case "RSA-OAEP-512":
          algorithm = {
            name: "RSA-OAEP",
            hash: `SHA-${parseInt(jwk.alg.slice(-3), 10) || 1}`
          };
          keyUsages = jwk.d ? ["decrypt", "unwrapKey"] : ["encrypt", "wrapKey"];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    case "EC": {
      switch (jwk.alg) {
        case "ES256":
          algorithm = { name: "ECDSA", namedCurve: "P-256" };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ES384":
          algorithm = { name: "ECDSA", namedCurve: "P-384" };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ES512":
          algorithm = { name: "ECDSA", namedCurve: "P-521" };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW":
          algorithm = { name: "ECDH", namedCurve: jwk.crv };
          keyUsages = jwk.d ? ["deriveBits"] : [];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    case "OKP": {
      switch (jwk.alg) {
        case "Ed25519":
          algorithm = { name: "Ed25519" };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "EdDSA":
          algorithm = { name: jwk.crv };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW":
          algorithm = { name: jwk.crv };
          keyUsages = jwk.d ? ["deriveBits"] : [];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
      }
      break;
    }
    default:
      throw new JOSENotSupported('Invalid or unsupported JWK "kty" (Key Type) Parameter value');
  }
  return { algorithm, keyUsages };
}
var parse, jwk_to_key_default;
var init_jwk_to_key = __esm({
  "node_modules/jose/dist/browser/runtime/jwk_to_key.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_webcrypto();
    init_errors();
    __name(subtleMapping, "subtleMapping");
    parse = /* @__PURE__ */ __name(async (jwk) => {
      if (!jwk.alg) {
        throw new TypeError('"alg" argument is required when "jwk.alg" is not present');
      }
      const { algorithm, keyUsages } = subtleMapping(jwk);
      const rest = [
        algorithm,
        jwk.ext ?? false,
        jwk.key_ops ?? keyUsages
      ];
      const keyData = { ...jwk };
      delete keyData.alg;
      delete keyData.use;
      return webcrypto_default.subtle.importKey("jwk", keyData, ...rest);
    }, "parse");
    jwk_to_key_default = parse;
  }
});

// node_modules/jose/dist/browser/runtime/normalize_key.js
var exportKeyValue, privCache, pubCache, isKeyObject, importAndCache, normalizePublicKey, normalizePrivateKey, normalize_key_default;
var init_normalize_key = __esm({
  "node_modules/jose/dist/browser/runtime/normalize_key.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_is_jwk();
    init_base64url();
    init_jwk_to_key();
    exportKeyValue = /* @__PURE__ */ __name((k) => decode(k), "exportKeyValue");
    isKeyObject = /* @__PURE__ */ __name((key) => {
      return key?.[Symbol.toStringTag] === "KeyObject";
    }, "isKeyObject");
    importAndCache = /* @__PURE__ */ __name(async (cache, key, jwk, alg, freeze = false) => {
      let cached = cache.get(key);
      if (cached?.[alg]) {
        return cached[alg];
      }
      const cryptoKey = await jwk_to_key_default({ ...jwk, alg });
      if (freeze)
        Object.freeze(key);
      if (!cached) {
        cache.set(key, { [alg]: cryptoKey });
      } else {
        cached[alg] = cryptoKey;
      }
      return cryptoKey;
    }, "importAndCache");
    normalizePublicKey = /* @__PURE__ */ __name((key, alg) => {
      if (isKeyObject(key)) {
        let jwk = key.export({ format: "jwk" });
        delete jwk.d;
        delete jwk.dp;
        delete jwk.dq;
        delete jwk.p;
        delete jwk.q;
        delete jwk.qi;
        if (jwk.k) {
          return exportKeyValue(jwk.k);
        }
        pubCache || (pubCache = /* @__PURE__ */ new WeakMap());
        return importAndCache(pubCache, key, jwk, alg);
      }
      if (isJWK(key)) {
        if (key.k)
          return decode(key.k);
        pubCache || (pubCache = /* @__PURE__ */ new WeakMap());
        const cryptoKey = importAndCache(pubCache, key, key, alg, true);
        return cryptoKey;
      }
      return key;
    }, "normalizePublicKey");
    normalizePrivateKey = /* @__PURE__ */ __name((key, alg) => {
      if (isKeyObject(key)) {
        let jwk = key.export({ format: "jwk" });
        if (jwk.k) {
          return exportKeyValue(jwk.k);
        }
        privCache || (privCache = /* @__PURE__ */ new WeakMap());
        return importAndCache(privCache, key, jwk, alg);
      }
      if (isJWK(key)) {
        if (key.k)
          return decode(key.k);
        privCache || (privCache = /* @__PURE__ */ new WeakMap());
        const cryptoKey = importAndCache(privCache, key, key, alg, true);
        return cryptoKey;
      }
      return key;
    }, "normalizePrivateKey");
    normalize_key_default = { normalizePublicKey, normalizePrivateKey };
  }
});

// node_modules/jose/dist/browser/lib/cek.js
function bitLength2(alg) {
  switch (alg) {
    case "A128GCM":
      return 128;
    case "A192GCM":
      return 192;
    case "A256GCM":
    case "A128CBC-HS256":
      return 256;
    case "A192CBC-HS384":
      return 384;
    case "A256CBC-HS512":
      return 512;
    default:
      throw new JOSENotSupported(`Unsupported JWE Algorithm: ${alg}`);
  }
}
var cek_default;
var init_cek = __esm({
  "node_modules/jose/dist/browser/lib/cek.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_errors();
    init_random();
    __name(bitLength2, "bitLength");
    cek_default = /* @__PURE__ */ __name((alg) => random_default(new Uint8Array(bitLength2(alg) >> 3)), "default");
  }
});

// node_modules/jose/dist/browser/lib/format_pem.js
var format_pem_default;
var init_format_pem = __esm({
  "node_modules/jose/dist/browser/lib/format_pem.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    format_pem_default = /* @__PURE__ */ __name((b64, descriptor) => {
      const newlined = (b64.match(/.{1,64}/g) || []).join("\n");
      return `-----BEGIN ${descriptor}-----
${newlined}
-----END ${descriptor}-----`;
    }, "default");
  }
});

// node_modules/jose/dist/browser/runtime/asn1.js
function getElement(seq) {
  const result = [];
  let next = 0;
  while (next < seq.length) {
    const nextPart = parseElement(seq.subarray(next));
    result.push(nextPart);
    next += nextPart.byteLength;
  }
  return result;
}
function parseElement(bytes) {
  let position = 0;
  let tag2 = bytes[0] & 31;
  position++;
  if (tag2 === 31) {
    tag2 = 0;
    while (bytes[position] >= 128) {
      tag2 = tag2 * 128 + bytes[position] - 128;
      position++;
    }
    tag2 = tag2 * 128 + bytes[position] - 128;
    position++;
  }
  let length = 0;
  if (bytes[position] < 128) {
    length = bytes[position];
    position++;
  } else if (length === 128) {
    length = 0;
    while (bytes[position + length] !== 0 || bytes[position + length + 1] !== 0) {
      if (length > bytes.byteLength) {
        throw new TypeError("invalid indefinite form length");
      }
      length++;
    }
    const byteLength2 = position + length + 2;
    return {
      byteLength: byteLength2,
      contents: bytes.subarray(position, position + length),
      raw: bytes.subarray(0, byteLength2)
    };
  } else {
    const numberOfDigits = bytes[position] & 127;
    position++;
    length = 0;
    for (let i = 0; i < numberOfDigits; i++) {
      length = length * 256 + bytes[position];
      position++;
    }
  }
  const byteLength = position + length;
  return {
    byteLength,
    contents: bytes.subarray(position, byteLength),
    raw: bytes.subarray(0, byteLength)
  };
}
function spkiFromX509(buf) {
  const tbsCertificate = getElement(getElement(parseElement(buf).contents)[0].contents);
  return encodeBase64(tbsCertificate[tbsCertificate[0].raw[0] === 160 ? 6 : 5].raw);
}
function getSPKI(x509) {
  const pem = x509.replace(/(?:-----(?:BEGIN|END) CERTIFICATE-----|\s)/g, "");
  const raw = decodeBase64(pem);
  return format_pem_default(spkiFromX509(raw), "PUBLIC KEY");
}
var genericExport, toSPKI, toPKCS8, findOid, getNamedCurve2, genericImport, fromPKCS8, fromSPKI, fromX509;
var init_asn1 = __esm({
  "node_modules/jose/dist/browser/runtime/asn1.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_webcrypto();
    init_invalid_key_input();
    init_base64url();
    init_format_pem();
    init_errors();
    init_is_key_like();
    genericExport = /* @__PURE__ */ __name(async (keyType, keyFormat, key) => {
      if (!isCryptoKey(key)) {
        throw new TypeError(invalid_key_input_default(key, ...types));
      }
      if (!key.extractable) {
        throw new TypeError("CryptoKey is not extractable");
      }
      if (key.type !== keyType) {
        throw new TypeError(`key is not a ${keyType} key`);
      }
      return format_pem_default(encodeBase64(new Uint8Array(await webcrypto_default.subtle.exportKey(keyFormat, key))), `${keyType.toUpperCase()} KEY`);
    }, "genericExport");
    toSPKI = /* @__PURE__ */ __name((key) => {
      return genericExport("public", "spki", key);
    }, "toSPKI");
    toPKCS8 = /* @__PURE__ */ __name((key) => {
      return genericExport("private", "pkcs8", key);
    }, "toPKCS8");
    findOid = /* @__PURE__ */ __name((keyData, oid, from = 0) => {
      if (from === 0) {
        oid.unshift(oid.length);
        oid.unshift(6);
      }
      const i = keyData.indexOf(oid[0], from);
      if (i === -1)
        return false;
      const sub = keyData.subarray(i, i + oid.length);
      if (sub.length !== oid.length)
        return false;
      return sub.every((value, index) => value === oid[index]) || findOid(keyData, oid, i + 1);
    }, "findOid");
    getNamedCurve2 = /* @__PURE__ */ __name((keyData) => {
      switch (true) {
        case findOid(keyData, [42, 134, 72, 206, 61, 3, 1, 7]):
          return "P-256";
        case findOid(keyData, [43, 129, 4, 0, 34]):
          return "P-384";
        case findOid(keyData, [43, 129, 4, 0, 35]):
          return "P-521";
        case findOid(keyData, [43, 101, 110]):
          return "X25519";
        case findOid(keyData, [43, 101, 111]):
          return "X448";
        case findOid(keyData, [43, 101, 112]):
          return "Ed25519";
        case findOid(keyData, [43, 101, 113]):
          return "Ed448";
        default:
          throw new JOSENotSupported("Invalid or unsupported EC Key Curve or OKP Key Sub Type");
      }
    }, "getNamedCurve");
    genericImport = /* @__PURE__ */ __name(async (replace, keyFormat, pem, alg, options) => {
      let algorithm;
      let keyUsages;
      const keyData = new Uint8Array(atob(pem.replace(replace, "")).split("").map((c) => c.charCodeAt(0)));
      const isPublic = keyFormat === "spki";
      switch (alg) {
        case "PS256":
        case "PS384":
        case "PS512":
          algorithm = { name: "RSA-PSS", hash: `SHA-${alg.slice(-3)}` };
          keyUsages = isPublic ? ["verify"] : ["sign"];
          break;
        case "RS256":
        case "RS384":
        case "RS512":
          algorithm = { name: "RSASSA-PKCS1-v1_5", hash: `SHA-${alg.slice(-3)}` };
          keyUsages = isPublic ? ["verify"] : ["sign"];
          break;
        case "RSA-OAEP":
        case "RSA-OAEP-256":
        case "RSA-OAEP-384":
        case "RSA-OAEP-512":
          algorithm = {
            name: "RSA-OAEP",
            hash: `SHA-${parseInt(alg.slice(-3), 10) || 1}`
          };
          keyUsages = isPublic ? ["encrypt", "wrapKey"] : ["decrypt", "unwrapKey"];
          break;
        case "ES256":
          algorithm = { name: "ECDSA", namedCurve: "P-256" };
          keyUsages = isPublic ? ["verify"] : ["sign"];
          break;
        case "ES384":
          algorithm = { name: "ECDSA", namedCurve: "P-384" };
          keyUsages = isPublic ? ["verify"] : ["sign"];
          break;
        case "ES512":
          algorithm = { name: "ECDSA", namedCurve: "P-521" };
          keyUsages = isPublic ? ["verify"] : ["sign"];
          break;
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW": {
          const namedCurve = getNamedCurve2(keyData);
          algorithm = namedCurve.startsWith("P-") ? { name: "ECDH", namedCurve } : { name: namedCurve };
          keyUsages = isPublic ? [] : ["deriveBits"];
          break;
        }
        case "Ed25519":
          algorithm = { name: "Ed25519" };
          keyUsages = isPublic ? ["verify"] : ["sign"];
          break;
        case "EdDSA":
          algorithm = { name: getNamedCurve2(keyData) };
          keyUsages = isPublic ? ["verify"] : ["sign"];
          break;
        default:
          throw new JOSENotSupported('Invalid or unsupported "alg" (Algorithm) value');
      }
      return webcrypto_default.subtle.importKey(keyFormat, keyData, algorithm, options?.extractable ?? false, keyUsages);
    }, "genericImport");
    fromPKCS8 = /* @__PURE__ */ __name((pem, alg, options) => {
      return genericImport(/(?:-----(?:BEGIN|END) PRIVATE KEY-----|\s)/g, "pkcs8", pem, alg, options);
    }, "fromPKCS8");
    fromSPKI = /* @__PURE__ */ __name((pem, alg, options) => {
      return genericImport(/(?:-----(?:BEGIN|END) PUBLIC KEY-----|\s)/g, "spki", pem, alg, options);
    }, "fromSPKI");
    __name(getElement, "getElement");
    __name(parseElement, "parseElement");
    __name(spkiFromX509, "spkiFromX509");
    __name(getSPKI, "getSPKI");
    fromX509 = /* @__PURE__ */ __name((pem, alg, options) => {
      let spki;
      try {
        spki = getSPKI(pem);
      } catch (cause) {
        throw new TypeError("Failed to parse the X.509 certificate", { cause });
      }
      return fromSPKI(spki, alg, options);
    }, "fromX509");
  }
});

// node_modules/jose/dist/browser/key/import.js
async function importSPKI(spki, alg, options) {
  if (typeof spki !== "string" || spki.indexOf("-----BEGIN PUBLIC KEY-----") !== 0) {
    throw new TypeError('"spki" must be SPKI formatted string');
  }
  return fromSPKI(spki, alg, options);
}
async function importX509(x509, alg, options) {
  if (typeof x509 !== "string" || x509.indexOf("-----BEGIN CERTIFICATE-----") !== 0) {
    throw new TypeError('"x509" must be X.509 formatted string');
  }
  return fromX509(x509, alg, options);
}
async function importPKCS8(pkcs8, alg, options) {
  if (typeof pkcs8 !== "string" || pkcs8.indexOf("-----BEGIN PRIVATE KEY-----") !== 0) {
    throw new TypeError('"pkcs8" must be PKCS#8 formatted string');
  }
  return fromPKCS8(pkcs8, alg, options);
}
async function importJWK(jwk, alg) {
  if (!isObject(jwk)) {
    throw new TypeError("JWK must be an object");
  }
  alg || (alg = jwk.alg);
  switch (jwk.kty) {
    case "oct":
      if (typeof jwk.k !== "string" || !jwk.k) {
        throw new TypeError('missing "k" (Key Value) Parameter value');
      }
      return decode(jwk.k);
    case "RSA":
      if ("oth" in jwk && jwk.oth !== void 0) {
        throw new JOSENotSupported('RSA JWK "oth" (Other Primes Info) Parameter value is not supported');
      }
    case "EC":
    case "OKP":
      return jwk_to_key_default({ ...jwk, alg });
    default:
      throw new JOSENotSupported('Unsupported "kty" (Key Type) Parameter value');
  }
}
var init_import = __esm({
  "node_modules/jose/dist/browser/key/import.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_base64url();
    init_asn1();
    init_jwk_to_key();
    init_errors();
    init_is_object();
    __name(importSPKI, "importSPKI");
    __name(importX509, "importX509");
    __name(importPKCS8, "importPKCS8");
    __name(importJWK, "importJWK");
  }
});

// node_modules/jose/dist/browser/lib/check_key_type.js
function checkKeyType(allowJwk, alg, key, usage) {
  const symmetric = alg.startsWith("HS") || alg === "dir" || alg.startsWith("PBES2") || /^A\d{3}(?:GCM)?KW$/.test(alg);
  if (symmetric) {
    symmetricTypeCheck(alg, key, usage, allowJwk);
  } else {
    asymmetricTypeCheck(alg, key, usage, allowJwk);
  }
}
var tag, jwkMatchesOp, symmetricTypeCheck, asymmetricTypeCheck, check_key_type_default, checkKeyTypeWithJwk;
var init_check_key_type = __esm({
  "node_modules/jose/dist/browser/lib/check_key_type.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_invalid_key_input();
    init_is_key_like();
    init_is_jwk();
    tag = /* @__PURE__ */ __name((key) => key?.[Symbol.toStringTag], "tag");
    jwkMatchesOp = /* @__PURE__ */ __name((alg, key, usage) => {
      if (key.use !== void 0 && key.use !== "sig") {
        throw new TypeError("Invalid key for this operation, when present its use must be sig");
      }
      if (key.key_ops !== void 0 && key.key_ops.includes?.(usage) !== true) {
        throw new TypeError(`Invalid key for this operation, when present its key_ops must include ${usage}`);
      }
      if (key.alg !== void 0 && key.alg !== alg) {
        throw new TypeError(`Invalid key for this operation, when present its alg must be ${alg}`);
      }
      return true;
    }, "jwkMatchesOp");
    symmetricTypeCheck = /* @__PURE__ */ __name((alg, key, usage, allowJwk) => {
      if (key instanceof Uint8Array)
        return;
      if (allowJwk && isJWK(key)) {
        if (isSecretJWK(key) && jwkMatchesOp(alg, key, usage))
          return;
        throw new TypeError(`JSON Web Key for symmetric algorithms must have JWK "kty" (Key Type) equal to "oct" and the JWK "k" (Key Value) present`);
      }
      if (!is_key_like_default(key)) {
        throw new TypeError(withAlg(alg, key, ...types, "Uint8Array", allowJwk ? "JSON Web Key" : null));
      }
      if (key.type !== "secret") {
        throw new TypeError(`${tag(key)} instances for symmetric algorithms must be of type "secret"`);
      }
    }, "symmetricTypeCheck");
    asymmetricTypeCheck = /* @__PURE__ */ __name((alg, key, usage, allowJwk) => {
      if (allowJwk && isJWK(key)) {
        switch (usage) {
          case "sign":
            if (isPrivateJWK(key) && jwkMatchesOp(alg, key, usage))
              return;
            throw new TypeError(`JSON Web Key for this operation be a private JWK`);
          case "verify":
            if (isPublicJWK(key) && jwkMatchesOp(alg, key, usage))
              return;
            throw new TypeError(`JSON Web Key for this operation be a public JWK`);
        }
      }
      if (!is_key_like_default(key)) {
        throw new TypeError(withAlg(alg, key, ...types, allowJwk ? "JSON Web Key" : null));
      }
      if (key.type === "secret") {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithms must not be of type "secret"`);
      }
      if (usage === "sign" && key.type === "public") {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm signing must be of type "private"`);
      }
      if (usage === "decrypt" && key.type === "public") {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm decryption must be of type "private"`);
      }
      if (key.algorithm && usage === "verify" && key.type === "private") {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm verifying must be of type "public"`);
      }
      if (key.algorithm && usage === "encrypt" && key.type === "private") {
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm encryption must be of type "public"`);
      }
    }, "asymmetricTypeCheck");
    __name(checkKeyType, "checkKeyType");
    check_key_type_default = checkKeyType.bind(void 0, false);
    checkKeyTypeWithJwk = checkKeyType.bind(void 0, true);
  }
});

// node_modules/jose/dist/browser/runtime/encrypt.js
async function cbcEncrypt(enc, plaintext, cek, iv, aad) {
  if (!(cek instanceof Uint8Array)) {
    throw new TypeError(invalid_key_input_default(cek, "Uint8Array"));
  }
  const keySize = parseInt(enc.slice(1, 4), 10);
  const encKey = await webcrypto_default.subtle.importKey("raw", cek.subarray(keySize >> 3), "AES-CBC", false, ["encrypt"]);
  const macKey = await webcrypto_default.subtle.importKey("raw", cek.subarray(0, keySize >> 3), {
    hash: `SHA-${keySize << 1}`,
    name: "HMAC"
  }, false, ["sign"]);
  const ciphertext = new Uint8Array(await webcrypto_default.subtle.encrypt({
    iv,
    name: "AES-CBC"
  }, encKey, plaintext));
  const macData = concat(aad, iv, ciphertext, uint64be(aad.length << 3));
  const tag2 = new Uint8Array((await webcrypto_default.subtle.sign("HMAC", macKey, macData)).slice(0, keySize >> 3));
  return { ciphertext, tag: tag2, iv };
}
async function gcmEncrypt(enc, plaintext, cek, iv, aad) {
  let encKey;
  if (cek instanceof Uint8Array) {
    encKey = await webcrypto_default.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  } else {
    checkEncCryptoKey(cek, enc, "encrypt");
    encKey = cek;
  }
  const encrypted = new Uint8Array(await webcrypto_default.subtle.encrypt({
    additionalData: aad,
    iv,
    name: "AES-GCM",
    tagLength: 128
  }, encKey, plaintext));
  const tag2 = encrypted.slice(-16);
  const ciphertext = encrypted.slice(0, -16);
  return { ciphertext, tag: tag2, iv };
}
var encrypt3, encrypt_default;
var init_encrypt = __esm({
  "node_modules/jose/dist/browser/runtime/encrypt.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_buffer_utils();
    init_check_iv_length();
    init_check_cek_length();
    init_webcrypto();
    init_crypto_key();
    init_invalid_key_input();
    init_iv();
    init_errors();
    init_is_key_like();
    __name(cbcEncrypt, "cbcEncrypt");
    __name(gcmEncrypt, "gcmEncrypt");
    encrypt3 = /* @__PURE__ */ __name(async (enc, plaintext, cek, iv, aad) => {
      if (!isCryptoKey(cek) && !(cek instanceof Uint8Array)) {
        throw new TypeError(invalid_key_input_default(cek, ...types, "Uint8Array"));
      }
      if (iv) {
        check_iv_length_default(enc, iv);
      } else {
        iv = iv_default(enc);
      }
      switch (enc) {
        case "A128CBC-HS256":
        case "A192CBC-HS384":
        case "A256CBC-HS512":
          if (cek instanceof Uint8Array) {
            check_cek_length_default(cek, parseInt(enc.slice(-3), 10));
          }
          return cbcEncrypt(enc, plaintext, cek, iv, aad);
        case "A128GCM":
        case "A192GCM":
        case "A256GCM":
          if (cek instanceof Uint8Array) {
            check_cek_length_default(cek, parseInt(enc.slice(1, 4), 10));
          }
          return gcmEncrypt(enc, plaintext, cek, iv, aad);
        default:
          throw new JOSENotSupported("Unsupported JWE Content Encryption Algorithm");
      }
    }, "encrypt");
    encrypt_default = encrypt3;
  }
});

// node_modules/jose/dist/browser/lib/aesgcmkw.js
async function wrap2(alg, key, cek, iv) {
  const jweAlgorithm = alg.slice(0, 7);
  const wrapped = await encrypt_default(jweAlgorithm, cek, key, iv, new Uint8Array(0));
  return {
    encryptedKey: wrapped.ciphertext,
    iv: encode(wrapped.iv),
    tag: encode(wrapped.tag)
  };
}
async function unwrap2(alg, key, encryptedKey, iv, tag2) {
  const jweAlgorithm = alg.slice(0, 7);
  return decrypt_default(jweAlgorithm, key, encryptedKey, iv, tag2, new Uint8Array(0));
}
var init_aesgcmkw = __esm({
  "node_modules/jose/dist/browser/lib/aesgcmkw.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_encrypt();
    init_decrypt();
    init_base64url();
    __name(wrap2, "wrap");
    __name(unwrap2, "unwrap");
  }
});

// node_modules/jose/dist/browser/lib/decrypt_key_management.js
async function decryptKeyManagement(alg, key, encryptedKey, joseHeader, options) {
  check_key_type_default(alg, key, "decrypt");
  key = await normalize_key_default.normalizePrivateKey?.(key, alg) || key;
  switch (alg) {
    case "dir": {
      if (encryptedKey !== void 0)
        throw new JWEInvalid("Encountered unexpected JWE Encrypted Key");
      return key;
    }
    case "ECDH-ES":
      if (encryptedKey !== void 0)
        throw new JWEInvalid("Encountered unexpected JWE Encrypted Key");
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      if (!isObject(joseHeader.epk))
        throw new JWEInvalid(`JOSE Header "epk" (Ephemeral Public Key) missing or invalid`);
      if (!ecdhAllowed(key))
        throw new JOSENotSupported("ECDH with the provided key is not allowed or not supported by your javascript runtime");
      const epk = await importJWK(joseHeader.epk, alg);
      let partyUInfo;
      let partyVInfo;
      if (joseHeader.apu !== void 0) {
        if (typeof joseHeader.apu !== "string")
          throw new JWEInvalid(`JOSE Header "apu" (Agreement PartyUInfo) invalid`);
        try {
          partyUInfo = decode(joseHeader.apu);
        } catch {
          throw new JWEInvalid("Failed to base64url decode the apu");
        }
      }
      if (joseHeader.apv !== void 0) {
        if (typeof joseHeader.apv !== "string")
          throw new JWEInvalid(`JOSE Header "apv" (Agreement PartyVInfo) invalid`);
        try {
          partyVInfo = decode(joseHeader.apv);
        } catch {
          throw new JWEInvalid("Failed to base64url decode the apv");
        }
      }
      const sharedSecret = await deriveKey(epk, key, alg === "ECDH-ES" ? joseHeader.enc : alg, alg === "ECDH-ES" ? bitLength2(joseHeader.enc) : parseInt(alg.slice(-5, -2), 10), partyUInfo, partyVInfo);
      if (alg === "ECDH-ES")
        return sharedSecret;
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      return unwrap(alg.slice(-6), sharedSecret, encryptedKey);
    }
    case "RSA1_5":
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      return decrypt3(alg, key, encryptedKey);
    }
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      if (typeof joseHeader.p2c !== "number")
        throw new JWEInvalid(`JOSE Header "p2c" (PBES2 Count) missing or invalid`);
      const p2cLimit = options?.maxPBES2Count || 1e4;
      if (joseHeader.p2c > p2cLimit)
        throw new JWEInvalid(`JOSE Header "p2c" (PBES2 Count) out is of acceptable bounds`);
      if (typeof joseHeader.p2s !== "string")
        throw new JWEInvalid(`JOSE Header "p2s" (PBES2 Salt) missing or invalid`);
      let p2s2;
      try {
        p2s2 = decode(joseHeader.p2s);
      } catch {
        throw new JWEInvalid("Failed to base64url decode the p2s");
      }
      return decrypt2(alg, key, encryptedKey, joseHeader.p2c, p2s2);
    }
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      return unwrap(alg, key, encryptedKey);
    }
    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      if (encryptedKey === void 0)
        throw new JWEInvalid("JWE Encrypted Key missing");
      if (typeof joseHeader.iv !== "string")
        throw new JWEInvalid(`JOSE Header "iv" (Initialization Vector) missing or invalid`);
      if (typeof joseHeader.tag !== "string")
        throw new JWEInvalid(`JOSE Header "tag" (Authentication Tag) missing or invalid`);
      let iv;
      try {
        iv = decode(joseHeader.iv);
      } catch {
        throw new JWEInvalid("Failed to base64url decode the iv");
      }
      let tag2;
      try {
        tag2 = decode(joseHeader.tag);
      } catch {
        throw new JWEInvalid("Failed to base64url decode the tag");
      }
      return unwrap2(alg, key, encryptedKey, iv, tag2);
    }
    default: {
      throw new JOSENotSupported('Invalid or unsupported "alg" (JWE Algorithm) header value');
    }
  }
}
var decrypt_key_management_default;
var init_decrypt_key_management = __esm({
  "node_modules/jose/dist/browser/lib/decrypt_key_management.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_aeskw();
    init_ecdhes();
    init_pbes2kw();
    init_rsaes();
    init_base64url();
    init_normalize_key();
    init_errors();
    init_cek();
    init_import();
    init_check_key_type();
    init_is_object();
    init_aesgcmkw();
    __name(decryptKeyManagement, "decryptKeyManagement");
    decrypt_key_management_default = decryptKeyManagement;
  }
});

// node_modules/jose/dist/browser/lib/validate_crit.js
function validateCrit(Err, recognizedDefault, recognizedOption, protectedHeader, joseHeader) {
  if (joseHeader.crit !== void 0 && protectedHeader?.crit === void 0) {
    throw new Err('"crit" (Critical) Header Parameter MUST be integrity protected');
  }
  if (!protectedHeader || protectedHeader.crit === void 0) {
    return /* @__PURE__ */ new Set();
  }
  if (!Array.isArray(protectedHeader.crit) || protectedHeader.crit.length === 0 || protectedHeader.crit.some((input) => typeof input !== "string" || input.length === 0)) {
    throw new Err('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
  }
  let recognized;
  if (recognizedOption !== void 0) {
    recognized = new Map([...Object.entries(recognizedOption), ...recognizedDefault.entries()]);
  } else {
    recognized = recognizedDefault;
  }
  for (const parameter of protectedHeader.crit) {
    if (!recognized.has(parameter)) {
      throw new JOSENotSupported(`Extension Header Parameter "${parameter}" is not recognized`);
    }
    if (joseHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" is missing`);
    }
    if (recognized.get(parameter) && protectedHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" MUST be integrity protected`);
    }
  }
  return new Set(protectedHeader.crit);
}
var validate_crit_default;
var init_validate_crit = __esm({
  "node_modules/jose/dist/browser/lib/validate_crit.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_errors();
    __name(validateCrit, "validateCrit");
    validate_crit_default = validateCrit;
  }
});

// node_modules/jose/dist/browser/lib/validate_algorithms.js
var validateAlgorithms, validate_algorithms_default;
var init_validate_algorithms = __esm({
  "node_modules/jose/dist/browser/lib/validate_algorithms.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    validateAlgorithms = /* @__PURE__ */ __name((option, algorithms) => {
      if (algorithms !== void 0 && (!Array.isArray(algorithms) || algorithms.some((s) => typeof s !== "string"))) {
        throw new TypeError(`"${option}" option must be an array of strings`);
      }
      if (!algorithms) {
        return void 0;
      }
      return new Set(algorithms);
    }, "validateAlgorithms");
    validate_algorithms_default = validateAlgorithms;
  }
});

// node_modules/jose/dist/browser/jwe/flattened/decrypt.js
async function flattenedDecrypt(jwe, key, options) {
  if (!isObject(jwe)) {
    throw new JWEInvalid("Flattened JWE must be an object");
  }
  if (jwe.protected === void 0 && jwe.header === void 0 && jwe.unprotected === void 0) {
    throw new JWEInvalid("JOSE Header missing");
  }
  if (jwe.iv !== void 0 && typeof jwe.iv !== "string") {
    throw new JWEInvalid("JWE Initialization Vector incorrect type");
  }
  if (typeof jwe.ciphertext !== "string") {
    throw new JWEInvalid("JWE Ciphertext missing or incorrect type");
  }
  if (jwe.tag !== void 0 && typeof jwe.tag !== "string") {
    throw new JWEInvalid("JWE Authentication Tag incorrect type");
  }
  if (jwe.protected !== void 0 && typeof jwe.protected !== "string") {
    throw new JWEInvalid("JWE Protected Header incorrect type");
  }
  if (jwe.encrypted_key !== void 0 && typeof jwe.encrypted_key !== "string") {
    throw new JWEInvalid("JWE Encrypted Key incorrect type");
  }
  if (jwe.aad !== void 0 && typeof jwe.aad !== "string") {
    throw new JWEInvalid("JWE AAD incorrect type");
  }
  if (jwe.header !== void 0 && !isObject(jwe.header)) {
    throw new JWEInvalid("JWE Shared Unprotected Header incorrect type");
  }
  if (jwe.unprotected !== void 0 && !isObject(jwe.unprotected)) {
    throw new JWEInvalid("JWE Per-Recipient Unprotected Header incorrect type");
  }
  let parsedProt;
  if (jwe.protected) {
    try {
      const protectedHeader2 = decode(jwe.protected);
      parsedProt = JSON.parse(decoder.decode(protectedHeader2));
    } catch {
      throw new JWEInvalid("JWE Protected Header is invalid");
    }
  }
  if (!is_disjoint_default(parsedProt, jwe.header, jwe.unprotected)) {
    throw new JWEInvalid("JWE Protected, JWE Unprotected Header, and JWE Per-Recipient Unprotected Header Parameter names must be disjoint");
  }
  const joseHeader = {
    ...parsedProt,
    ...jwe.header,
    ...jwe.unprotected
  };
  validate_crit_default(JWEInvalid, /* @__PURE__ */ new Map(), options?.crit, parsedProt, joseHeader);
  if (joseHeader.zip !== void 0) {
    throw new JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported.');
  }
  const { alg, enc } = joseHeader;
  if (typeof alg !== "string" || !alg) {
    throw new JWEInvalid("missing JWE Algorithm (alg) in JWE Header");
  }
  if (typeof enc !== "string" || !enc) {
    throw new JWEInvalid("missing JWE Encryption Algorithm (enc) in JWE Header");
  }
  const keyManagementAlgorithms = options && validate_algorithms_default("keyManagementAlgorithms", options.keyManagementAlgorithms);
  const contentEncryptionAlgorithms = options && validate_algorithms_default("contentEncryptionAlgorithms", options.contentEncryptionAlgorithms);
  if (keyManagementAlgorithms && !keyManagementAlgorithms.has(alg) || !keyManagementAlgorithms && alg.startsWith("PBES2")) {
    throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter value not allowed');
  }
  if (contentEncryptionAlgorithms && !contentEncryptionAlgorithms.has(enc)) {
    throw new JOSEAlgNotAllowed('"enc" (Encryption Algorithm) Header Parameter value not allowed');
  }
  let encryptedKey;
  if (jwe.encrypted_key !== void 0) {
    try {
      encryptedKey = decode(jwe.encrypted_key);
    } catch {
      throw new JWEInvalid("Failed to base64url decode the encrypted_key");
    }
  }
  let resolvedKey = false;
  if (typeof key === "function") {
    key = await key(parsedProt, jwe);
    resolvedKey = true;
  }
  let cek;
  try {
    cek = await decrypt_key_management_default(alg, key, encryptedKey, joseHeader, options);
  } catch (err) {
    if (err instanceof TypeError || err instanceof JWEInvalid || err instanceof JOSENotSupported) {
      throw err;
    }
    cek = cek_default(enc);
  }
  let iv;
  let tag2;
  if (jwe.iv !== void 0) {
    try {
      iv = decode(jwe.iv);
    } catch {
      throw new JWEInvalid("Failed to base64url decode the iv");
    }
  }
  if (jwe.tag !== void 0) {
    try {
      tag2 = decode(jwe.tag);
    } catch {
      throw new JWEInvalid("Failed to base64url decode the tag");
    }
  }
  const protectedHeader = encoder.encode(jwe.protected ?? "");
  let additionalData;
  if (jwe.aad !== void 0) {
    additionalData = concat(protectedHeader, encoder.encode("."), encoder.encode(jwe.aad));
  } else {
    additionalData = protectedHeader;
  }
  let ciphertext;
  try {
    ciphertext = decode(jwe.ciphertext);
  } catch {
    throw new JWEInvalid("Failed to base64url decode the ciphertext");
  }
  const plaintext = await decrypt_default(enc, cek, ciphertext, iv, tag2, additionalData);
  const result = { plaintext };
  if (jwe.protected !== void 0) {
    result.protectedHeader = parsedProt;
  }
  if (jwe.aad !== void 0) {
    try {
      result.additionalAuthenticatedData = decode(jwe.aad);
    } catch {
      throw new JWEInvalid("Failed to base64url decode the aad");
    }
  }
  if (jwe.unprotected !== void 0) {
    result.sharedUnprotectedHeader = jwe.unprotected;
  }
  if (jwe.header !== void 0) {
    result.unprotectedHeader = jwe.header;
  }
  if (resolvedKey) {
    return { ...result, key };
  }
  return result;
}
var init_decrypt2 = __esm({
  "node_modules/jose/dist/browser/jwe/flattened/decrypt.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_base64url();
    init_decrypt();
    init_errors();
    init_is_disjoint();
    init_is_object();
    init_decrypt_key_management();
    init_buffer_utils();
    init_cek();
    init_validate_crit();
    init_validate_algorithms();
    __name(flattenedDecrypt, "flattenedDecrypt");
  }
});

// node_modules/jose/dist/browser/jwe/compact/decrypt.js
async function compactDecrypt(jwe, key, options) {
  if (jwe instanceof Uint8Array) {
    jwe = decoder.decode(jwe);
  }
  if (typeof jwe !== "string") {
    throw new JWEInvalid("Compact JWE must be a string or Uint8Array");
  }
  const { 0: protectedHeader, 1: encryptedKey, 2: iv, 3: ciphertext, 4: tag2, length } = jwe.split(".");
  if (length !== 5) {
    throw new JWEInvalid("Invalid Compact JWE");
  }
  const decrypted = await flattenedDecrypt({
    ciphertext,
    iv: iv || void 0,
    protected: protectedHeader,
    tag: tag2 || void 0,
    encrypted_key: encryptedKey || void 0
  }, key, options);
  const result = { plaintext: decrypted.plaintext, protectedHeader: decrypted.protectedHeader };
  if (typeof key === "function") {
    return { ...result, key: decrypted.key };
  }
  return result;
}
var init_decrypt3 = __esm({
  "node_modules/jose/dist/browser/jwe/compact/decrypt.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_decrypt2();
    init_errors();
    init_buffer_utils();
    __name(compactDecrypt, "compactDecrypt");
  }
});

// node_modules/jose/dist/browser/jwe/general/decrypt.js
async function generalDecrypt(jwe, key, options) {
  if (!isObject(jwe)) {
    throw new JWEInvalid("General JWE must be an object");
  }
  if (!Array.isArray(jwe.recipients) || !jwe.recipients.every(isObject)) {
    throw new JWEInvalid("JWE Recipients missing or incorrect type");
  }
  if (!jwe.recipients.length) {
    throw new JWEInvalid("JWE Recipients has no members");
  }
  for (const recipient of jwe.recipients) {
    try {
      return await flattenedDecrypt({
        aad: jwe.aad,
        ciphertext: jwe.ciphertext,
        encrypted_key: recipient.encrypted_key,
        header: recipient.header,
        iv: jwe.iv,
        protected: jwe.protected,
        tag: jwe.tag,
        unprotected: jwe.unprotected
      }, key, options);
    } catch {
    }
  }
  throw new JWEDecryptionFailed();
}
var init_decrypt4 = __esm({
  "node_modules/jose/dist/browser/jwe/general/decrypt.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_decrypt2();
    init_errors();
    init_is_object();
    __name(generalDecrypt, "generalDecrypt");
  }
});

// node_modules/jose/dist/browser/lib/private_symbols.js
var unprotected;
var init_private_symbols = __esm({
  "node_modules/jose/dist/browser/lib/private_symbols.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    unprotected = Symbol();
  }
});

// node_modules/jose/dist/browser/runtime/key_to_jwk.js
var keyToJWK, key_to_jwk_default;
var init_key_to_jwk = __esm({
  "node_modules/jose/dist/browser/runtime/key_to_jwk.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_webcrypto();
    init_invalid_key_input();
    init_base64url();
    init_is_key_like();
    keyToJWK = /* @__PURE__ */ __name(async (key) => {
      if (key instanceof Uint8Array) {
        return {
          kty: "oct",
          k: encode(key)
        };
      }
      if (!isCryptoKey(key)) {
        throw new TypeError(invalid_key_input_default(key, ...types, "Uint8Array"));
      }
      if (!key.extractable) {
        throw new TypeError("non-extractable CryptoKey cannot be exported as a JWK");
      }
      const { ext, key_ops, alg, use, ...jwk } = await webcrypto_default.subtle.exportKey("jwk", key);
      return jwk;
    }, "keyToJWK");
    key_to_jwk_default = keyToJWK;
  }
});

// node_modules/jose/dist/browser/key/export.js
async function exportSPKI(key) {
  return toSPKI(key);
}
async function exportPKCS8(key) {
  return toPKCS8(key);
}
async function exportJWK(key) {
  return key_to_jwk_default(key);
}
var init_export = __esm({
  "node_modules/jose/dist/browser/key/export.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_asn1();
    init_asn1();
    init_key_to_jwk();
    __name(exportSPKI, "exportSPKI");
    __name(exportPKCS8, "exportPKCS8");
    __name(exportJWK, "exportJWK");
  }
});

// node_modules/jose/dist/browser/lib/encrypt_key_management.js
async function encryptKeyManagement(alg, enc, key, providedCek, providedParameters = {}) {
  let encryptedKey;
  let parameters;
  let cek;
  check_key_type_default(alg, key, "encrypt");
  key = await normalize_key_default.normalizePublicKey?.(key, alg) || key;
  switch (alg) {
    case "dir": {
      cek = key;
      break;
    }
    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      if (!ecdhAllowed(key)) {
        throw new JOSENotSupported("ECDH with the provided key is not allowed or not supported by your javascript runtime");
      }
      const { apu, apv } = providedParameters;
      let { epk: ephemeralKey } = providedParameters;
      ephemeralKey || (ephemeralKey = (await generateEpk(key)).privateKey);
      const { x, y, crv, kty } = await exportJWK(ephemeralKey);
      const sharedSecret = await deriveKey(key, ephemeralKey, alg === "ECDH-ES" ? enc : alg, alg === "ECDH-ES" ? bitLength2(enc) : parseInt(alg.slice(-5, -2), 10), apu, apv);
      parameters = { epk: { x, crv, kty } };
      if (kty === "EC")
        parameters.epk.y = y;
      if (apu)
        parameters.apu = encode(apu);
      if (apv)
        parameters.apv = encode(apv);
      if (alg === "ECDH-ES") {
        cek = sharedSecret;
        break;
      }
      cek = providedCek || cek_default(enc);
      const kwAlg = alg.slice(-6);
      encryptedKey = await wrap(kwAlg, sharedSecret, cek);
      break;
    }
    case "RSA1_5":
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512": {
      cek = providedCek || cek_default(enc);
      encryptedKey = await encrypt2(alg, key, cek);
      break;
    }
    case "PBES2-HS256+A128KW":
    case "PBES2-HS384+A192KW":
    case "PBES2-HS512+A256KW": {
      cek = providedCek || cek_default(enc);
      const { p2c, p2s: p2s2 } = providedParameters;
      ({ encryptedKey, ...parameters } = await encrypt(alg, key, cek, p2c, p2s2));
      break;
    }
    case "A128KW":
    case "A192KW":
    case "A256KW": {
      cek = providedCek || cek_default(enc);
      encryptedKey = await wrap(alg, key, cek);
      break;
    }
    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW": {
      cek = providedCek || cek_default(enc);
      const { iv } = providedParameters;
      ({ encryptedKey, ...parameters } = await wrap2(alg, key, cek, iv));
      break;
    }
    default: {
      throw new JOSENotSupported('Invalid or unsupported "alg" (JWE Algorithm) header value');
    }
  }
  return { cek, encryptedKey, parameters };
}
var encrypt_key_management_default;
var init_encrypt_key_management = __esm({
  "node_modules/jose/dist/browser/lib/encrypt_key_management.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_aeskw();
    init_ecdhes();
    init_pbes2kw();
    init_rsaes();
    init_base64url();
    init_normalize_key();
    init_cek();
    init_errors();
    init_export();
    init_check_key_type();
    init_aesgcmkw();
    __name(encryptKeyManagement, "encryptKeyManagement");
    encrypt_key_management_default = encryptKeyManagement;
  }
});

// node_modules/jose/dist/browser/jwe/flattened/encrypt.js
var FlattenedEncrypt;
var init_encrypt2 = __esm({
  "node_modules/jose/dist/browser/jwe/flattened/encrypt.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_base64url();
    init_private_symbols();
    init_encrypt();
    init_encrypt_key_management();
    init_errors();
    init_is_disjoint();
    init_buffer_utils();
    init_validate_crit();
    FlattenedEncrypt = class {
      static {
        __name(this, "FlattenedEncrypt");
      }
      constructor(plaintext) {
        if (!(plaintext instanceof Uint8Array)) {
          throw new TypeError("plaintext must be an instance of Uint8Array");
        }
        this._plaintext = plaintext;
      }
      setKeyManagementParameters(parameters) {
        if (this._keyManagementParameters) {
          throw new TypeError("setKeyManagementParameters can only be called once");
        }
        this._keyManagementParameters = parameters;
        return this;
      }
      setProtectedHeader(protectedHeader) {
        if (this._protectedHeader) {
          throw new TypeError("setProtectedHeader can only be called once");
        }
        this._protectedHeader = protectedHeader;
        return this;
      }
      setSharedUnprotectedHeader(sharedUnprotectedHeader) {
        if (this._sharedUnprotectedHeader) {
          throw new TypeError("setSharedUnprotectedHeader can only be called once");
        }
        this._sharedUnprotectedHeader = sharedUnprotectedHeader;
        return this;
      }
      setUnprotectedHeader(unprotectedHeader) {
        if (this._unprotectedHeader) {
          throw new TypeError("setUnprotectedHeader can only be called once");
        }
        this._unprotectedHeader = unprotectedHeader;
        return this;
      }
      setAdditionalAuthenticatedData(aad) {
        this._aad = aad;
        return this;
      }
      setContentEncryptionKey(cek) {
        if (this._cek) {
          throw new TypeError("setContentEncryptionKey can only be called once");
        }
        this._cek = cek;
        return this;
      }
      setInitializationVector(iv) {
        if (this._iv) {
          throw new TypeError("setInitializationVector can only be called once");
        }
        this._iv = iv;
        return this;
      }
      async encrypt(key, options) {
        if (!this._protectedHeader && !this._unprotectedHeader && !this._sharedUnprotectedHeader) {
          throw new JWEInvalid("either setProtectedHeader, setUnprotectedHeader, or sharedUnprotectedHeader must be called before #encrypt()");
        }
        if (!is_disjoint_default(this._protectedHeader, this._unprotectedHeader, this._sharedUnprotectedHeader)) {
          throw new JWEInvalid("JWE Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint");
        }
        const joseHeader = {
          ...this._protectedHeader,
          ...this._unprotectedHeader,
          ...this._sharedUnprotectedHeader
        };
        validate_crit_default(JWEInvalid, /* @__PURE__ */ new Map(), options?.crit, this._protectedHeader, joseHeader);
        if (joseHeader.zip !== void 0) {
          throw new JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported.');
        }
        const { alg, enc } = joseHeader;
        if (typeof alg !== "string" || !alg) {
          throw new JWEInvalid('JWE "alg" (Algorithm) Header Parameter missing or invalid');
        }
        if (typeof enc !== "string" || !enc) {
          throw new JWEInvalid('JWE "enc" (Encryption Algorithm) Header Parameter missing or invalid');
        }
        let encryptedKey;
        if (this._cek && (alg === "dir" || alg === "ECDH-ES")) {
          throw new TypeError(`setContentEncryptionKey cannot be called with JWE "alg" (Algorithm) Header ${alg}`);
        }
        let cek;
        {
          let parameters;
          ({ cek, encryptedKey, parameters } = await encrypt_key_management_default(alg, enc, key, this._cek, this._keyManagementParameters));
          if (parameters) {
            if (options && unprotected in options) {
              if (!this._unprotectedHeader) {
                this.setUnprotectedHeader(parameters);
              } else {
                this._unprotectedHeader = { ...this._unprotectedHeader, ...parameters };
              }
            } else if (!this._protectedHeader) {
              this.setProtectedHeader(parameters);
            } else {
              this._protectedHeader = { ...this._protectedHeader, ...parameters };
            }
          }
        }
        let additionalData;
        let protectedHeader;
        let aadMember;
        if (this._protectedHeader) {
          protectedHeader = encoder.encode(encode(JSON.stringify(this._protectedHeader)));
        } else {
          protectedHeader = encoder.encode("");
        }
        if (this._aad) {
          aadMember = encode(this._aad);
          additionalData = concat(protectedHeader, encoder.encode("."), encoder.encode(aadMember));
        } else {
          additionalData = protectedHeader;
        }
        const { ciphertext, tag: tag2, iv } = await encrypt_default(enc, this._plaintext, cek, this._iv, additionalData);
        const jwe = {
          ciphertext: encode(ciphertext)
        };
        if (iv) {
          jwe.iv = encode(iv);
        }
        if (tag2) {
          jwe.tag = encode(tag2);
        }
        if (encryptedKey) {
          jwe.encrypted_key = encode(encryptedKey);
        }
        if (aadMember) {
          jwe.aad = aadMember;
        }
        if (this._protectedHeader) {
          jwe.protected = decoder.decode(protectedHeader);
        }
        if (this._sharedUnprotectedHeader) {
          jwe.unprotected = this._sharedUnprotectedHeader;
        }
        if (this._unprotectedHeader) {
          jwe.header = this._unprotectedHeader;
        }
        return jwe;
      }
    };
  }
});

// node_modules/jose/dist/browser/jwe/general/encrypt.js
var IndividualRecipient, GeneralEncrypt;
var init_encrypt3 = __esm({
  "node_modules/jose/dist/browser/jwe/general/encrypt.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_encrypt2();
    init_private_symbols();
    init_errors();
    init_cek();
    init_is_disjoint();
    init_encrypt_key_management();
    init_base64url();
    init_validate_crit();
    IndividualRecipient = class {
      static {
        __name(this, "IndividualRecipient");
      }
      constructor(enc, key, options) {
        this.parent = enc;
        this.key = key;
        this.options = options;
      }
      setUnprotectedHeader(unprotectedHeader) {
        if (this.unprotectedHeader) {
          throw new TypeError("setUnprotectedHeader can only be called once");
        }
        this.unprotectedHeader = unprotectedHeader;
        return this;
      }
      addRecipient(...args) {
        return this.parent.addRecipient(...args);
      }
      encrypt(...args) {
        return this.parent.encrypt(...args);
      }
      done() {
        return this.parent;
      }
    };
    GeneralEncrypt = class {
      static {
        __name(this, "GeneralEncrypt");
      }
      constructor(plaintext) {
        this._recipients = [];
        this._plaintext = plaintext;
      }
      addRecipient(key, options) {
        const recipient = new IndividualRecipient(this, key, { crit: options?.crit });
        this._recipients.push(recipient);
        return recipient;
      }
      setProtectedHeader(protectedHeader) {
        if (this._protectedHeader) {
          throw new TypeError("setProtectedHeader can only be called once");
        }
        this._protectedHeader = protectedHeader;
        return this;
      }
      setSharedUnprotectedHeader(sharedUnprotectedHeader) {
        if (this._unprotectedHeader) {
          throw new TypeError("setSharedUnprotectedHeader can only be called once");
        }
        this._unprotectedHeader = sharedUnprotectedHeader;
        return this;
      }
      setAdditionalAuthenticatedData(aad) {
        this._aad = aad;
        return this;
      }
      async encrypt() {
        if (!this._recipients.length) {
          throw new JWEInvalid("at least one recipient must be added");
        }
        if (this._recipients.length === 1) {
          const [recipient] = this._recipients;
          const flattened = await new FlattenedEncrypt(this._plaintext).setAdditionalAuthenticatedData(this._aad).setProtectedHeader(this._protectedHeader).setSharedUnprotectedHeader(this._unprotectedHeader).setUnprotectedHeader(recipient.unprotectedHeader).encrypt(recipient.key, { ...recipient.options });
          const jwe2 = {
            ciphertext: flattened.ciphertext,
            iv: flattened.iv,
            recipients: [{}],
            tag: flattened.tag
          };
          if (flattened.aad)
            jwe2.aad = flattened.aad;
          if (flattened.protected)
            jwe2.protected = flattened.protected;
          if (flattened.unprotected)
            jwe2.unprotected = flattened.unprotected;
          if (flattened.encrypted_key)
            jwe2.recipients[0].encrypted_key = flattened.encrypted_key;
          if (flattened.header)
            jwe2.recipients[0].header = flattened.header;
          return jwe2;
        }
        let enc;
        for (let i = 0; i < this._recipients.length; i++) {
          const recipient = this._recipients[i];
          if (!is_disjoint_default(this._protectedHeader, this._unprotectedHeader, recipient.unprotectedHeader)) {
            throw new JWEInvalid("JWE Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint");
          }
          const joseHeader = {
            ...this._protectedHeader,
            ...this._unprotectedHeader,
            ...recipient.unprotectedHeader
          };
          const { alg } = joseHeader;
          if (typeof alg !== "string" || !alg) {
            throw new JWEInvalid('JWE "alg" (Algorithm) Header Parameter missing or invalid');
          }
          if (alg === "dir" || alg === "ECDH-ES") {
            throw new JWEInvalid('"dir" and "ECDH-ES" alg may only be used with a single recipient');
          }
          if (typeof joseHeader.enc !== "string" || !joseHeader.enc) {
            throw new JWEInvalid('JWE "enc" (Encryption Algorithm) Header Parameter missing or invalid');
          }
          if (!enc) {
            enc = joseHeader.enc;
          } else if (enc !== joseHeader.enc) {
            throw new JWEInvalid('JWE "enc" (Encryption Algorithm) Header Parameter must be the same for all recipients');
          }
          validate_crit_default(JWEInvalid, /* @__PURE__ */ new Map(), recipient.options.crit, this._protectedHeader, joseHeader);
          if (joseHeader.zip !== void 0) {
            throw new JOSENotSupported('JWE "zip" (Compression Algorithm) Header Parameter is not supported.');
          }
        }
        const cek = cek_default(enc);
        const jwe = {
          ciphertext: "",
          iv: "",
          recipients: [],
          tag: ""
        };
        for (let i = 0; i < this._recipients.length; i++) {
          const recipient = this._recipients[i];
          const target = {};
          jwe.recipients.push(target);
          const joseHeader = {
            ...this._protectedHeader,
            ...this._unprotectedHeader,
            ...recipient.unprotectedHeader
          };
          const p2c = joseHeader.alg.startsWith("PBES2") ? 2048 + i : void 0;
          if (i === 0) {
            const flattened = await new FlattenedEncrypt(this._plaintext).setAdditionalAuthenticatedData(this._aad).setContentEncryptionKey(cek).setProtectedHeader(this._protectedHeader).setSharedUnprotectedHeader(this._unprotectedHeader).setUnprotectedHeader(recipient.unprotectedHeader).setKeyManagementParameters({ p2c }).encrypt(recipient.key, {
              ...recipient.options,
              [unprotected]: true
            });
            jwe.ciphertext = flattened.ciphertext;
            jwe.iv = flattened.iv;
            jwe.tag = flattened.tag;
            if (flattened.aad)
              jwe.aad = flattened.aad;
            if (flattened.protected)
              jwe.protected = flattened.protected;
            if (flattened.unprotected)
              jwe.unprotected = flattened.unprotected;
            target.encrypted_key = flattened.encrypted_key;
            if (flattened.header)
              target.header = flattened.header;
            continue;
          }
          const { encryptedKey, parameters } = await encrypt_key_management_default(recipient.unprotectedHeader?.alg || this._protectedHeader?.alg || this._unprotectedHeader?.alg, enc, recipient.key, cek, { p2c });
          target.encrypted_key = encode(encryptedKey);
          if (recipient.unprotectedHeader || parameters)
            target.header = { ...recipient.unprotectedHeader, ...parameters };
        }
        return jwe;
      }
    };
  }
});

// node_modules/jose/dist/browser/runtime/subtle_dsa.js
function subtleDsa(alg, algorithm) {
  const hash = `SHA-${alg.slice(-3)}`;
  switch (alg) {
    case "HS256":
    case "HS384":
    case "HS512":
      return { hash, name: "HMAC" };
    case "PS256":
    case "PS384":
    case "PS512":
      return { hash, name: "RSA-PSS", saltLength: alg.slice(-3) >> 3 };
    case "RS256":
    case "RS384":
    case "RS512":
      return { hash, name: "RSASSA-PKCS1-v1_5" };
    case "ES256":
    case "ES384":
    case "ES512":
      return { hash, name: "ECDSA", namedCurve: algorithm.namedCurve };
    case "Ed25519":
      return { name: "Ed25519" };
    case "EdDSA":
      return { name: algorithm.name };
    default:
      throw new JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
  }
}
var init_subtle_dsa = __esm({
  "node_modules/jose/dist/browser/runtime/subtle_dsa.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_errors();
    __name(subtleDsa, "subtleDsa");
  }
});

// node_modules/jose/dist/browser/runtime/get_sign_verify_key.js
async function getCryptoKey3(alg, key, usage) {
  if (usage === "sign") {
    key = await normalize_key_default.normalizePrivateKey(key, alg);
  }
  if (usage === "verify") {
    key = await normalize_key_default.normalizePublicKey(key, alg);
  }
  if (isCryptoKey(key)) {
    checkSigCryptoKey(key, alg, usage);
    return key;
  }
  if (key instanceof Uint8Array) {
    if (!alg.startsWith("HS")) {
      throw new TypeError(invalid_key_input_default(key, ...types));
    }
    return webcrypto_default.subtle.importKey("raw", key, { hash: `SHA-${alg.slice(-3)}`, name: "HMAC" }, false, [usage]);
  }
  throw new TypeError(invalid_key_input_default(key, ...types, "Uint8Array", "JSON Web Key"));
}
var init_get_sign_verify_key = __esm({
  "node_modules/jose/dist/browser/runtime/get_sign_verify_key.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_webcrypto();
    init_crypto_key();
    init_invalid_key_input();
    init_is_key_like();
    init_normalize_key();
    __name(getCryptoKey3, "getCryptoKey");
  }
});

// node_modules/jose/dist/browser/runtime/verify.js
var verify, verify_default;
var init_verify = __esm({
  "node_modules/jose/dist/browser/runtime/verify.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_subtle_dsa();
    init_webcrypto();
    init_check_key_length();
    init_get_sign_verify_key();
    verify = /* @__PURE__ */ __name(async (alg, key, signature, data) => {
      const cryptoKey = await getCryptoKey3(alg, key, "verify");
      check_key_length_default(alg, cryptoKey);
      const algorithm = subtleDsa(alg, cryptoKey.algorithm);
      try {
        return await webcrypto_default.subtle.verify(algorithm, cryptoKey, signature, data);
      } catch {
        return false;
      }
    }, "verify");
    verify_default = verify;
  }
});

// node_modules/jose/dist/browser/jws/flattened/verify.js
async function flattenedVerify(jws, key, options) {
  if (!isObject(jws)) {
    throw new JWSInvalid("Flattened JWS must be an object");
  }
  if (jws.protected === void 0 && jws.header === void 0) {
    throw new JWSInvalid('Flattened JWS must have either of the "protected" or "header" members');
  }
  if (jws.protected !== void 0 && typeof jws.protected !== "string") {
    throw new JWSInvalid("JWS Protected Header incorrect type");
  }
  if (jws.payload === void 0) {
    throw new JWSInvalid("JWS Payload missing");
  }
  if (typeof jws.signature !== "string") {
    throw new JWSInvalid("JWS Signature missing or incorrect type");
  }
  if (jws.header !== void 0 && !isObject(jws.header)) {
    throw new JWSInvalid("JWS Unprotected Header incorrect type");
  }
  let parsedProt = {};
  if (jws.protected) {
    try {
      const protectedHeader = decode(jws.protected);
      parsedProt = JSON.parse(decoder.decode(protectedHeader));
    } catch {
      throw new JWSInvalid("JWS Protected Header is invalid");
    }
  }
  if (!is_disjoint_default(parsedProt, jws.header)) {
    throw new JWSInvalid("JWS Protected and JWS Unprotected Header Parameter names must be disjoint");
  }
  const joseHeader = {
    ...parsedProt,
    ...jws.header
  };
  const extensions = validate_crit_default(JWSInvalid, /* @__PURE__ */ new Map([["b64", true]]), options?.crit, parsedProt, joseHeader);
  let b64 = true;
  if (extensions.has("b64")) {
    b64 = parsedProt.b64;
    if (typeof b64 !== "boolean") {
      throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
    }
  }
  const { alg } = joseHeader;
  if (typeof alg !== "string" || !alg) {
    throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
  }
  const algorithms = options && validate_algorithms_default("algorithms", options.algorithms);
  if (algorithms && !algorithms.has(alg)) {
    throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter value not allowed');
  }
  if (b64) {
    if (typeof jws.payload !== "string") {
      throw new JWSInvalid("JWS Payload must be a string");
    }
  } else if (typeof jws.payload !== "string" && !(jws.payload instanceof Uint8Array)) {
    throw new JWSInvalid("JWS Payload must be a string or an Uint8Array instance");
  }
  let resolvedKey = false;
  if (typeof key === "function") {
    key = await key(parsedProt, jws);
    resolvedKey = true;
    checkKeyTypeWithJwk(alg, key, "verify");
    if (isJWK(key)) {
      key = await importJWK(key, alg);
    }
  } else {
    checkKeyTypeWithJwk(alg, key, "verify");
  }
  const data = concat(encoder.encode(jws.protected ?? ""), encoder.encode("."), typeof jws.payload === "string" ? encoder.encode(jws.payload) : jws.payload);
  let signature;
  try {
    signature = decode(jws.signature);
  } catch {
    throw new JWSInvalid("Failed to base64url decode the signature");
  }
  const verified = await verify_default(alg, key, signature, data);
  if (!verified) {
    throw new JWSSignatureVerificationFailed();
  }
  let payload;
  if (b64) {
    try {
      payload = decode(jws.payload);
    } catch {
      throw new JWSInvalid("Failed to base64url decode the payload");
    }
  } else if (typeof jws.payload === "string") {
    payload = encoder.encode(jws.payload);
  } else {
    payload = jws.payload;
  }
  const result = { payload };
  if (jws.protected !== void 0) {
    result.protectedHeader = parsedProt;
  }
  if (jws.header !== void 0) {
    result.unprotectedHeader = jws.header;
  }
  if (resolvedKey) {
    return { ...result, key };
  }
  return result;
}
var init_verify2 = __esm({
  "node_modules/jose/dist/browser/jws/flattened/verify.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_base64url();
    init_verify();
    init_errors();
    init_buffer_utils();
    init_is_disjoint();
    init_is_object();
    init_check_key_type();
    init_validate_crit();
    init_validate_algorithms();
    init_is_jwk();
    init_import();
    __name(flattenedVerify, "flattenedVerify");
  }
});

// node_modules/jose/dist/browser/jws/compact/verify.js
async function compactVerify(jws, key, options) {
  if (jws instanceof Uint8Array) {
    jws = decoder.decode(jws);
  }
  if (typeof jws !== "string") {
    throw new JWSInvalid("Compact JWS must be a string or Uint8Array");
  }
  const { 0: protectedHeader, 1: payload, 2: signature, length } = jws.split(".");
  if (length !== 3) {
    throw new JWSInvalid("Invalid Compact JWS");
  }
  const verified = await flattenedVerify({ payload, protected: protectedHeader, signature }, key, options);
  const result = { payload: verified.payload, protectedHeader: verified.protectedHeader };
  if (typeof key === "function") {
    return { ...result, key: verified.key };
  }
  return result;
}
var init_verify3 = __esm({
  "node_modules/jose/dist/browser/jws/compact/verify.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_verify2();
    init_errors();
    init_buffer_utils();
    __name(compactVerify, "compactVerify");
  }
});

// node_modules/jose/dist/browser/jws/general/verify.js
async function generalVerify(jws, key, options) {
  if (!isObject(jws)) {
    throw new JWSInvalid("General JWS must be an object");
  }
  if (!Array.isArray(jws.signatures) || !jws.signatures.every(isObject)) {
    throw new JWSInvalid("JWS Signatures missing or incorrect type");
  }
  for (const signature of jws.signatures) {
    try {
      return await flattenedVerify({
        header: signature.header,
        payload: jws.payload,
        protected: signature.protected,
        signature: signature.signature
      }, key, options);
    } catch {
    }
  }
  throw new JWSSignatureVerificationFailed();
}
var init_verify4 = __esm({
  "node_modules/jose/dist/browser/jws/general/verify.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_verify2();
    init_errors();
    init_is_object();
    __name(generalVerify, "generalVerify");
  }
});

// node_modules/jose/dist/browser/lib/epoch.js
var epoch_default;
var init_epoch = __esm({
  "node_modules/jose/dist/browser/lib/epoch.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    epoch_default = /* @__PURE__ */ __name((date) => Math.floor(date.getTime() / 1e3), "default");
  }
});

// node_modules/jose/dist/browser/lib/secs.js
var minute, hour, day, week, year, REGEX, secs_default;
var init_secs = __esm({
  "node_modules/jose/dist/browser/lib/secs.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    minute = 60;
    hour = minute * 60;
    day = hour * 24;
    week = day * 7;
    year = day * 365.25;
    REGEX = /^(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$/i;
    secs_default = /* @__PURE__ */ __name((str) => {
      const matched = REGEX.exec(str);
      if (!matched || matched[4] && matched[1]) {
        throw new TypeError("Invalid time period format");
      }
      const value = parseFloat(matched[2]);
      const unit = matched[3].toLowerCase();
      let numericDate;
      switch (unit) {
        case "sec":
        case "secs":
        case "second":
        case "seconds":
        case "s":
          numericDate = Math.round(value);
          break;
        case "minute":
        case "minutes":
        case "min":
        case "mins":
        case "m":
          numericDate = Math.round(value * minute);
          break;
        case "hour":
        case "hours":
        case "hr":
        case "hrs":
        case "h":
          numericDate = Math.round(value * hour);
          break;
        case "day":
        case "days":
        case "d":
          numericDate = Math.round(value * day);
          break;
        case "week":
        case "weeks":
        case "w":
          numericDate = Math.round(value * week);
          break;
        default:
          numericDate = Math.round(value * year);
          break;
      }
      if (matched[1] === "-" || matched[4] === "ago") {
        return -numericDate;
      }
      return numericDate;
    }, "default");
  }
});

// node_modules/jose/dist/browser/lib/jwt_claims_set.js
var normalizeTyp, checkAudiencePresence, jwt_claims_set_default;
var init_jwt_claims_set = __esm({
  "node_modules/jose/dist/browser/lib/jwt_claims_set.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_errors();
    init_buffer_utils();
    init_epoch();
    init_secs();
    init_is_object();
    normalizeTyp = /* @__PURE__ */ __name((value) => value.toLowerCase().replace(/^application\//, ""), "normalizeTyp");
    checkAudiencePresence = /* @__PURE__ */ __name((audPayload, audOption) => {
      if (typeof audPayload === "string") {
        return audOption.includes(audPayload);
      }
      if (Array.isArray(audPayload)) {
        return audOption.some(Set.prototype.has.bind(new Set(audPayload)));
      }
      return false;
    }, "checkAudiencePresence");
    jwt_claims_set_default = /* @__PURE__ */ __name((protectedHeader, encodedPayload, options = {}) => {
      let payload;
      try {
        payload = JSON.parse(decoder.decode(encodedPayload));
      } catch {
      }
      if (!isObject(payload)) {
        throw new JWTInvalid("JWT Claims Set must be a top-level JSON object");
      }
      const { typ } = options;
      if (typ && (typeof protectedHeader.typ !== "string" || normalizeTyp(protectedHeader.typ) !== normalizeTyp(typ))) {
        throw new JWTClaimValidationFailed('unexpected "typ" JWT header value', payload, "typ", "check_failed");
      }
      const { requiredClaims = [], issuer, subject, audience, maxTokenAge } = options;
      const presenceCheck = [...requiredClaims];
      if (maxTokenAge !== void 0)
        presenceCheck.push("iat");
      if (audience !== void 0)
        presenceCheck.push("aud");
      if (subject !== void 0)
        presenceCheck.push("sub");
      if (issuer !== void 0)
        presenceCheck.push("iss");
      for (const claim of new Set(presenceCheck.reverse())) {
        if (!(claim in payload)) {
          throw new JWTClaimValidationFailed(`missing required "${claim}" claim`, payload, claim, "missing");
        }
      }
      if (issuer && !(Array.isArray(issuer) ? issuer : [issuer]).includes(payload.iss)) {
        throw new JWTClaimValidationFailed('unexpected "iss" claim value', payload, "iss", "check_failed");
      }
      if (subject && payload.sub !== subject) {
        throw new JWTClaimValidationFailed('unexpected "sub" claim value', payload, "sub", "check_failed");
      }
      if (audience && !checkAudiencePresence(payload.aud, typeof audience === "string" ? [audience] : audience)) {
        throw new JWTClaimValidationFailed('unexpected "aud" claim value', payload, "aud", "check_failed");
      }
      let tolerance;
      switch (typeof options.clockTolerance) {
        case "string":
          tolerance = secs_default(options.clockTolerance);
          break;
        case "number":
          tolerance = options.clockTolerance;
          break;
        case "undefined":
          tolerance = 0;
          break;
        default:
          throw new TypeError("Invalid clockTolerance option type");
      }
      const { currentDate } = options;
      const now = epoch_default(currentDate || /* @__PURE__ */ new Date());
      if ((payload.iat !== void 0 || maxTokenAge) && typeof payload.iat !== "number") {
        throw new JWTClaimValidationFailed('"iat" claim must be a number', payload, "iat", "invalid");
      }
      if (payload.nbf !== void 0) {
        if (typeof payload.nbf !== "number") {
          throw new JWTClaimValidationFailed('"nbf" claim must be a number', payload, "nbf", "invalid");
        }
        if (payload.nbf > now + tolerance) {
          throw new JWTClaimValidationFailed('"nbf" claim timestamp check failed', payload, "nbf", "check_failed");
        }
      }
      if (payload.exp !== void 0) {
        if (typeof payload.exp !== "number") {
          throw new JWTClaimValidationFailed('"exp" claim must be a number', payload, "exp", "invalid");
        }
        if (payload.exp <= now - tolerance) {
          throw new JWTExpired('"exp" claim timestamp check failed', payload, "exp", "check_failed");
        }
      }
      if (maxTokenAge) {
        const age = now - payload.iat;
        const max = typeof maxTokenAge === "number" ? maxTokenAge : secs_default(maxTokenAge);
        if (age - tolerance > max) {
          throw new JWTExpired('"iat" claim timestamp check failed (too far in the past)', payload, "iat", "check_failed");
        }
        if (age < 0 - tolerance) {
          throw new JWTClaimValidationFailed('"iat" claim timestamp check failed (it should be in the past)', payload, "iat", "check_failed");
        }
      }
      return payload;
    }, "default");
  }
});

// node_modules/jose/dist/browser/jwt/verify.js
async function jwtVerify(jwt, key, options) {
  const verified = await compactVerify(jwt, key, options);
  if (verified.protectedHeader.crit?.includes("b64") && verified.protectedHeader.b64 === false) {
    throw new JWTInvalid("JWTs MUST NOT use unencoded payload");
  }
  const payload = jwt_claims_set_default(verified.protectedHeader, verified.payload, options);
  const result = { payload, protectedHeader: verified.protectedHeader };
  if (typeof key === "function") {
    return { ...result, key: verified.key };
  }
  return result;
}
var init_verify5 = __esm({
  "node_modules/jose/dist/browser/jwt/verify.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_verify3();
    init_jwt_claims_set();
    init_errors();
    __name(jwtVerify, "jwtVerify");
  }
});

// node_modules/jose/dist/browser/jwt/decrypt.js
async function jwtDecrypt(jwt, key, options) {
  const decrypted = await compactDecrypt(jwt, key, options);
  const payload = jwt_claims_set_default(decrypted.protectedHeader, decrypted.plaintext, options);
  const { protectedHeader } = decrypted;
  if (protectedHeader.iss !== void 0 && protectedHeader.iss !== payload.iss) {
    throw new JWTClaimValidationFailed('replicated "iss" claim header parameter mismatch', payload, "iss", "mismatch");
  }
  if (protectedHeader.sub !== void 0 && protectedHeader.sub !== payload.sub) {
    throw new JWTClaimValidationFailed('replicated "sub" claim header parameter mismatch', payload, "sub", "mismatch");
  }
  if (protectedHeader.aud !== void 0 && JSON.stringify(protectedHeader.aud) !== JSON.stringify(payload.aud)) {
    throw new JWTClaimValidationFailed('replicated "aud" claim header parameter mismatch', payload, "aud", "mismatch");
  }
  const result = { payload, protectedHeader };
  if (typeof key === "function") {
    return { ...result, key: decrypted.key };
  }
  return result;
}
var init_decrypt5 = __esm({
  "node_modules/jose/dist/browser/jwt/decrypt.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_decrypt3();
    init_jwt_claims_set();
    init_errors();
    __name(jwtDecrypt, "jwtDecrypt");
  }
});

// node_modules/jose/dist/browser/jwe/compact/encrypt.js
var CompactEncrypt;
var init_encrypt4 = __esm({
  "node_modules/jose/dist/browser/jwe/compact/encrypt.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_encrypt2();
    CompactEncrypt = class {
      static {
        __name(this, "CompactEncrypt");
      }
      constructor(plaintext) {
        this._flattened = new FlattenedEncrypt(plaintext);
      }
      setContentEncryptionKey(cek) {
        this._flattened.setContentEncryptionKey(cek);
        return this;
      }
      setInitializationVector(iv) {
        this._flattened.setInitializationVector(iv);
        return this;
      }
      setProtectedHeader(protectedHeader) {
        this._flattened.setProtectedHeader(protectedHeader);
        return this;
      }
      setKeyManagementParameters(parameters) {
        this._flattened.setKeyManagementParameters(parameters);
        return this;
      }
      async encrypt(key, options) {
        const jwe = await this._flattened.encrypt(key, options);
        return [jwe.protected, jwe.encrypted_key, jwe.iv, jwe.ciphertext, jwe.tag].join(".");
      }
    };
  }
});

// node_modules/jose/dist/browser/runtime/sign.js
var sign, sign_default;
var init_sign = __esm({
  "node_modules/jose/dist/browser/runtime/sign.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_subtle_dsa();
    init_webcrypto();
    init_check_key_length();
    init_get_sign_verify_key();
    sign = /* @__PURE__ */ __name(async (alg, key, data) => {
      const cryptoKey = await getCryptoKey3(alg, key, "sign");
      check_key_length_default(alg, cryptoKey);
      const signature = await webcrypto_default.subtle.sign(subtleDsa(alg, cryptoKey.algorithm), cryptoKey, data);
      return new Uint8Array(signature);
    }, "sign");
    sign_default = sign;
  }
});

// node_modules/jose/dist/browser/jws/flattened/sign.js
var FlattenedSign;
var init_sign2 = __esm({
  "node_modules/jose/dist/browser/jws/flattened/sign.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_base64url();
    init_sign();
    init_is_disjoint();
    init_errors();
    init_buffer_utils();
    init_check_key_type();
    init_validate_crit();
    FlattenedSign = class {
      static {
        __name(this, "FlattenedSign");
      }
      constructor(payload) {
        if (!(payload instanceof Uint8Array)) {
          throw new TypeError("payload must be an instance of Uint8Array");
        }
        this._payload = payload;
      }
      setProtectedHeader(protectedHeader) {
        if (this._protectedHeader) {
          throw new TypeError("setProtectedHeader can only be called once");
        }
        this._protectedHeader = protectedHeader;
        return this;
      }
      setUnprotectedHeader(unprotectedHeader) {
        if (this._unprotectedHeader) {
          throw new TypeError("setUnprotectedHeader can only be called once");
        }
        this._unprotectedHeader = unprotectedHeader;
        return this;
      }
      async sign(key, options) {
        if (!this._protectedHeader && !this._unprotectedHeader) {
          throw new JWSInvalid("either setProtectedHeader or setUnprotectedHeader must be called before #sign()");
        }
        if (!is_disjoint_default(this._protectedHeader, this._unprotectedHeader)) {
          throw new JWSInvalid("JWS Protected and JWS Unprotected Header Parameter names must be disjoint");
        }
        const joseHeader = {
          ...this._protectedHeader,
          ...this._unprotectedHeader
        };
        const extensions = validate_crit_default(JWSInvalid, /* @__PURE__ */ new Map([["b64", true]]), options?.crit, this._protectedHeader, joseHeader);
        let b64 = true;
        if (extensions.has("b64")) {
          b64 = this._protectedHeader.b64;
          if (typeof b64 !== "boolean") {
            throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
          }
        }
        const { alg } = joseHeader;
        if (typeof alg !== "string" || !alg) {
          throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
        }
        checkKeyTypeWithJwk(alg, key, "sign");
        let payload = this._payload;
        if (b64) {
          payload = encoder.encode(encode(payload));
        }
        let protectedHeader;
        if (this._protectedHeader) {
          protectedHeader = encoder.encode(encode(JSON.stringify(this._protectedHeader)));
        } else {
          protectedHeader = encoder.encode("");
        }
        const data = concat(protectedHeader, encoder.encode("."), payload);
        const signature = await sign_default(alg, key, data);
        const jws = {
          signature: encode(signature),
          payload: ""
        };
        if (b64) {
          jws.payload = decoder.decode(payload);
        }
        if (this._unprotectedHeader) {
          jws.header = this._unprotectedHeader;
        }
        if (this._protectedHeader) {
          jws.protected = decoder.decode(protectedHeader);
        }
        return jws;
      }
    };
  }
});

// node_modules/jose/dist/browser/jws/compact/sign.js
var CompactSign;
var init_sign3 = __esm({
  "node_modules/jose/dist/browser/jws/compact/sign.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_sign2();
    CompactSign = class {
      static {
        __name(this, "CompactSign");
      }
      constructor(payload) {
        this._flattened = new FlattenedSign(payload);
      }
      setProtectedHeader(protectedHeader) {
        this._flattened.setProtectedHeader(protectedHeader);
        return this;
      }
      async sign(key, options) {
        const jws = await this._flattened.sign(key, options);
        if (jws.payload === void 0) {
          throw new TypeError("use the flattened module for creating JWS with b64: false");
        }
        return `${jws.protected}.${jws.payload}.${jws.signature}`;
      }
    };
  }
});

// node_modules/jose/dist/browser/jws/general/sign.js
var IndividualSignature, GeneralSign;
var init_sign4 = __esm({
  "node_modules/jose/dist/browser/jws/general/sign.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_sign2();
    init_errors();
    IndividualSignature = class {
      static {
        __name(this, "IndividualSignature");
      }
      constructor(sig, key, options) {
        this.parent = sig;
        this.key = key;
        this.options = options;
      }
      setProtectedHeader(protectedHeader) {
        if (this.protectedHeader) {
          throw new TypeError("setProtectedHeader can only be called once");
        }
        this.protectedHeader = protectedHeader;
        return this;
      }
      setUnprotectedHeader(unprotectedHeader) {
        if (this.unprotectedHeader) {
          throw new TypeError("setUnprotectedHeader can only be called once");
        }
        this.unprotectedHeader = unprotectedHeader;
        return this;
      }
      addSignature(...args) {
        return this.parent.addSignature(...args);
      }
      sign(...args) {
        return this.parent.sign(...args);
      }
      done() {
        return this.parent;
      }
    };
    GeneralSign = class {
      static {
        __name(this, "GeneralSign");
      }
      constructor(payload) {
        this._signatures = [];
        this._payload = payload;
      }
      addSignature(key, options) {
        const signature = new IndividualSignature(this, key, options);
        this._signatures.push(signature);
        return signature;
      }
      async sign() {
        if (!this._signatures.length) {
          throw new JWSInvalid("at least one signature must be added");
        }
        const jws = {
          signatures: [],
          payload: ""
        };
        for (let i = 0; i < this._signatures.length; i++) {
          const signature = this._signatures[i];
          const flattened = new FlattenedSign(this._payload);
          flattened.setProtectedHeader(signature.protectedHeader);
          flattened.setUnprotectedHeader(signature.unprotectedHeader);
          const { payload, ...rest } = await flattened.sign(signature.key, signature.options);
          if (i === 0) {
            jws.payload = payload;
          } else if (jws.payload !== payload) {
            throw new JWSInvalid("inconsistent use of JWS Unencoded Payload (RFC7797)");
          }
          jws.signatures.push(rest);
        }
        return jws;
      }
    };
  }
});

// node_modules/jose/dist/browser/jwt/produce.js
function validateInput(label, input) {
  if (!Number.isFinite(input)) {
    throw new TypeError(`Invalid ${label} input`);
  }
  return input;
}
var ProduceJWT;
var init_produce = __esm({
  "node_modules/jose/dist/browser/jwt/produce.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_epoch();
    init_is_object();
    init_secs();
    __name(validateInput, "validateInput");
    ProduceJWT = class {
      static {
        __name(this, "ProduceJWT");
      }
      constructor(payload = {}) {
        if (!isObject(payload)) {
          throw new TypeError("JWT Claims Set MUST be an object");
        }
        this._payload = payload;
      }
      setIssuer(issuer) {
        this._payload = { ...this._payload, iss: issuer };
        return this;
      }
      setSubject(subject) {
        this._payload = { ...this._payload, sub: subject };
        return this;
      }
      setAudience(audience) {
        this._payload = { ...this._payload, aud: audience };
        return this;
      }
      setJti(jwtId) {
        this._payload = { ...this._payload, jti: jwtId };
        return this;
      }
      setNotBefore(input) {
        if (typeof input === "number") {
          this._payload = { ...this._payload, nbf: validateInput("setNotBefore", input) };
        } else if (input instanceof Date) {
          this._payload = { ...this._payload, nbf: validateInput("setNotBefore", epoch_default(input)) };
        } else {
          this._payload = { ...this._payload, nbf: epoch_default(/* @__PURE__ */ new Date()) + secs_default(input) };
        }
        return this;
      }
      setExpirationTime(input) {
        if (typeof input === "number") {
          this._payload = { ...this._payload, exp: validateInput("setExpirationTime", input) };
        } else if (input instanceof Date) {
          this._payload = { ...this._payload, exp: validateInput("setExpirationTime", epoch_default(input)) };
        } else {
          this._payload = { ...this._payload, exp: epoch_default(/* @__PURE__ */ new Date()) + secs_default(input) };
        }
        return this;
      }
      setIssuedAt(input) {
        if (typeof input === "undefined") {
          this._payload = { ...this._payload, iat: epoch_default(/* @__PURE__ */ new Date()) };
        } else if (input instanceof Date) {
          this._payload = { ...this._payload, iat: validateInput("setIssuedAt", epoch_default(input)) };
        } else if (typeof input === "string") {
          this._payload = {
            ...this._payload,
            iat: validateInput("setIssuedAt", epoch_default(/* @__PURE__ */ new Date()) + secs_default(input))
          };
        } else {
          this._payload = { ...this._payload, iat: validateInput("setIssuedAt", input) };
        }
        return this;
      }
    };
  }
});

// node_modules/jose/dist/browser/jwt/sign.js
var SignJWT;
var init_sign5 = __esm({
  "node_modules/jose/dist/browser/jwt/sign.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_sign3();
    init_errors();
    init_buffer_utils();
    init_produce();
    SignJWT = class extends ProduceJWT {
      static {
        __name(this, "SignJWT");
      }
      setProtectedHeader(protectedHeader) {
        this._protectedHeader = protectedHeader;
        return this;
      }
      async sign(key, options) {
        const sig = new CompactSign(encoder.encode(JSON.stringify(this._payload)));
        sig.setProtectedHeader(this._protectedHeader);
        if (Array.isArray(this._protectedHeader?.crit) && this._protectedHeader.crit.includes("b64") && this._protectedHeader.b64 === false) {
          throw new JWTInvalid("JWTs MUST NOT use unencoded payload");
        }
        return sig.sign(key, options);
      }
    };
  }
});

// node_modules/jose/dist/browser/jwt/encrypt.js
var EncryptJWT;
var init_encrypt5 = __esm({
  "node_modules/jose/dist/browser/jwt/encrypt.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_encrypt4();
    init_buffer_utils();
    init_produce();
    EncryptJWT = class extends ProduceJWT {
      static {
        __name(this, "EncryptJWT");
      }
      setProtectedHeader(protectedHeader) {
        if (this._protectedHeader) {
          throw new TypeError("setProtectedHeader can only be called once");
        }
        this._protectedHeader = protectedHeader;
        return this;
      }
      setKeyManagementParameters(parameters) {
        if (this._keyManagementParameters) {
          throw new TypeError("setKeyManagementParameters can only be called once");
        }
        this._keyManagementParameters = parameters;
        return this;
      }
      setContentEncryptionKey(cek) {
        if (this._cek) {
          throw new TypeError("setContentEncryptionKey can only be called once");
        }
        this._cek = cek;
        return this;
      }
      setInitializationVector(iv) {
        if (this._iv) {
          throw new TypeError("setInitializationVector can only be called once");
        }
        this._iv = iv;
        return this;
      }
      replicateIssuerAsHeader() {
        this._replicateIssuerAsHeader = true;
        return this;
      }
      replicateSubjectAsHeader() {
        this._replicateSubjectAsHeader = true;
        return this;
      }
      replicateAudienceAsHeader() {
        this._replicateAudienceAsHeader = true;
        return this;
      }
      async encrypt(key, options) {
        const enc = new CompactEncrypt(encoder.encode(JSON.stringify(this._payload)));
        if (this._replicateIssuerAsHeader) {
          this._protectedHeader = { ...this._protectedHeader, iss: this._payload.iss };
        }
        if (this._replicateSubjectAsHeader) {
          this._protectedHeader = { ...this._protectedHeader, sub: this._payload.sub };
        }
        if (this._replicateAudienceAsHeader) {
          this._protectedHeader = { ...this._protectedHeader, aud: this._payload.aud };
        }
        enc.setProtectedHeader(this._protectedHeader);
        if (this._iv) {
          enc.setInitializationVector(this._iv);
        }
        if (this._cek) {
          enc.setContentEncryptionKey(this._cek);
        }
        if (this._keyManagementParameters) {
          enc.setKeyManagementParameters(this._keyManagementParameters);
        }
        return enc.encrypt(key, options);
      }
    };
  }
});

// node_modules/jose/dist/browser/jwk/thumbprint.js
async function calculateJwkThumbprint(jwk, digestAlgorithm) {
  if (!isObject(jwk)) {
    throw new TypeError("JWK must be an object");
  }
  digestAlgorithm ?? (digestAlgorithm = "sha256");
  if (digestAlgorithm !== "sha256" && digestAlgorithm !== "sha384" && digestAlgorithm !== "sha512") {
    throw new TypeError('digestAlgorithm must one of "sha256", "sha384", or "sha512"');
  }
  let components;
  switch (jwk.kty) {
    case "EC":
      check(jwk.crv, '"crv" (Curve) Parameter');
      check(jwk.x, '"x" (X Coordinate) Parameter');
      check(jwk.y, '"y" (Y Coordinate) Parameter');
      components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
      break;
    case "OKP":
      check(jwk.crv, '"crv" (Subtype of Key Pair) Parameter');
      check(jwk.x, '"x" (Public Key) Parameter');
      components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
      break;
    case "RSA":
      check(jwk.e, '"e" (Exponent) Parameter');
      check(jwk.n, '"n" (Modulus) Parameter');
      components = { e: jwk.e, kty: jwk.kty, n: jwk.n };
      break;
    case "oct":
      check(jwk.k, '"k" (Key Value) Parameter');
      components = { k: jwk.k, kty: jwk.kty };
      break;
    default:
      throw new JOSENotSupported('"kty" (Key Type) Parameter missing or unsupported');
  }
  const data = encoder.encode(JSON.stringify(components));
  return encode(await digest_default(digestAlgorithm, data));
}
async function calculateJwkThumbprintUri(jwk, digestAlgorithm) {
  digestAlgorithm ?? (digestAlgorithm = "sha256");
  const thumbprint = await calculateJwkThumbprint(jwk, digestAlgorithm);
  return `urn:ietf:params:oauth:jwk-thumbprint:sha-${digestAlgorithm.slice(-3)}:${thumbprint}`;
}
var check;
var init_thumbprint = __esm({
  "node_modules/jose/dist/browser/jwk/thumbprint.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_digest();
    init_base64url();
    init_errors();
    init_buffer_utils();
    init_is_object();
    check = /* @__PURE__ */ __name((value, description) => {
      if (typeof value !== "string" || !value) {
        throw new JWKInvalid(`${description} missing or invalid`);
      }
    }, "check");
    __name(calculateJwkThumbprint, "calculateJwkThumbprint");
    __name(calculateJwkThumbprintUri, "calculateJwkThumbprintUri");
  }
});

// node_modules/jose/dist/browser/jwk/embedded.js
async function EmbeddedJWK(protectedHeader, token) {
  const joseHeader = {
    ...protectedHeader,
    ...token?.header
  };
  if (!isObject(joseHeader.jwk)) {
    throw new JWSInvalid('"jwk" (JSON Web Key) Header Parameter must be a JSON object');
  }
  const key = await importJWK({ ...joseHeader.jwk, ext: true }, joseHeader.alg);
  if (key instanceof Uint8Array || key.type !== "public") {
    throw new JWSInvalid('"jwk" (JSON Web Key) Header Parameter must be a public key');
  }
  return key;
}
var init_embedded = __esm({
  "node_modules/jose/dist/browser/jwk/embedded.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_import();
    init_is_object();
    init_errors();
    __name(EmbeddedJWK, "EmbeddedJWK");
  }
});

// node_modules/jose/dist/browser/jwks/local.js
function getKtyFromAlg(alg) {
  switch (typeof alg === "string" && alg.slice(0, 2)) {
    case "RS":
    case "PS":
      return "RSA";
    case "ES":
      return "EC";
    case "Ed":
      return "OKP";
    default:
      throw new JOSENotSupported('Unsupported "alg" value for a JSON Web Key Set');
  }
}
function isJWKSLike(jwks) {
  return jwks && typeof jwks === "object" && Array.isArray(jwks.keys) && jwks.keys.every(isJWKLike);
}
function isJWKLike(key) {
  return isObject(key);
}
function clone(obj) {
  if (typeof structuredClone === "function") {
    return structuredClone(obj);
  }
  return JSON.parse(JSON.stringify(obj));
}
async function importWithAlgCache(cache, jwk, alg) {
  const cached = cache.get(jwk) || cache.set(jwk, {}).get(jwk);
  if (cached[alg] === void 0) {
    const key = await importJWK({ ...jwk, ext: true }, alg);
    if (key instanceof Uint8Array || key.type !== "public") {
      throw new JWKSInvalid("JSON Web Key Set members must be public keys");
    }
    cached[alg] = key;
  }
  return cached[alg];
}
function createLocalJWKSet(jwks) {
  const set = new LocalJWKSet(jwks);
  const localJWKSet = /* @__PURE__ */ __name(async (protectedHeader, token) => set.getKey(protectedHeader, token), "localJWKSet");
  Object.defineProperties(localJWKSet, {
    jwks: {
      value: /* @__PURE__ */ __name(() => clone(set._jwks), "value"),
      enumerable: true,
      configurable: false,
      writable: false
    }
  });
  return localJWKSet;
}
var LocalJWKSet;
var init_local = __esm({
  "node_modules/jose/dist/browser/jwks/local.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_import();
    init_errors();
    init_is_object();
    __name(getKtyFromAlg, "getKtyFromAlg");
    __name(isJWKSLike, "isJWKSLike");
    __name(isJWKLike, "isJWKLike");
    __name(clone, "clone");
    LocalJWKSet = class {
      static {
        __name(this, "LocalJWKSet");
      }
      constructor(jwks) {
        this._cached = /* @__PURE__ */ new WeakMap();
        if (!isJWKSLike(jwks)) {
          throw new JWKSInvalid("JSON Web Key Set malformed");
        }
        this._jwks = clone(jwks);
      }
      async getKey(protectedHeader, token) {
        const { alg, kid } = { ...protectedHeader, ...token?.header };
        const kty = getKtyFromAlg(alg);
        const candidates = this._jwks.keys.filter((jwk2) => {
          let candidate = kty === jwk2.kty;
          if (candidate && typeof kid === "string") {
            candidate = kid === jwk2.kid;
          }
          if (candidate && typeof jwk2.alg === "string") {
            candidate = alg === jwk2.alg;
          }
          if (candidate && typeof jwk2.use === "string") {
            candidate = jwk2.use === "sig";
          }
          if (candidate && Array.isArray(jwk2.key_ops)) {
            candidate = jwk2.key_ops.includes("verify");
          }
          if (candidate) {
            switch (alg) {
              case "ES256":
                candidate = jwk2.crv === "P-256";
                break;
              case "ES256K":
                candidate = jwk2.crv === "secp256k1";
                break;
              case "ES384":
                candidate = jwk2.crv === "P-384";
                break;
              case "ES512":
                candidate = jwk2.crv === "P-521";
                break;
              case "Ed25519":
                candidate = jwk2.crv === "Ed25519";
                break;
              case "EdDSA":
                candidate = jwk2.crv === "Ed25519" || jwk2.crv === "Ed448";
                break;
            }
          }
          return candidate;
        });
        const { 0: jwk, length } = candidates;
        if (length === 0) {
          throw new JWKSNoMatchingKey();
        }
        if (length !== 1) {
          const error = new JWKSMultipleMatchingKeys();
          const { _cached } = this;
          error[Symbol.asyncIterator] = async function* () {
            for (const jwk2 of candidates) {
              try {
                yield await importWithAlgCache(_cached, jwk2, alg);
              } catch {
              }
            }
          };
          throw error;
        }
        return importWithAlgCache(this._cached, jwk, alg);
      }
    };
    __name(importWithAlgCache, "importWithAlgCache");
    __name(createLocalJWKSet, "createLocalJWKSet");
  }
});

// node_modules/jose/dist/browser/runtime/fetch_jwks.js
var fetchJwks, fetch_jwks_default;
var init_fetch_jwks = __esm({
  "node_modules/jose/dist/browser/runtime/fetch_jwks.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_errors();
    fetchJwks = /* @__PURE__ */ __name(async (url, timeout, options) => {
      let controller;
      let id;
      let timedOut = false;
      if (typeof AbortController === "function") {
        controller = new AbortController();
        id = setTimeout(() => {
          timedOut = true;
          controller.abort();
        }, timeout);
      }
      const response = await fetch(url.href, {
        signal: controller ? controller.signal : void 0,
        redirect: "manual",
        headers: options.headers
      }).catch((err) => {
        if (timedOut)
          throw new JWKSTimeout();
        throw err;
      });
      if (id !== void 0)
        clearTimeout(id);
      if (response.status !== 200) {
        throw new JOSEError("Expected 200 OK from the JSON Web Key Set HTTP response");
      }
      try {
        return await response.json();
      } catch {
        throw new JOSEError("Failed to parse the JSON Web Key Set HTTP response as JSON");
      }
    }, "fetchJwks");
    fetch_jwks_default = fetchJwks;
  }
});

// node_modules/jose/dist/browser/jwks/remote.js
function isCloudflareWorkers() {
  return typeof WebSocketPair !== "undefined" || typeof navigator !== "undefined" && true || typeof EdgeRuntime !== "undefined" && EdgeRuntime === "vercel";
}
function isFreshJwksCache(input, cacheMaxAge) {
  if (typeof input !== "object" || input === null) {
    return false;
  }
  if (!("uat" in input) || typeof input.uat !== "number" || Date.now() - input.uat >= cacheMaxAge) {
    return false;
  }
  if (!("jwks" in input) || !isObject(input.jwks) || !Array.isArray(input.jwks.keys) || !Array.prototype.every.call(input.jwks.keys, isObject)) {
    return false;
  }
  return true;
}
function createRemoteJWKSet(url, options) {
  const set = new RemoteJWKSet(url, options);
  const remoteJWKSet = /* @__PURE__ */ __name(async (protectedHeader, token) => set.getKey(protectedHeader, token), "remoteJWKSet");
  Object.defineProperties(remoteJWKSet, {
    coolingDown: {
      get: /* @__PURE__ */ __name(() => set.coolingDown(), "get"),
      enumerable: true,
      configurable: false
    },
    fresh: {
      get: /* @__PURE__ */ __name(() => set.fresh(), "get"),
      enumerable: true,
      configurable: false
    },
    reload: {
      value: /* @__PURE__ */ __name(() => set.reload(), "value"),
      enumerable: true,
      configurable: false,
      writable: false
    },
    reloading: {
      get: /* @__PURE__ */ __name(() => !!set._pendingFetch, "get"),
      enumerable: true,
      configurable: false
    },
    jwks: {
      value: /* @__PURE__ */ __name(() => set._local?.jwks(), "value"),
      enumerable: true,
      configurable: false,
      writable: false
    }
  });
  return remoteJWKSet;
}
var USER_AGENT, jwksCache, RemoteJWKSet, experimental_jwksCache;
var init_remote = __esm({
  "node_modules/jose/dist/browser/jwks/remote.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_fetch_jwks();
    init_errors();
    init_local();
    init_is_object();
    __name(isCloudflareWorkers, "isCloudflareWorkers");
    if (typeof navigator === "undefined" || !"Cloudflare-Workers"?.startsWith?.("Mozilla/5.0 ")) {
      const NAME = "jose";
      const VERSION = "v5.10.0";
      USER_AGENT = `${NAME}/${VERSION}`;
    }
    jwksCache = Symbol();
    __name(isFreshJwksCache, "isFreshJwksCache");
    RemoteJWKSet = class {
      static {
        __name(this, "RemoteJWKSet");
      }
      constructor(url, options) {
        if (!(url instanceof URL)) {
          throw new TypeError("url must be an instance of URL");
        }
        this._url = new URL(url.href);
        this._options = { agent: options?.agent, headers: options?.headers };
        this._timeoutDuration = typeof options?.timeoutDuration === "number" ? options?.timeoutDuration : 5e3;
        this._cooldownDuration = typeof options?.cooldownDuration === "number" ? options?.cooldownDuration : 3e4;
        this._cacheMaxAge = typeof options?.cacheMaxAge === "number" ? options?.cacheMaxAge : 6e5;
        if (options?.[jwksCache] !== void 0) {
          this._cache = options?.[jwksCache];
          if (isFreshJwksCache(options?.[jwksCache], this._cacheMaxAge)) {
            this._jwksTimestamp = this._cache.uat;
            this._local = createLocalJWKSet(this._cache.jwks);
          }
        }
      }
      coolingDown() {
        return typeof this._jwksTimestamp === "number" ? Date.now() < this._jwksTimestamp + this._cooldownDuration : false;
      }
      fresh() {
        return typeof this._jwksTimestamp === "number" ? Date.now() < this._jwksTimestamp + this._cacheMaxAge : false;
      }
      async getKey(protectedHeader, token) {
        if (!this._local || !this.fresh()) {
          await this.reload();
        }
        try {
          return await this._local(protectedHeader, token);
        } catch (err) {
          if (err instanceof JWKSNoMatchingKey) {
            if (this.coolingDown() === false) {
              await this.reload();
              return this._local(protectedHeader, token);
            }
          }
          throw err;
        }
      }
      async reload() {
        if (this._pendingFetch && isCloudflareWorkers()) {
          this._pendingFetch = void 0;
        }
        const headers = new Headers(this._options.headers);
        if (USER_AGENT && !headers.has("User-Agent")) {
          headers.set("User-Agent", USER_AGENT);
          this._options.headers = Object.fromEntries(headers.entries());
        }
        this._pendingFetch || (this._pendingFetch = fetch_jwks_default(this._url, this._timeoutDuration, this._options).then((json) => {
          this._local = createLocalJWKSet(json);
          if (this._cache) {
            this._cache.uat = Date.now();
            this._cache.jwks = json;
          }
          this._jwksTimestamp = Date.now();
          this._pendingFetch = void 0;
        }).catch((err) => {
          this._pendingFetch = void 0;
          throw err;
        }));
        await this._pendingFetch;
      }
    };
    __name(createRemoteJWKSet, "createRemoteJWKSet");
    experimental_jwksCache = jwksCache;
  }
});

// node_modules/jose/dist/browser/jwt/unsecured.js
var UnsecuredJWT;
var init_unsecured = __esm({
  "node_modules/jose/dist/browser/jwt/unsecured.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_base64url();
    init_buffer_utils();
    init_errors();
    init_jwt_claims_set();
    init_produce();
    UnsecuredJWT = class extends ProduceJWT {
      static {
        __name(this, "UnsecuredJWT");
      }
      encode() {
        const header = encode(JSON.stringify({ alg: "none" }));
        const payload = encode(JSON.stringify(this._payload));
        return `${header}.${payload}.`;
      }
      static decode(jwt, options) {
        if (typeof jwt !== "string") {
          throw new JWTInvalid("Unsecured JWT must be a string");
        }
        const { 0: encodedHeader, 1: encodedPayload, 2: signature, length } = jwt.split(".");
        if (length !== 3 || signature !== "") {
          throw new JWTInvalid("Invalid Unsecured JWT");
        }
        let header;
        try {
          header = JSON.parse(decoder.decode(decode(encodedHeader)));
          if (header.alg !== "none")
            throw new Error();
        } catch {
          throw new JWTInvalid("Invalid Unsecured JWT");
        }
        const payload = jwt_claims_set_default(header, decode(encodedPayload), options);
        return { payload, header };
      }
    };
  }
});

// node_modules/jose/dist/browser/util/base64url.js
var base64url_exports2 = {};
__export(base64url_exports2, {
  decode: () => decode2,
  encode: () => encode2
});
var encode2, decode2;
var init_base64url2 = __esm({
  "node_modules/jose/dist/browser/util/base64url.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_base64url();
    encode2 = encode;
    decode2 = decode;
  }
});

// node_modules/jose/dist/browser/util/decode_protected_header.js
function decodeProtectedHeader(token) {
  let protectedB64u;
  if (typeof token === "string") {
    const parts = token.split(".");
    if (parts.length === 3 || parts.length === 5) {
      ;
      [protectedB64u] = parts;
    }
  } else if (typeof token === "object" && token) {
    if ("protected" in token) {
      protectedB64u = token.protected;
    } else {
      throw new TypeError("Token does not contain a Protected Header");
    }
  }
  try {
    if (typeof protectedB64u !== "string" || !protectedB64u) {
      throw new Error();
    }
    const result = JSON.parse(decoder.decode(decode2(protectedB64u)));
    if (!isObject(result)) {
      throw new Error();
    }
    return result;
  } catch {
    throw new TypeError("Invalid Token or Protected Header formatting");
  }
}
var init_decode_protected_header = __esm({
  "node_modules/jose/dist/browser/util/decode_protected_header.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_base64url2();
    init_buffer_utils();
    init_is_object();
    __name(decodeProtectedHeader, "decodeProtectedHeader");
  }
});

// node_modules/jose/dist/browser/util/decode_jwt.js
function decodeJwt(jwt) {
  if (typeof jwt !== "string")
    throw new JWTInvalid("JWTs must use Compact JWS serialization, JWT must be a string");
  const { 1: payload, length } = jwt.split(".");
  if (length === 5)
    throw new JWTInvalid("Only JWTs using Compact JWS serialization can be decoded");
  if (length !== 3)
    throw new JWTInvalid("Invalid JWT");
  if (!payload)
    throw new JWTInvalid("JWTs must contain a payload");
  let decoded;
  try {
    decoded = decode2(payload);
  } catch {
    throw new JWTInvalid("Failed to base64url decode the payload");
  }
  let result;
  try {
    result = JSON.parse(decoder.decode(decoded));
  } catch {
    throw new JWTInvalid("Failed to parse the decoded payload as JSON");
  }
  if (!isObject(result))
    throw new JWTInvalid("Invalid JWT Claims Set");
  return result;
}
var init_decode_jwt = __esm({
  "node_modules/jose/dist/browser/util/decode_jwt.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_base64url2();
    init_buffer_utils();
    init_is_object();
    init_errors();
    __name(decodeJwt, "decodeJwt");
  }
});

// node_modules/jose/dist/browser/runtime/generate.js
async function generateSecret(alg, options) {
  let length;
  let algorithm;
  let keyUsages;
  switch (alg) {
    case "HS256":
    case "HS384":
    case "HS512":
      length = parseInt(alg.slice(-3), 10);
      algorithm = { name: "HMAC", hash: `SHA-${length}`, length };
      keyUsages = ["sign", "verify"];
      break;
    case "A128CBC-HS256":
    case "A192CBC-HS384":
    case "A256CBC-HS512":
      length = parseInt(alg.slice(-3), 10);
      return random_default(new Uint8Array(length >> 3));
    case "A128KW":
    case "A192KW":
    case "A256KW":
      length = parseInt(alg.slice(1, 4), 10);
      algorithm = { name: "AES-KW", length };
      keyUsages = ["wrapKey", "unwrapKey"];
      break;
    case "A128GCMKW":
    case "A192GCMKW":
    case "A256GCMKW":
    case "A128GCM":
    case "A192GCM":
    case "A256GCM":
      length = parseInt(alg.slice(1, 4), 10);
      algorithm = { name: "AES-GCM", length };
      keyUsages = ["encrypt", "decrypt"];
      break;
    default:
      throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
  }
  return webcrypto_default.subtle.generateKey(algorithm, options?.extractable ?? false, keyUsages);
}
function getModulusLengthOption(options) {
  const modulusLength = options?.modulusLength ?? 2048;
  if (typeof modulusLength !== "number" || modulusLength < 2048) {
    throw new JOSENotSupported("Invalid or unsupported modulusLength option provided, 2048 bits or larger keys must be used");
  }
  return modulusLength;
}
async function generateKeyPair(alg, options) {
  let algorithm;
  let keyUsages;
  switch (alg) {
    case "PS256":
    case "PS384":
    case "PS512":
      algorithm = {
        name: "RSA-PSS",
        hash: `SHA-${alg.slice(-3)}`,
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength: getModulusLengthOption(options)
      };
      keyUsages = ["sign", "verify"];
      break;
    case "RS256":
    case "RS384":
    case "RS512":
      algorithm = {
        name: "RSASSA-PKCS1-v1_5",
        hash: `SHA-${alg.slice(-3)}`,
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength: getModulusLengthOption(options)
      };
      keyUsages = ["sign", "verify"];
      break;
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512":
      algorithm = {
        name: "RSA-OAEP",
        hash: `SHA-${parseInt(alg.slice(-3), 10) || 1}`,
        publicExponent: new Uint8Array([1, 0, 1]),
        modulusLength: getModulusLengthOption(options)
      };
      keyUsages = ["decrypt", "unwrapKey", "encrypt", "wrapKey"];
      break;
    case "ES256":
      algorithm = { name: "ECDSA", namedCurve: "P-256" };
      keyUsages = ["sign", "verify"];
      break;
    case "ES384":
      algorithm = { name: "ECDSA", namedCurve: "P-384" };
      keyUsages = ["sign", "verify"];
      break;
    case "ES512":
      algorithm = { name: "ECDSA", namedCurve: "P-521" };
      keyUsages = ["sign", "verify"];
      break;
    case "Ed25519":
      algorithm = { name: "Ed25519" };
      keyUsages = ["sign", "verify"];
      break;
    case "EdDSA": {
      keyUsages = ["sign", "verify"];
      const crv = options?.crv ?? "Ed25519";
      switch (crv) {
        case "Ed25519":
        case "Ed448":
          algorithm = { name: crv };
          break;
        default:
          throw new JOSENotSupported("Invalid or unsupported crv option provided");
      }
      break;
    }
    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      keyUsages = ["deriveKey", "deriveBits"];
      const crv = options?.crv ?? "P-256";
      switch (crv) {
        case "P-256":
        case "P-384":
        case "P-521": {
          algorithm = { name: "ECDH", namedCurve: crv };
          break;
        }
        case "X25519":
        case "X448":
          algorithm = { name: crv };
          break;
        default:
          throw new JOSENotSupported("Invalid or unsupported crv option provided, supported values are P-256, P-384, P-521, X25519, and X448");
      }
      break;
    }
    default:
      throw new JOSENotSupported('Invalid or unsupported JWK "alg" (Algorithm) Parameter value');
  }
  return webcrypto_default.subtle.generateKey(algorithm, options?.extractable ?? false, keyUsages);
}
var init_generate = __esm({
  "node_modules/jose/dist/browser/runtime/generate.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_webcrypto();
    init_errors();
    init_random();
    __name(generateSecret, "generateSecret");
    __name(getModulusLengthOption, "getModulusLengthOption");
    __name(generateKeyPair, "generateKeyPair");
  }
});

// node_modules/jose/dist/browser/key/generate_key_pair.js
async function generateKeyPair2(alg, options) {
  return generateKeyPair(alg, options);
}
var init_generate_key_pair = __esm({
  "node_modules/jose/dist/browser/key/generate_key_pair.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_generate();
    __name(generateKeyPair2, "generateKeyPair");
  }
});

// node_modules/jose/dist/browser/key/generate_secret.js
async function generateSecret2(alg, options) {
  return generateSecret(alg, options);
}
var init_generate_secret = __esm({
  "node_modules/jose/dist/browser/key/generate_secret.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_generate();
    __name(generateSecret2, "generateSecret");
  }
});

// node_modules/jose/dist/browser/runtime/runtime.js
var runtime_default;
var init_runtime = __esm({
  "node_modules/jose/dist/browser/runtime/runtime.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    runtime_default = "WebCryptoAPI";
  }
});

// node_modules/jose/dist/browser/util/runtime.js
var runtime_default2;
var init_runtime2 = __esm({
  "node_modules/jose/dist/browser/util/runtime.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_runtime();
    runtime_default2 = runtime_default;
  }
});

// node_modules/jose/dist/browser/index.js
var browser_exports = {};
__export(browser_exports, {
  CompactEncrypt: () => CompactEncrypt,
  CompactSign: () => CompactSign,
  EmbeddedJWK: () => EmbeddedJWK,
  EncryptJWT: () => EncryptJWT,
  FlattenedEncrypt: () => FlattenedEncrypt,
  FlattenedSign: () => FlattenedSign,
  GeneralEncrypt: () => GeneralEncrypt,
  GeneralSign: () => GeneralSign,
  SignJWT: () => SignJWT,
  UnsecuredJWT: () => UnsecuredJWT,
  base64url: () => base64url_exports2,
  calculateJwkThumbprint: () => calculateJwkThumbprint,
  calculateJwkThumbprintUri: () => calculateJwkThumbprintUri,
  compactDecrypt: () => compactDecrypt,
  compactVerify: () => compactVerify,
  createLocalJWKSet: () => createLocalJWKSet,
  createRemoteJWKSet: () => createRemoteJWKSet,
  cryptoRuntime: () => runtime_default2,
  decodeJwt: () => decodeJwt,
  decodeProtectedHeader: () => decodeProtectedHeader,
  errors: () => errors_exports,
  experimental_jwksCache: () => experimental_jwksCache,
  exportJWK: () => exportJWK,
  exportPKCS8: () => exportPKCS8,
  exportSPKI: () => exportSPKI,
  flattenedDecrypt: () => flattenedDecrypt,
  flattenedVerify: () => flattenedVerify,
  generalDecrypt: () => generalDecrypt,
  generalVerify: () => generalVerify,
  generateKeyPair: () => generateKeyPair2,
  generateSecret: () => generateSecret2,
  importJWK: () => importJWK,
  importPKCS8: () => importPKCS8,
  importSPKI: () => importSPKI,
  importX509: () => importX509,
  jwksCache: () => jwksCache,
  jwtDecrypt: () => jwtDecrypt,
  jwtVerify: () => jwtVerify
});
var init_browser = __esm({
  "node_modules/jose/dist/browser/index.js"() {
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    init_decrypt3();
    init_decrypt2();
    init_decrypt4();
    init_encrypt3();
    init_verify3();
    init_verify2();
    init_verify4();
    init_verify5();
    init_decrypt5();
    init_encrypt4();
    init_encrypt2();
    init_sign3();
    init_sign2();
    init_sign4();
    init_sign5();
    init_encrypt5();
    init_thumbprint();
    init_embedded();
    init_local();
    init_remote();
    init_unsecured();
    init_export();
    init_import();
    init_decode_protected_header();
    init_decode_jwt();
    init_errors();
    init_generate_key_pair();
    init_generate_secret();
    init_base64url2();
    init_runtime2();
  }
});

// node_modules/stytch/dist/shared/envs.js
var require_envs = __commonJS({
  "node_modules/stytch/dist/shared/envs.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.test = exports.live = exports.fraud = void 0;
    var test = exports.test = "https://test.stytch.com/";
    var live = exports.live = "https://api.stytch.com/";
    var fraud = exports.fraud = "https://telemetry.stytch.com/";
  }
});

// node_modules/stytch/package.json
var require_package = __commonJS({
  "node_modules/stytch/package.json"(exports, module) {
    module.exports = {
      name: "stytch",
      version: "12.19.0",
      description: "A wrapper for the Stytch API",
      types: "./types/lib/index.d.ts",
      main: "./dist/index.js",
      type: "commonjs",
      exports: {
        types: "./types/lib/index.d.ts",
        require: "./dist/index.js",
        default: "./dist/index.js"
      },
      files: [
        "dist/**/*",
        "types/**/*"
      ],
      repository: {
        type: "git",
        url: "git://github.com/stytchauth/stytch-node.git"
      },
      engines: {
        node: ">= 18.0.0"
      },
      scripts: {
        build: "rm -rf dist types && babel lib --out-dir dist --extensions '.ts' && tsc --declaration --outDir types --emitDeclarationOnly",
        format: "prettier --write .",
        "check-format": "prettier --check .",
        lint: "eslint lib",
        test: "jest",
        "test-packages": "./test-packages/test.sh"
      },
      author: "Stytch",
      bugs: {
        url: "git://github.com/stytchauth/stytch-node/issues"
      },
      license: "MIT",
      devDependencies: {
        "@babel/cli": "^7.23.0",
        "@babel/core": "^7.23.0",
        "@babel/preset-env": "^7.22.20",
        "@babel/preset-typescript": "^7.23.0",
        "@types/jest": "^29.5.5",
        "@types/node": "^20.14.8",
        "@typescript-eslint/eslint-plugin": "^4.33.0",
        "@typescript-eslint/parser": "^4.33.0",
        eslint: "^7.32.0",
        jest: "^29.7.0",
        prettier: "2.4.1",
        "ts-jest": "^29.1.1",
        typescript: "^5.5.4"
      },
      dependencies: {
        jose: "^5.6.3",
        undici: "^6.19.5"
      },
      eslintConfig: {
        extends: "airbnb",
        env: {
          commonjs: true,
          node: true,
          mocha: true
        },
        rules: {
          indent: [
            "error",
            4
          ],
          "no-underscore-dangle": 0,
          strict: 0,
          "prefer-rest-params": 0
        }
      }
    };
  }
});

// node_modules/stytch/dist/shared/base64.js
var require_base64 = __commonJS({
  "node_modules/stytch/dist/shared/base64.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.base64Encode = base64Encode;
    var LOOKUP_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    function base64Encode(input) {
      let output = "";
      for (let i2 = 0; i2 < input.length; i2++) {
        if (input.charCodeAt(i2) > 128) {
          throw Error("Base64 encoded unicode is not supported. Cannot encode " + input);
        }
      }
      let char1 = 0, char2 = 0, char3 = 0;
      let enc1 = 0, enc2 = 0, enc3 = 0, enc4 = 0;
      let i = 0;
      while (i < input.length) {
        char1 = input.charCodeAt(i++);
        char2 = input.charCodeAt(i++);
        char3 = input.charCodeAt(i++);
        enc1 = char1 >> 2;
        enc2 = (char1 & 3) << 4 | char2 >> 4;
        enc3 = (char2 & 15) << 2 | char3 >> 6;
        enc4 = char3 & 63;
        if (isNaN(char2)) {
          enc3 = enc4 = 64;
        } else if (isNaN(char3)) {
          enc4 = 64;
        }
        output = output + LOOKUP_TABLE.charAt(enc1) + LOOKUP_TABLE.charAt(enc2) + LOOKUP_TABLE.charAt(enc3) + LOOKUP_TABLE.charAt(enc4);
      }
      return output;
    }
    __name(base64Encode, "base64Encode");
  }
});

// node_modules/stytch/dist/shared/client.js
var require_client = __commonJS({
  "node_modules/stytch/dist/shared/client.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.BaseClient = void 0;
    var envs = _interopRequireWildcard(require_envs());
    var _package = require_package();
    var _base = require_base64();
    function _getRequireWildcardCache(nodeInterop) {
      if (typeof WeakMap !== "function") return null;
      var cacheBabelInterop = /* @__PURE__ */ new WeakMap();
      var cacheNodeInterop = /* @__PURE__ */ new WeakMap();
      return (_getRequireWildcardCache = /* @__PURE__ */ __name(function(nodeInterop2) {
        return nodeInterop2 ? cacheNodeInterop : cacheBabelInterop;
      }, "_getRequireWildcardCache"))(nodeInterop);
    }
    __name(_getRequireWildcardCache, "_getRequireWildcardCache");
    function _interopRequireWildcard(obj, nodeInterop) {
      if (!nodeInterop && obj && obj.__esModule) {
        return obj;
      }
      if (obj === null || typeof obj !== "object" && typeof obj !== "function") {
        return { default: obj };
      }
      var cache = _getRequireWildcardCache(nodeInterop);
      if (cache && cache.has(obj)) {
        return cache.get(obj);
      }
      var newObj = {};
      var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor;
      for (var key in obj) {
        if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) {
          var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null;
          if (desc && (desc.get || desc.set)) {
            Object.defineProperty(newObj, key, desc);
          } else {
            newObj[key] = obj[key];
          }
        }
      }
      newObj.default = obj;
      if (cache) {
        cache.set(obj, newObj);
      }
      return newObj;
    }
    __name(_interopRequireWildcard, "_interopRequireWildcard");
    var DEFAULT_TIMEOUT = 10 * 60 * 1e3;
    var BaseClient = class {
      static {
        __name(this, "BaseClient");
      }
      constructor(config) {
        if (typeof config != "object") {
          throw new Error("Unexpected config type. Refer to https://github.com/stytchauth/stytch-node for how to use the Node client library.");
        }
        if (!config.project_id) {
          throw new Error('Missing "project_id" in config');
        }
        if (!config.secret) {
          throw new Error('Missing "secret" in config');
        }
        if (config.env && config.custom_base_url) {
          console.warn(`[Stytch] Warning: Both 'env' and 'base_url' were provided in the client config. 'env' will be ignored in favor of 'base_url'.`);
        }
        if (config.custom_base_url && !config.custom_base_url.startsWith("https://")) {
          throw new Error("custom_base_url must use HTTPS scheme");
        }
        if (!config.env) {
          if (config.project_id.startsWith("project-live-")) {
            config.env = envs.live;
          } else {
            config.env = envs.test;
          }
        }
        if (!config.fraud_env) {
          config.fraud_env = envs.fraud;
        }
        if (config.env != envs.test && config.env != envs.live) {
          console.warn(`[Stytch] Warning: Using a custom 'env' value ("${config.env}") instead of 'envs.test' or 'envs.live". If you're attempting to use a custom baseURL consider the base_url parameter.`);
        }
        const headers = {
          "Content-Type": "application/json",
          "User-Agent": `Stytch Node v${_package.version}`,
          Authorization: "Basic " + (0, _base.base64Encode)(config.project_id + ":" + config.secret)
        };
        const baseURL = config.custom_base_url || config.env;
        this.fetchConfig = {
          baseURL,
          fraudBaseURL: config.fraud_env,
          headers,
          timeout: config.timeout || DEFAULT_TIMEOUT,
          dispatcher: config.dispatcher
        };
        this.baseURL = baseURL;
        if (!this.baseURL.endsWith("/")) {
          this.baseURL += "/";
        }
      }
    };
    exports.BaseClient = BaseClient;
  }
});

// node_modules/stytch/dist/shared/method_options.js
var require_method_options = __commonJS({
  "node_modules/stytch/dist/shared/method_options.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.addAuthorizationHeaders = addAuthorizationHeaders;
    function addAuthorizationHeaders(headers, authorization) {
      if (authorization.session_token) {
        headers["X-Stytch-Member-Session"] = authorization.session_token;
      }
      if (authorization.session_jwt) {
        headers["X-Stytch-Member-SessionJWT"] = authorization.session_jwt;
      }
    }
    __name(addAuthorizationHeaders, "addAuthorizationHeaders");
  }
});

// node_modules/stytch/dist/shared/errors.js
var require_errors = __commonJS({
  "node_modules/stytch/dist/shared/errors.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.StytchError = exports.RequestError = exports.ClientError = void 0;
    var StytchError = class extends Error {
      static {
        __name(this, "StytchError");
      }
      constructor(data) {
        super(JSON.stringify(data));
        if ("error" in data) {
          this.status_code = data.status_code;
          this.request_id = data.request_id;
          this.error_type = data.error;
          this.error_message = data.error_description;
          this.error_url = data.error_uri;
        } else {
          this.status_code = data.status_code;
          this.request_id = data.request_id;
          this.error_type = data.error_type;
          this.error_message = data.error_message;
          this.error_url = data.error_url;
          this.error_details = data.error_details;
        }
      }
    };
    exports.StytchError = StytchError;
    var RequestError = class extends Error {
      static {
        __name(this, "RequestError");
      }
      constructor(message2, request) {
        super(message2);
        this.request = request;
      }
    };
    exports.RequestError = RequestError;
    var ClientError = class extends Error {
      static {
        __name(this, "ClientError");
      }
      constructor(code, message2, cause) {
        let msg = `${code}: ${message2}`;
        if (cause) {
          msg += `: ${cause}`;
        }
        super(msg);
        this.code = code;
        this.cause = cause;
      }
    };
    exports.ClientError = ClientError;
  }
});

// node_modules/stytch/dist/shared/index.js
var require_shared = __commonJS({
  "node_modules/stytch/dist/shared/index.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.request = request;
    var _errors = require_errors();
    async function request(fetchConfig, requestConfig) {
      const baseURL = requestConfig.baseURLType == "FRAUD" ? fetchConfig.fraudBaseURL : fetchConfig.baseURL;
      const url = new URL(requestConfig.url, baseURL);
      if (requestConfig.params) {
        Object.entries(requestConfig.params).forEach(([key, value]) => {
          if (value !== void 0) {
            url.searchParams.append(key, String(value));
          }
        });
      }
      const finalHeaders = {
        ...fetchConfig.headers,
        ...requestConfig.headers
      };
      let response;
      try {
        const body = requestConfig.data ? JSON.stringify(requestConfig.data) : requestConfig.dataRaw;
        response = await fetch(url.toString(), {
          method: requestConfig.method,
          body,
          // @ts-expect-error [AUTH-2047] things fail catastrophically when using the NextJS fetch-cache
          // so we need to explicitly opt out of it using the "no-store" tag - which isn't part of the core Node fetch API
          cache: "no-store",
          ...fetchConfig,
          headers: finalHeaders
        });
      } catch (e) {
        const err = e;
        throw new _errors.RequestError(err.message, requestConfig);
      }
      let responseJSON;
      try {
        responseJSON = await response.json();
      } catch (e) {
        const err = e;
        throw new _errors.RequestError(`Unable to parse JSON response from server: ${err.message}`, requestConfig);
      }
      if (response.status >= 400) {
        throw new _errors.StytchError(responseJSON);
      }
      return responseJSON;
    }
    __name(request, "request");
  }
});

// node_modules/stytch/dist/b2c/crypto_wallets.js
var require_crypto_wallets = __commonJS({
  "node_modules/stytch/dist/b2c/crypto_wallets.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.CryptoWallets = void 0;
    require_method_options();
    var _shared = require_shared();
    var CryptoWallets = class {
      static {
        __name(this, "CryptoWallets");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Initiate the authentication of a crypto wallet. After calling this endpoint, the user will need to sign
       * a message containing the returned `challenge` field.
       *
       * For Ethereum crypto wallets, you can optionally use the Sign In With Ethereum (SIWE) protocol for the
       * message by passing in the `siwe_params`. The only required fields are `domain` and `uri`.
       * If the crypto wallet detects that the domain in the message does not match the website's domain, it will
       * display a warning to the user.
       *
       * If not using the SIWE protocol, the message will simply consist of the project name and a random string.
       * @param data {@link CryptoWalletsAuthenticateStartRequest}
       * @returns {@link CryptoWalletsAuthenticateStartResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticateStart(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/crypto_wallets/authenticate/start`,
          headers,
          data
        });
      }
      /**
       * Complete the authentication of a crypto wallet by passing the signature.
       * @param data {@link CryptoWalletsAuthenticateRequest}
       * @returns {@link CryptoWalletsAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/crypto_wallets/authenticate`,
          headers,
          data
        });
      }
    };
    exports.CryptoWallets = CryptoWallets;
  }
});

// node_modules/stytch/dist/b2c/fraud_fingerprint.js
var require_fraud_fingerprint = __commonJS({
  "node_modules/stytch/dist/b2c/fraud_fingerprint.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Fingerprint = void 0;
    require_method_options();
    var _shared = require_shared();
    var Fingerprint = class {
      static {
        __name(this, "Fingerprint");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Lookup the associated fingerprint for the `telemetry_id` returned from the `GetTelemetryID` function.
       * Learn more about the different fingerprint types and verdicts in our
       * [DFP guide](https://stytch.com/docs/fraud/guides/device-fingerprinting/overview).
       *
       * Make a decision based on the returned `verdict`:
       * * `ALLOW` - This is a known valid device grouping or device profile that is part of the default `ALLOW`
       * listed set of known devices by Stytch. This grouping is made up of  verified device profiles that match
       * the characteristics of known/authentic traffic origins.
       * * `BLOCK` - This is a known bad or malicious device profile that is undesirable and should be blocked
       * from completing the privileged action in question.
       * * `CHALLENGE` - This is an unknown or potentially malicious device that should be put through increased
       * friction such as 2FA or other forms of extended user verification before allowing the privileged action
       * to proceed.
       *
       * If the `telemetry_id` is not found, we will return a 404 `telemetry_id_not_found`
       * [error](https://stytch.com/docs/fraud/api/errors/404#telemetry_id_not_found). We recommend treating 404
       * errors as a `BLOCK`, since it could be a sign of an attacker trying to bypass DFP protections by
       * generating fake telemetry IDs.
       * @param data {@link FraudFingerprintLookupRequest}
       * @returns {@link FraudFingerprintLookupResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      lookup(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/fingerprint/lookup`,
          baseURLType: "FRAUD",
          headers,
          data
        });
      }
    };
    exports.Fingerprint = Fingerprint;
  }
});

// node_modules/stytch/dist/b2c/fraud_rules.js
var require_fraud_rules = __commonJS({
  "node_modules/stytch/dist/b2c/fraud_rules.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Rules = void 0;
    require_method_options();
    var _shared = require_shared();
    var Rules = class {
      static {
        __name(this, "Rules");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Set a rule for a particular `visitor_id`, `browser_id`, `visitor_fingerprint`, `browser_fingerprint`,
       * `hardware_fingerprint`, `network_fingerprint`, `cidr_block`, `asn`, or `country_code`. This is helpful
       * in cases where you want to allow or block a specific user or fingerprint. You should be careful when
       * setting rules for `browser_fingerprint`, `hardware_fingerprint`, or `network_fingerprint` as they can be
       * shared across multiple users, and you could affect more users than intended.
       *
       * You may not set an `ALLOW` rule for a `country_code`.
       *
       * Rules are applied in the order specified above. For example, if an end user has an `ALLOW` rule set for
       * their `visitor_id` but a `BLOCK` rule set for their `hardware_fingerprint`, they will receive an `ALLOW`
       * verdict because the `visitor_id` rule takes precedence.
       *
       * If there are conflicts between multiple `cidr_block` rules (for example, if the `ip_address` of the end
       * user overlaps with multiple CIDR blocks that have rules set), the conflicts are resolved as follows:
       * - The smallest block size takes precedence. For example, if an `ip_address` overlaps with a `cidr_block`
       * rule of `ALLOW` for a block with a prefix of `/32` and a `cidr_block` rule of `BLOCK` with a prefix of
       * `/24`, the rule match verdict will be `ALLOW`.
       * - Among equivalent size blocks, `BLOCK` takes precedence over `CHALLENGE`, which takes precedence over
       * `ALLOW`. For example, if an `ip_address` overlaps with two `cidr_block` rules with blocks of the same
       * size that return `CHALLENGE` and `ALLOW`, the rule match verdict will be `CHALLENGE`.
       * @param data {@link FraudRulesSetRequest}
       * @returns {@link FraudRulesSetResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      set(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/rules/set`,
          baseURLType: "FRAUD",
          headers,
          data
        });
      }
      /**
       * Get all rules that have been set for your project.
       * @param data {@link FraudRulesListRequest}
       * @returns {@link FraudRulesListResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      list(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/rules/list`,
          baseURLType: "FRAUD",
          headers,
          data
        });
      }
    };
    exports.Rules = Rules;
  }
});

// node_modules/stytch/dist/b2c/fraud.js
var require_fraud = __commonJS({
  "node_modules/stytch/dist/b2c/fraud.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Fraud = void 0;
    require_method_options();
    var _fraud_fingerprint = require_fraud_fingerprint();
    var _fraud_rules = require_fraud_rules();
    var Fraud = class {
      static {
        __name(this, "Fraud");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
        this.fingerprint = new _fraud_fingerprint.Fingerprint(this.fetchConfig);
        this.rules = new _fraud_rules.Rules(this.fetchConfig);
      }
    };
    exports.Fraud = Fraud;
  }
});

// node_modules/stytch/dist/b2c/impersonation.js
var require_impersonation = __commonJS({
  "node_modules/stytch/dist/b2c/impersonation.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Impersonation = void 0;
    require_method_options();
    var _shared = require_shared();
    var Impersonation = class {
      static {
        __name(this, "Impersonation");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Authenticate an impersonation token to impersonate a User. This endpoint requires an impersonation token
       * that is not expired or previously used.
       * A Stytch session will be created for the impersonated user with a 60 minute duration. Impersonated
       * sessions cannot be extended.
       *
       * Prior to this step, you can generate an impersonation token by visiting the Stytch dashboard, viewing a
       * user, and clicking the `Impersonate User` button.
       * @param data {@link ImpersonationAuthenticateRequest}
       * @returns {@link ImpersonationAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/impersonation/authenticate`,
          headers,
          data
        });
      }
    };
    exports.Impersonation = Impersonation;
  }
});

// node_modules/stytch/dist/shared/sessions.js
var require_sessions = __commonJS({
  "node_modules/stytch/dist/shared/sessions.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.authenticateJwtLocal = authenticateJwtLocal;
    exports.authenticateM2MJwtLocal = authenticateM2MJwtLocal;
    exports.authenticateSessionJwtLocal = authenticateSessionJwtLocal;
    exports.trimTrailingSlash = trimTrailingSlash;
    var jose = _interopRequireWildcard((init_browser(), __toCommonJS(browser_exports)));
    var _errors = require_errors();
    function _getRequireWildcardCache(nodeInterop) {
      if (typeof WeakMap !== "function") return null;
      var cacheBabelInterop = /* @__PURE__ */ new WeakMap();
      var cacheNodeInterop = /* @__PURE__ */ new WeakMap();
      return (_getRequireWildcardCache = /* @__PURE__ */ __name(function(nodeInterop2) {
        return nodeInterop2 ? cacheNodeInterop : cacheBabelInterop;
      }, "_getRequireWildcardCache"))(nodeInterop);
    }
    __name(_getRequireWildcardCache, "_getRequireWildcardCache");
    function _interopRequireWildcard(obj, nodeInterop) {
      if (!nodeInterop && obj && obj.__esModule) {
        return obj;
      }
      if (obj === null || typeof obj !== "object" && typeof obj !== "function") {
        return { default: obj };
      }
      var cache = _getRequireWildcardCache(nodeInterop);
      if (cache && cache.has(obj)) {
        return cache.get(obj);
      }
      var newObj = {};
      var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor;
      for (var key in obj) {
        if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) {
          var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null;
          if (desc && (desc.get || desc.set)) {
            Object.defineProperty(newObj, key, desc);
          } else {
            newObj[key] = obj[key];
          }
        }
      }
      newObj.default = obj;
      if (cache) {
        cache.set(obj, newObj);
      }
      return newObj;
    }
    __name(_interopRequireWildcard, "_interopRequireWildcard");
    var sessionClaim = "https://stytch.com/session";
    function trimTrailingSlash(baseURL) {
      while (baseURL.endsWith("/")) {
        baseURL = baseURL.slice(0, -1);
      }
      return baseURL;
    }
    __name(trimTrailingSlash, "trimTrailingSlash");
    async function authenticateJwtLocal(jwksClient, jwtOptions, jwt, options) {
      const now = options?.current_date || /* @__PURE__ */ new Date();
      let payload;
      try {
        const token = await jose.jwtVerify(jwt, jwksClient, {
          ...jwtOptions,
          clockTolerance: options?.clock_tolerance_seconds,
          currentDate: now
          // Don't pass maxTokenAge directly to jwtVerify because it interprets zero as "infinity".
          // We want zero to mean "every token is stale" and force remote verification.
        });
        payload = token.payload;
      } catch (err) {
        throw new _errors.ClientError("jwt_invalid", "Could not verify JWT", err);
      }
      const maxTokenAge = options?.max_token_age_seconds;
      if (maxTokenAge != null) {
        const iat = payload.iat;
        if (!iat) {
          throw new _errors.ClientError("jwt_invalid", "JWT was missing iat claim");
        }
        const nowEpoch = +now / 1e3;
        if (nowEpoch - iat >= maxTokenAge) {
          throw new _errors.ClientError("jwt_too_old", `JWT was issued at ${iat}, more than ${maxTokenAge} seconds ago`);
        }
      }
      const {
        /* eslint-disable @typescript-eslint/no-unused-vars */
        aud: _aud,
        exp: _exp,
        iat: _iat,
        iss: _iss,
        jti: _jti,
        nbf: _nbf,
        sub: _sub,
        /* eslint-enable @typescript-eslint/no-unused-vars */
        ...customClaims
      } = payload;
      return {
        payload,
        customClaims
      };
    }
    __name(authenticateJwtLocal, "authenticateJwtLocal");
    async function authenticateM2MJwtLocal(jwksClient, jwtOptions, jwt, options) {
      const {
        payload,
        customClaims: untypedClaims
      } = await authenticateJwtLocal(jwksClient, jwtOptions, jwt, options);
      const {
        scope: scopeClaim,
        ...customClaims
      } = untypedClaims;
      const scope = scopeClaim;
      return {
        sub: payload.sub ?? "",
        scope,
        custom_claims: customClaims
      };
    }
    __name(authenticateM2MJwtLocal, "authenticateM2MJwtLocal");
    async function authenticateSessionJwtLocal(jwksClient, jwtOptions, jwt, options) {
      const {
        payload,
        customClaims: untypedClaims
      } = await authenticateJwtLocal(jwksClient, jwtOptions, jwt, options);
      const {
        [sessionClaim]: stytchClaim,
        ...customClaims
      } = untypedClaims;
      const claim = stytchClaim;
      return {
        session_id: claim.id,
        attributes: claim.attributes,
        authentication_factors: claim.authentication_factors,
        sub: payload.sub || "",
        // The JWT expiration time is the same as the session's.
        // The exp claim is a Unix timestamp in seconds, so convert it to milliseconds first. The
        // other timestamps are RFC3339-formatted strings.
        started_at: claim.started_at,
        last_accessed_at: claim.last_accessed_at,
        // For JWTs that include it, prefer the inner expires_at claim.
        expires_at: new Date(claim.expires_at || (payload.exp || 0) * 1e3).toISOString(),
        custom_claims: customClaims,
        roles: claim.roles
      };
    }
    __name(authenticateSessionJwtLocal, "authenticateSessionJwtLocal");
  }
});

// node_modules/stytch/dist/b2c/m2m_clients_secrets.js
var require_m2m_clients_secrets = __commonJS({
  "node_modules/stytch/dist/b2c/m2m_clients_secrets.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Secrets = void 0;
    require_method_options();
    var _shared = require_shared();
    var Secrets = class {
      static {
        __name(this, "Secrets");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Initiate the rotation of an M2M client secret. After this endpoint is called, both the client's
       * `client_secret` and `next_client_secret` will be valid. To complete the secret rotation flow, update all
       * usages of `client_secret` to `next_client_secret` and call the
       * [Rotate Secret Endpoint](https://stytch.com/docs/b2b/api/m2m-rotate-secret)[Rotate Secret Endpoint](https://stytch.com/docs/api/m2m-rotate-secret) to complete the flow.Secret rotation can be cancelled using the [Rotate Cancel Endpoint](https://stytch.com/docs/b2b/api/m2m-rotate-secret-cancel)[Rotate Cancel Endpoint](https://stytch.com/docs/api/m2m-rotate-secret-cancel).
       *
       * **Important:** This is the only time you will be able to view the generated `next_client_secret` in the
       * API response. Stytch stores a hash of the `next_client_secret` and cannot recover the value if lost. Be
       * sure to persist the `next_client_secret` in a secure location. If the `next_client_secret` is lost, you
       * will need to trigger a secret rotation flow to receive another one.
       * @param data {@link M2MClientsSecretsRotateStartRequest}
       * @returns {@link M2MClientsSecretsRotateStartResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      rotateStart(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/m2m/clients/${data.client_id}/secrets/rotate/start`,
          headers,
          data: {}
        });
      }
      /**
       * Cancel the rotation of an M2M client secret started with the
       * [Start Secret Rotation Endpoint](https://stytch.com/docs/b2b/api/m2m-rotate-secret-start)
       * [Start Secret Rotation Endpoint](https://stytch.com/docs/api/m2m-rotate-secret-start).
       * After this endpoint is called, the client's `next_client_secret` is discarded and only the original
       * `client_secret` will be valid.
       * @param data {@link M2MClientsSecretsRotateCancelRequest}
       * @returns {@link M2MClientsSecretsRotateCancelResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      rotateCancel(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/m2m/clients/${data.client_id}/secrets/rotate/cancel`,
          headers,
          data: {}
        });
      }
      /**
       * Complete the rotation of an M2M client secret started with the
       * [Start Secret Rotation Endpoint](https://stytch.com/docs/b2b/api/m2m-rotate-secret-start)
       * [Start Secret Rotation Endpoint](https://stytch.com/docs/api/m2m-rotate-secret-start).
       * After this endpoint is called, the client's `next_client_secret` becomes its `client_secret` and the
       * previous `client_secret` will no longer be valid.
       * @param data {@link M2MClientsSecretsRotateRequest}
       * @returns {@link M2MClientsSecretsRotateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      rotate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/m2m/clients/${data.client_id}/secrets/rotate`,
          headers,
          data: {}
        });
      }
    };
    exports.Secrets = Secrets;
  }
});

// node_modules/stytch/dist/b2c/m2m_clients.js
var require_m2m_clients = __commonJS({
  "node_modules/stytch/dist/b2c/m2m_clients.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Clients = void 0;
    require_method_options();
    var _shared = require_shared();
    var _m2m_clients_secrets = require_m2m_clients_secrets();
    var Clients = class {
      static {
        __name(this, "Clients");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
        this.secrets = new _m2m_clients_secrets.Secrets(this.fetchConfig);
      }
      /**
       * Gets information about an existing M2M Client.
       * @param params {@link M2MClientsGetRequest}
       * @returns {@link M2MClientsGetResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      get(params) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/m2m/clients/${params.client_id}`,
          headers,
          params: {}
        });
      }
      /**
       * Search for M2M Clients within your Stytch Project. Submit an empty `query` in the request to return all
       * M2M Clients.
       *
       * The following search filters are supported today:
       * - `client_id`: Pass in a list of client IDs to get many clients in a single request
       * - `client_name`: Search for clients by exact match on client name
       * - `scopes`: Search for clients assigned a specific scope
       * @param data {@link M2MClientsSearchRequest}
       * @returns {@link M2MClientsSearchResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      search(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/m2m/clients/search`,
          headers,
          data
        });
      }
      /**
       * Updates an existing M2M Client. You can use this endpoint to activate or deactivate a M2M Client by
       * changing its `status`. A deactivated M2M Client will not be allowed to perform future token exchange
       * flows until it is reactivated.
       *
       * **Important:** Deactivating a M2M Client will not invalidate any existing JWTs issued to the client,
       * only prevent it from receiving new ones.
       * To protect more-sensitive routes, pass a lower `max_token_age` value
       * when[authenticating the token](https://stytch.com/docs/b2b/api/authenticate-m2m-token)[authenticating the token](https://stytch.com/docs/api/authenticate-m2m-token).
       * @param data {@link M2MClientsUpdateRequest}
       * @returns {@link M2MClientsUpdateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      update(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "PUT",
          url: `/v1/m2m/clients/${data.client_id}`,
          headers,
          data: {
            client_name: data.client_name,
            client_description: data.client_description,
            status: data.status,
            scopes: data.scopes,
            trusted_metadata: data.trusted_metadata
          }
        });
      }
      /**
       * Deletes the M2M Client.
       *
       * **Important:** Deleting a M2M Client will not invalidate any existing JWTs issued to the client, only
       * prevent it from receiving new ones.
       * To protect more-sensitive routes, pass a lower `max_token_age` value
       * when[authenticating the token](https://stytch.com/docs/b2b/api/authenticate-m2m-token)[authenticating the token](https://stytch.com/docs/api/authenticate-m2m-token).
       * @param data {@link M2MClientsDeleteRequest}
       * @returns {@link M2MClientsDeleteResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      delete(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "DELETE",
          url: `/v1/m2m/clients/${data.client_id}`,
          headers,
          data: {}
        });
      }
      /**
       * Creates a new M2M Client. On initial client creation, you may pass in a custom `client_id` or
       * `client_secret` to import an existing M2M client. If you do not pass in a custom `client_id` or
       * `client_secret`, one will be generated automatically. The `client_id` must be unique among all clients
       * in your project.
       *
       * **Important:** This is the only time you will be able to view the generated `client_secret` in the API
       * response. Stytch stores a hash of the `client_secret` and cannot recover the value if lost. Be sure to
       * persist the `client_secret` in a secure location. If the `client_secret` is lost, you will need to
       * trigger a secret rotation flow to receive another one.
       * @param data {@link M2MClientsCreateRequest}
       * @returns {@link M2MClientsCreateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      create(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/m2m/clients`,
          headers,
          data
        });
      }
    };
    exports.Clients = Clients;
  }
});

// node_modules/stytch/dist/b2c/m2m_local.js
var require_m2m_local = __commonJS({
  "node_modules/stytch/dist/b2c/m2m_local.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.performAuthorizationCheck = performAuthorizationCheck;
    function performAuthorizationCheck({
      hasScopes,
      requiredScopes
    }) {
      const clientScopes = {};
      hasScopes.forEach((scope) => {
        let action = scope;
        let resource = "-";
        if (scope.includes(":")) {
          [action, resource] = scope.split(":");
        }
        if (!clientScopes[action]) {
          clientScopes[action] = /* @__PURE__ */ new Set();
        }
        clientScopes[action].add(resource);
      });
      for (const requiredScope of requiredScopes) {
        let requiredAction = requiredScope;
        let requiredResource = "-";
        if (requiredScope.includes(":")) {
          [requiredAction, requiredResource] = requiredScope.split(":");
        }
        if (!clientScopes[requiredAction]) {
          return false;
        }
        const resources = clientScopes[requiredAction];
        if (!resources.has("*") && !resources.has(requiredResource)) {
          return false;
        }
      }
      return true;
    }
    __name(performAuthorizationCheck, "performAuthorizationCheck");
  }
});

// node_modules/stytch/dist/b2c/m2m.js
var require_m2m = __commonJS({
  "node_modules/stytch/dist/b2c/m2m.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.M2M = void 0;
    require_method_options();
    var _m2m_clients = require_m2m_clients();
    var _sessions = require_sessions();
    var _errors = require_errors();
    var _m2m_local = require_m2m_local();
    var _shared = require_shared();
    var M2M = class {
      static {
        __name(this, "M2M");
      }
      constructor(fetchConfig, jwtConfig) {
        this.fetchConfig = fetchConfig;
        this.clients = new _m2m_clients.Clients(this.fetchConfig);
        this.jwksClient = jwtConfig.jwks;
        this.jwtOptions = {
          audience: jwtConfig.projectID,
          issuer: jwtConfig.issuers,
          typ: "JWT"
        };
      }
      // MANUAL(token)(SERVICE_METHOD)
      /**
       * Retrieve an access token for the given M2M Client.
       * Access tokens are JWTs signed with the project's JWKS, and are valid for one hour after issuance.
       * M2M Access tokens contain a standard set of claims as well as any custom claims generated from templates.
       *
       * M2M Access tokens can be validated locally using the Authenticate Access Token method in the Stytch Backend SDKs,
       * or with any library that supports JWT signature validation.
       *
       * Here is an example of a standard set of claims from a M2M Access Token:
       *   ```
       *  {
       *    "sub": "m2m-client-test-d731954d-dab3-4a2b-bdee-07f3ad1be885",
       *    "iss": "stytch.com/project-test-3e71d0a1-1e3e-4ee2-9be0-d7c0900f02c2",
       *    "aud": ["project-test-3e71d0a1-1e3e-4ee2-9be0-d7c0900f02c2"],
       *    "scope": "read:users write:users",
       *    "iat": 4102473300,
       *    "nbf": 4102473300,
       *    "exp": 4102476900
       *  }
       *  ```
       * @param data {@link TokenRequest}
       * @async
       * @returns {@link TokenResponse}
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      async token(data) {
        const fetchConfig = {
          ...this.fetchConfig,
          headers: {
            ["User-Agent"]: this.fetchConfig.headers["User-Agent"],
            "Content-Type": "application/x-www-form-urlencoded"
          }
        };
        const params = {
          client_id: data.client_id,
          client_secret: data.client_secret,
          grant_type: "client_credentials"
        };
        if (data.scopes && data.scopes.length > 0) {
          params.scope = data.scopes?.join(" ");
        }
        return (0, _shared.request)(fetchConfig, {
          method: "POST",
          url: `/v1/public/${this.jwtOptions.audience}/oauth2/token`,
          dataRaw: new URLSearchParams(params)
        });
      }
      // ENDMANUAL(token)
      // MANUAL(authenticateToken)(SERVICE_METHOD)
      // ADDIMPORT: import { authenticateM2MJwtLocal, JwtConfig } from "../shared/sessions";
      // ADDIMPORT: import { request } from "../shared";
      // ADDIMPORT: import { performAuthorizationCheck, ScopeAuthorizationFunc } from "./m2m_local";
      // ADDIMPORT: import { ClientError } from "../shared/errors";
      /**
        * Authenticate an access token issued by Stytch from the Token endpoint.
        * M2M access tokens are JWTs signed with the project's JWKs, and can be validated locally using any Stytch client library.
        * You may pass in an optional set of scopes that the JWT must contain in order to enforce permissions.
        * You may also override the default scope authorization function to implement custom authorization logic.
        *
        * @param data {@link AuthenticateTokenRequest}
        * @param scopeAuthorizationFunc {@link ScopeAuthorizationFunc} - A function that checks if the token has the required scopes. 
          The default function assumes scopes are either direct string matches or written in the form "action:resource". See the 
          documentation for {@link performAuthorizationCheck} for more information.
        * @async
        * @returns {@link AuthenticateTokenResponse}
        * @throws {ClientError} when token can not be authenticated
      */
      async authenticateToken(data, scopeAuthorizationFunc = _m2m_local.performAuthorizationCheck) {
        const {
          sub,
          scope,
          custom_claims
        } = await (0, _sessions.authenticateM2MJwtLocal)(this.jwksClient, this.jwtOptions, data.access_token, {
          max_token_age_seconds: data.max_token_age_seconds,
          clock_tolerance_seconds: data.clock_tolerance_seconds
        });
        const scopes = scope.split(" ");
        if (data.required_scopes && data.required_scopes.length > 0) {
          const isAuthorized = scopeAuthorizationFunc({
            hasScopes: scopes,
            requiredScopes: data.required_scopes
          });
          if (!isAuthorized) {
            throw new _errors.ClientError("missing_scopes", "Missing at least one required scope", data.required_scopes);
          }
        }
        return {
          client_id: sub,
          scopes,
          custom_claims
        };
      }
      // ENDMANUAL(authenticateToken)
    };
    exports.M2M = M2M;
  }
});

// node_modules/stytch/dist/b2c/magic_links_email.js
var require_magic_links_email = __commonJS({
  "node_modules/stytch/dist/b2c/magic_links_email.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Email = void 0;
    require_method_options();
    var _shared = require_shared();
    var Email = class {
      static {
        __name(this, "Email");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Send a magic link to an existing Stytch user using their email address. If you'd like to create a user
       * and send them a magic link by email with one request, use our
       * [log in or create endpoint](https://stytch.com/docs/api/log-in-or-create-user-by-email).
       *
       * ### Add an email to an existing user
       * This endpoint also allows you to add a new email address to an existing Stytch User. Including a
       * `user_id`, `session_token`, or `session_jwt` in your Send Magic Link by email request will add the new,
       * unverified email address to the existing Stytch User. If the user successfully authenticates within 5
       * minutes, the new email address will be marked as verified and remain permanently on the existing Stytch
       * User. Otherwise, it will be removed from the User object, and any subsequent login requests using that
       * email address will create a new User.
       *
       * ### Next steps
       * The user is emailed a magic link which redirects them to the provided
       * [redirect URL](https://stytch.com/docs/guides/magic-links/email-magic-links/redirect-routing). Collect
       * the `token` from the URL query parameters, and call
       * [Authenticate magic link](https://stytch.com/docs/api/authenticate-magic-link) to complete
       * authentication.
       * @param data {@link MagicLinksEmailSendRequest}
       * @returns {@link MagicLinksEmailSendResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      send(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/magic_links/email/send`,
          headers,
          data
        });
      }
      /**
       * Send either a login or signup Magic Link to the User based on if the email is associated with a User
       * already. A new or pending User will receive a signup Magic Link. An active User will receive a login
       * Magic Link. For more information on how to control the status your Users are created in see the
       * `create_user_as_pending` flag.
       *
       * ### Next steps
       * The User is emailed a Magic Link which redirects them to the provided
       * [redirect URL](https://stytch.com/docs/guides/magic-links/email-magic-links/redirect-routing). Collect
       * the `token` from the URL query parameters and call
       * [Authenticate Magic Link](https://stytch.com/docs/api/authenticate-magic-link) to complete
       * authentication.
       * @param data {@link MagicLinksEmailLoginOrCreateRequest}
       * @returns {@link MagicLinksEmailLoginOrCreateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      loginOrCreate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/magic_links/email/login_or_create`,
          headers,
          data
        });
      }
      /**
       * Create a User and send an invite Magic Link to the provided `email`. The User will be created with a
       * `pending` status until they click the Magic Link in the invite email.
       *
       * ### Next steps
       * The User is emailed a Magic Link which redirects them to the provided
       * [redirect URL](https://stytch.com/docs/guides/magic-links/email-magic-links/redirect-routing). Collect
       * the `token` from the URL query parameters and call
       * [Authenticate Magic Link](https://stytch.com/docs/api/authenticate-magic-link) to complete
       * authentication.
       * @param data {@link MagicLinksEmailInviteRequest}
       * @returns {@link MagicLinksEmailInviteResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      invite(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/magic_links/email/invite`,
          headers,
          data
        });
      }
      /**
       * Revoke a pending invite based on the `email` provided.
       * @param data {@link MagicLinksEmailRevokeInviteRequest}
       * @returns {@link MagicLinksEmailRevokeInviteResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      revokeInvite(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/magic_links/email/revoke_invite`,
          headers,
          data
        });
      }
    };
    exports.Email = Email;
  }
});

// node_modules/stytch/dist/b2c/magic_links.js
var require_magic_links = __commonJS({
  "node_modules/stytch/dist/b2c/magic_links.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.MagicLinks = void 0;
    require_method_options();
    var _magic_links_email = require_magic_links_email();
    var _shared = require_shared();
    var MagicLinks = class {
      static {
        __name(this, "MagicLinks");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
        this.email = new _magic_links_email.Email(this.fetchConfig);
      }
      /**
       * Authenticate a User given a Magic Link. This endpoint verifies that the Magic Link token is valid,
       * hasn't expired or been previously used, and any optional security settings such as IP match or user
       * agent match are satisfied.
       * @param data {@link MagicLinksAuthenticateRequest}
       * @returns {@link MagicLinksAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/magic_links/authenticate`,
          headers,
          data
        });
      }
      /**
       * Create an Embeddable Magic Link token for a User. Access to this endpoint is restricted. To enable it,
       * please send us a note at support@stytch.com.
       *
       * ### Next steps
       * Send the returned `token` value to the end user in a link which directs to your application. When the
       * end user follows your link, collect the token, and call
       * [Authenticate Magic Link](https://stytch.com/docs/api/authenticate-magic-link) to complete
       * authentication.
       *
       * **Note:** Authenticating an Embeddable Magic Link token will **not** result in any of the Stytch User's
       * factors (email address or phone number) being marked as verified, as Stytch cannot confirm where the
       * user received the token.
       * @param data {@link MagicLinksCreateRequest}
       * @returns {@link MagicLinksCreateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      create(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/magic_links`,
          headers,
          data
        });
      }
    };
    exports.MagicLinks = MagicLinks;
  }
});

// node_modules/stytch/dist/b2c/oauth.js
var require_oauth = __commonJS({
  "node_modules/stytch/dist/b2c/oauth.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.OAuth = void 0;
    require_method_options();
    var _shared = require_shared();
    var OAuth = class {
      static {
        __name(this, "OAuth");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Generate an OAuth Attach Token to pre-associate an OAuth flow with an existing Stytch User. Pass the
       * returned `oauth_attach_token` to the same provider's OAuth Start endpoint to treat this OAuth flow as a
       * login for that user instead of a signup for a new user.
       *
       * Exactly one of `user_id`, `session_token`, or `session_jwt` must be provided to identify the target
       * Stytch User.
       *
       * **Note**: This is an optional step in the OAuth flow. Stytch can often determine whether to associate a
       * new OAuth login with an existing User based on verified information (such as an email address) from the
       * identity provider. This endpoint is useful for cases where we can't, such as missing or unverified
       * provider information.
       *
       * See our [OAuth email address behavior](https://stytch.com/docs/guides/oauth/email-behavior) resource for
       * additional information.
       * @param data {@link OAuthAttachRequest}
       * @returns {@link OAuthAttachResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      attach(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/oauth/attach`,
          headers,
          data
        });
      }
      /**
       * Authenticate a User given a `token`. This endpoint verifies that the user completed the OAuth flow by
       * verifying that the token is valid and hasn't expired. To initiate a Stytch session for the user while
       * authenticating their OAuth token, include `session_duration_minutes`; a session with the identity
       * provider, e.g. Google or Facebook, will always be initiated upon successful authentication.
       * @param data {@link OAuthAuthenticateRequest}
       * @returns {@link OAuthAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/oauth/authenticate`,
          headers,
          data
        });
      }
    };
    exports.OAuth = OAuth;
  }
});

// node_modules/stytch/dist/b2c/otps_email.js
var require_otps_email = __commonJS({
  "node_modules/stytch/dist/b2c/otps_email.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Email = void 0;
    require_method_options();
    var _shared = require_shared();
    var Email = class {
      static {
        __name(this, "Email");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Send a One-Time Passcode (OTP) to a User using their email. If you'd like to create a user and send them
       * a passcode with one request, use our
       * [log in or create endpoint](https://stytch.com/docs/api/log-in-or-create-user-by-email-otp).
       *
       * ### Add an email to an existing user
       * This endpoint also allows you to add a new email address to an existing Stytch User. Including a
       * `user_id`, `session_token`, or `session_jwt` in your Send one-time passcode by email request will add
       * the new, unverified email address to the existing Stytch User. If the user successfully authenticates
       * within 5 minutes, the new email address will be marked as verified and remain permanently on the
       * existing Stytch User. Otherwise, it will be removed from the User object, and any subsequent login
       * requests using that email address will create a new User.
       *
       * ### Next steps
       * Collect the OTP which was delivered to the user. Call
       * [Authenticate OTP](https://stytch.com/docs/api/authenticate-otp) using the OTP `code` along with the
       * `email_id` found in the response as the `method_id`.
       * @param data {@link OTPsEmailSendRequest}
       * @returns {@link OTPsEmailSendResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      send(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/otps/email/send`,
          headers,
          data
        });
      }
      /**
       * Send a one-time passcode (OTP) to a User using their email. If the email is not associated with a User
       * already, a User will be created.
       *
       * ### Next steps
       *
       * Collect the OTP which was delivered to the User. Call
       * [Authenticate OTP](https://stytch.com/docs/api/authenticate-otp) using the OTP `code` along with the
       * `phone_id` found in the response as the `method_id`.
       * @param data {@link OTPsEmailLoginOrCreateRequest}
       * @returns {@link OTPsEmailLoginOrCreateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      loginOrCreate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/otps/email/login_or_create`,
          headers,
          data
        });
      }
    };
    exports.Email = Email;
  }
});

// node_modules/stytch/dist/b2c/otps_sms.js
var require_otps_sms = __commonJS({
  "node_modules/stytch/dist/b2c/otps_sms.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Sms = void 0;
    require_method_options();
    var _shared = require_shared();
    var Sms = class {
      static {
        __name(this, "Sms");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Send a one-time passcode (OTP) to a user's phone number. If you'd like to create a user and send them a
       * passcode with one request, use our
       * [log in or create](https://stytch.com/docs/api/log-in-or-create-user-by-sms) endpoint.
       *
       * Note that sending another OTP code before the first has expired will invalidate the first code.
       *
       * ### Cost to send SMS OTP
       * Before configuring SMS or WhatsApp OTPs, please review how Stytch
       * [bills the costs of international OTPs](https://stytch.com/pricing) and understand how to protect your
       * app against [toll fraud](https://stytch.com/docs/guides/passcodes/toll-fraud/overview).
       *
       * __Note:__ SMS to phone numbers outside of the US and Canada is disabled by default for customers who did
       * not use SMS prior to October 2023. If you're interested in sending international SMS, please reach out
       * to [support@stytch.com](mailto:support@stytch.com?subject=Enable%20international%20SMS).
       *
       * Even when international SMS is enabled, we do not support sending SMS to countries on our
       * [Unsupported countries list](https://stytch.com/docs/guides/passcodes/unsupported-countries).
       *
       * ### Add a phone number to an existing user
       *
       * This endpoint also allows you to add a new phone number to an existing Stytch User. Including a
       * `user_id`, `session_token`, or `session_jwt` in your Send one-time passcode by SMS request will add the
       * new, unverified phone number to the existing Stytch User. If the user successfully authenticates within
       * 5 minutes, the new phone number will be marked as verified and remain permanently on the existing Stytch
       * User. Otherwise, it will be removed from the User object, and any subsequent login requests using that
       * phone number will create a new User.
       *
       * ### Next steps
       *
       * Collect the OTP which was delivered to the user. Call
       * [Authenticate OTP](https://stytch.com/docs/api/authenticate-otp) using the OTP `code` along with the
       * `phone_id` found in the response as the `method_id`.
       * @param data {@link OTPsSmsSendRequest}
       * @returns {@link OTPsSmsSendResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      send(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/otps/sms/send`,
          headers,
          data
        });
      }
      /**
       * Send a One-Time Passcode (OTP) to a User using their phone number. If the phone number is not associated
       * with a user already, a user will be created.
       *
       * ### Cost to send SMS OTP
       * Before configuring SMS or WhatsApp OTPs, please review how Stytch
       * [bills the costs of international OTPs](https://stytch.com/pricing) and understand how to protect your
       * app against [toll fraud](https://stytch.com/docs/guides/passcodes/toll-fraud/overview).
       *
       * __Note:__ SMS to phone numbers outside of the US and Canada is disabled by default for customers who did
       * not use SMS prior to October 2023. If you're interested in sending international SMS, please reach out
       * to [support@stytch.com](mailto:support@stytch.com?subject=Enable%20international%20SMS).
       *
       * Even when international SMS is enabled, we do not support sending SMS to countries on our
       * [Unsupported countries list](https://stytch.com/docs/guides/passcodes/unsupported-countries).
       *
       * ### Next steps
       *
       * Collect the OTP which was delivered to the User. Call
       * [Authenticate OTP](https://stytch.com/docs/api/authenticate-otp) using the OTP `code` along with the
       * `phone_id` found in the response as the `method_id`.
       * @param data {@link OTPsSmsLoginOrCreateRequest}
       * @returns {@link OTPsSmsLoginOrCreateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      loginOrCreate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/otps/sms/login_or_create`,
          headers,
          data
        });
      }
    };
    exports.Sms = Sms;
  }
});

// node_modules/stytch/dist/b2c/otps_whatsapp.js
var require_otps_whatsapp = __commonJS({
  "node_modules/stytch/dist/b2c/otps_whatsapp.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Whatsapp = void 0;
    require_method_options();
    var _shared = require_shared();
    var Whatsapp = class {
      static {
        __name(this, "Whatsapp");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Send a One-Time Passcode (OTP) to a User's WhatsApp. If you'd like to create a user and send them a
       * passcode with one request, use our
       * [log in or create](https://stytch.com/docs/api/whatsapp-login-or-create) endpoint.
       *
       * Note that sending another OTP code before the first has expired will invalidate the first code.
       *
       * ### Cost to send SMS OTP
       * Before configuring SMS or WhatsApp OTPs, please review how Stytch
       * [bills the costs of international OTPs](https://stytch.com/pricing) and understand how to protect your
       * app against [toll fraud](https://stytch.com/docs/guides/passcodes/toll-fraud/overview).
       *
       * ### Add a phone number to an existing user
       *
       * This endpoint also allows you to add a new phone number to an existing Stytch User. Including a
       * `user_id`, `session_token`, or `session_jwt` in your Send one-time passcode by WhatsApp request will add
       * the new, unverified phone number to the existing Stytch User. If the user successfully authenticates
       * within 5 minutes, the new phone number will be marked as verified and remain permanently on the existing
       * Stytch User. Otherwise, it will be removed from the User object, and any subsequent login requests using
       * that phone number will create a new User.
       *
       * ### Next steps
       *
       * Collect the OTP which was delivered to the user. Call
       * [Authenticate OTP](https://stytch.com/docs/api/authenticate-otp) using the OTP `code` along with the
       * `phone_id` found in the response as the `method_id`.
       * @param data {@link OTPsWhatsappSendRequest}
       * @returns {@link OTPsWhatsappSendResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      send(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/otps/whatsapp/send`,
          headers,
          data
        });
      }
      /**
       * Send a one-time passcode (OTP) to a User's WhatsApp using their phone number. If the phone number is not
       * associated with a User already, a User will be created.
       *
       * ### Cost to send SMS OTP
       * Before configuring SMS or WhatsApp OTPs, please review how Stytch
       * [bills the costs of international OTPs](https://stytch.com/pricing) and understand how to protect your
       * app against [toll fraud](https://stytch.com/docs/guides/passcodes/toll-fraud/overview).
       *
       * ### Next steps
       *
       * Collect the OTP which was delivered to the User. Call
       * [Authenticate OTP](https://stytch.com/docs/api/authenticate-otp) using the OTP `code` along with the
       * `phone_id` found in the response as the `method_id`.
       * @param data {@link OTPsWhatsappLoginOrCreateRequest}
       * @returns {@link OTPsWhatsappLoginOrCreateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      loginOrCreate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/otps/whatsapp/login_or_create`,
          headers,
          data
        });
      }
    };
    exports.Whatsapp = Whatsapp;
  }
});

// node_modules/stytch/dist/b2c/otps.js
var require_otps = __commonJS({
  "node_modules/stytch/dist/b2c/otps.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.OTPs = void 0;
    require_method_options();
    var _otps_email = require_otps_email();
    var _shared = require_shared();
    var _otps_sms = require_otps_sms();
    var _otps_whatsapp = require_otps_whatsapp();
    var OTPs = class {
      static {
        __name(this, "OTPs");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
        this.sms = new _otps_sms.Sms(this.fetchConfig);
        this.whatsapp = new _otps_whatsapp.Whatsapp(this.fetchConfig);
        this.email = new _otps_email.Email(this.fetchConfig);
      }
      /**
       * Authenticate a User given a `method_id` (the associated `email_id` or `phone_id`) and a `code`. This
       * endpoint verifies that the code is valid, hasn't expired or been previously used, and any optional
       * security settings such as IP match or user agent match are satisfied. A given `method_id` may only have
       * a single active OTP code at any given time, if a User requests another OTP code before the first one has
       * expired, the first one will be invalidated.
       * @param data {@link OTPsAuthenticateRequest}
       * @returns {@link OTPsAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/otps/authenticate`,
          headers,
          data
        });
      }
    };
    exports.OTPs = OTPs;
  }
});

// node_modules/stytch/dist/b2c/passwords_email.js
var require_passwords_email = __commonJS({
  "node_modules/stytch/dist/b2c/passwords_email.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Email = void 0;
    require_method_options();
    var _shared = require_shared();
    var Email = class {
      static {
        __name(this, "Email");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Initiates a password reset for the email address provided. This will trigger an email to be sent to the
       * address, containing a magic link that will allow them to set a new password and authenticate.
       * @param data {@link PasswordsEmailResetStartRequest}
       * @returns {@link PasswordsEmailResetStartResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      resetStart(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/passwords/email/reset/start`,
          headers,
          data
        });
      }
      /**
       * Reset the user’s password and authenticate them. This endpoint checks that the magic link `token` is
       * valid, hasn’t expired, or already been used – and can optionally require additional security settings,
       * such as the IP address and user agent matching the initial reset request.
       *
       * The provided password needs to meet our password strength requirements, which can be checked in advance
       * with the password strength endpoint. If the token and password are accepted, the password is securely
       * stored for future authentication and the user is authenticated.
       *
       * Note that a successful password reset by email will revoke all active sessions for the `user_id`.
       * @param data {@link PasswordsEmailResetRequest}
       * @returns {@link PasswordsEmailResetResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      reset(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/passwords/email/reset`,
          headers,
          data
        });
      }
    };
    exports.Email = Email;
  }
});

// node_modules/stytch/dist/b2c/passwords_existing_password.js
var require_passwords_existing_password = __commonJS({
  "node_modules/stytch/dist/b2c/passwords_existing_password.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.ExistingPassword = void 0;
    require_method_options();
    var _shared = require_shared();
    var ExistingPassword = class {
      static {
        __name(this, "ExistingPassword");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Reset the User’s password using their existing password.
       *
       * Note that a successful password reset via an existing password will revoke all active sessions for the
       * `user_id`.
       * @param data {@link PasswordsExistingPasswordResetRequest}
       * @returns {@link PasswordsExistingPasswordResetResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      reset(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/passwords/existing_password/reset`,
          headers,
          data
        });
      }
    };
    exports.ExistingPassword = ExistingPassword;
  }
});

// node_modules/stytch/dist/b2c/passwords_session.js
var require_passwords_session = __commonJS({
  "node_modules/stytch/dist/b2c/passwords_session.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Sessions = void 0;
    require_method_options();
    var _shared = require_shared();
    var Sessions = class {
      static {
        __name(this, "Sessions");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Reset the user’s password using their existing session. The endpoint will error if the session does not
       * have a password, email magic link, or email OTP authentication factor that has been issued within the
       * last 5 minutes. This endpoint requires either a `session_jwt` or `session_token` be included in the
       * request.
       *
       * Note that a successful password reset via an existing session will revoke all active sessions for the
       * `user_id`, except for the one used during the reset flow.
       * @param data {@link PasswordsSessionResetRequest}
       * @returns {@link PasswordsSessionResetResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      reset(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/passwords/session/reset`,
          headers,
          data
        });
      }
    };
    exports.Sessions = Sessions;
  }
});

// node_modules/stytch/dist/b2c/passwords.js
var require_passwords = __commonJS({
  "node_modules/stytch/dist/b2c/passwords.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Passwords = void 0;
    require_method_options();
    var _passwords_email = require_passwords_email();
    var _passwords_existing_password = require_passwords_existing_password();
    var _shared = require_shared();
    var _passwords_session = require_passwords_session();
    var Passwords = class {
      static {
        __name(this, "Passwords");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
        this.email = new _passwords_email.Email(this.fetchConfig);
        this.existingPassword = new _passwords_existing_password.ExistingPassword(this.fetchConfig);
        this.sessions = new _passwords_session.Sessions(this.fetchConfig);
      }
      /**
       * Create a new user with a password. If `session_duration_minutes` is specified, a new session will be
       * started as well.
       *
       * If a user with this email already exists in your Stytch project, this endpoint will return a
       * `duplicate_email` error. To add a password to an existing passwordless user, you'll need to either call
       * the [Migrate password endpoint](https://stytch.com/docs/api/password-migrate) or prompt the user to
       * complete one of our password reset flows.
       *
       * This endpoint will return an error if the password provided does not meet our strength requirements,
       * which you can check beforehand via the
       * [Password strength check endpoint](https://stytch.com/docs/api/password-strength-check).
       *
       * When creating new Passwords users, it's good practice to enforce an email verification flow. We'd
       * recommend checking out our
       * [Email verification guide](https://stytch.com/docs/guides/passwords/email-verification/overview) for
       * more information.
       * @param data {@link PasswordsCreateRequest}
       * @returns {@link PasswordsCreateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      create(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/passwords`,
          headers,
          data
        });
      }
      /**
       * Authenticate a user with their email address and password. This endpoint verifies that the user has a
       * password currently set, and that the entered password is correct. There are two instances where the
       * endpoint will return a `reset_password` error even if they enter their previous password:
       *
       * **One:** The user’s credentials appeared in the HaveIBeenPwned dataset. We force a password reset to
       * ensure that the user is the legitimate owner of the email address, and not a malicious actor abusing the
       * compromised credentials.
       *
       * **Two:** A user that has previously authenticated with email/password uses a passwordless authentication
       * method tied to the same email address (e.g. Magic Links, Google OAuth) for the first time. Any
       * subsequent email/password authentication attempt will result in this error. We force a password reset in
       * this instance in order to safely deduplicate the account by email address, without introducing the risk
       * of a pre-hijack account takeover attack.
       *
       * Imagine a bad actor creates many accounts using passwords and the known email addresses of their
       * victims. If a victim comes to the site and logs in for the first time with an email-based passwordless
       * authentication method then both the victim and the bad actor have credentials to access to the same
       * account. To prevent this, any further email/password login attempts first require a password reset which
       * can only be accomplished by someone with access to the underlying email address.
       * @param data {@link PasswordsAuthenticateRequest}
       * @returns {@link PasswordsAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/passwords/authenticate`,
          headers,
          data
        });
      }
      /**
       * This API allows you to check whether or not the user’s provided password is valid, and to provide
       * feedback to the user on how to increase the strength of their password.
       *
       * This endpoint adapts to your Project's password strength configuration. If you're using
       * [zxcvbn](https://stytch.com/docs/guides/passwords/strength-policy), the default, your passwords are
       * considered valid if the strength score is >= 3. If you're using
       * [LUDS](https://stytch.com/docs/guides/passwords/strength-policy), your passwords are considered valid if
       * they meet the requirements that you've set with Stytch. You may update your password strength
       * configuration in the [stytch dashboard](https://stytch.com/dashboard/password-strength-config).
       *
       *
       * ### Password feedback
       *
       * The `feedback` object contains relevant fields for you to relay feedback to users that failed to create
       * a strong enough password.
       *
       * If you're using zxcvbn, the `feedback` object will contain `warning` and `suggestions` for any password
       * that does not meet the zxcvbn strength requirements. You can return these strings directly to the user
       * to help them craft a strong password.
       *
       * If you're using LUDS, the `feedback` object will contain an object named `luds_requirements` which
       * contain a collection of fields that the user failed or passed. You'll want to prompt the user to create
       * a password that meets all of the requirements that they failed.
       * @param data {@link PasswordsStrengthCheckRequest}
       * @returns {@link PasswordsStrengthCheckResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      strengthCheck(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/passwords/strength_check`,
          headers,
          data
        });
      }
      /**
       * Adds an existing password to a User's email that doesn't have a password yet. We support migrating users
       * from passwords stored with `bcrypt`, `scrypt`, `argon2`, `MD-5`, `SHA-1`, or `PBKDF2`. This endpoint has
       * a rate limit of 100 requests per second.
       * @param data {@link PasswordsMigrateRequest}
       * @returns {@link PasswordsMigrateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      migrate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/passwords/migrate`,
          headers,
          data
        });
      }
    };
    exports.Passwords = Passwords;
  }
});

// node_modules/stytch/dist/b2c/project.js
var require_project = __commonJS({
  "node_modules/stytch/dist/b2c/project.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Project = void 0;
    require_method_options();
    var _shared = require_shared();
    var Project = class {
      static {
        __name(this, "Project");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * @param params {@link ProjectMetricsRequest}
       * @returns {@link ProjectMetricsResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      metrics() {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/projects/metrics`,
          headers
        });
      }
    };
    exports.Project = Project;
  }
});

// node_modules/stytch/dist/b2c/sessions.js
var require_sessions2 = __commonJS({
  "node_modules/stytch/dist/b2c/sessions.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Sessions = void 0;
    require_method_options();
    var _shared = require_shared();
    var _sessions = require_sessions();
    var Sessions = class {
      static {
        __name(this, "Sessions");
      }
      constructor(fetchConfig, jwtConfig) {
        this.fetchConfig = fetchConfig;
        this.jwksClient = jwtConfig.jwks;
        this.jwtOptions = {
          audience: jwtConfig.projectID,
          issuer: jwtConfig.issuers,
          typ: "JWT"
        };
      }
      /**
       * List all active Sessions for a given `user_id`. All timestamps are formatted according to the RFC 3339
       * standard and are expressed in UTC, e.g. `2021-12-29T12:33:09Z`.
       * @param params {@link SessionsGetRequest}
       * @returns {@link SessionsGetResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      get(params) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/sessions`,
          headers,
          params: {
            ...params
          }
        });
      }
      /**
       * Authenticate a session token or session JWT and retrieve associated session data. If
       * `session_duration_minutes` is included, update the lifetime of the session to be that many minutes from
       * now. All timestamps are formatted according to the RFC 3339 standard and are expressed in UTC, e.g.
       * `2021-12-29T12:33:09Z`. This endpoint requires exactly one `session_jwt` or `session_token` as part of
       * the request. If both are included, you will receive a `too_many_session_arguments` error.
       *
       * You may provide a JWT that needs to be refreshed and is expired according to its `exp` claim. A new JWT
       * will be returned if both the signature and the underlying Session are still valid. See our
       * [How to use Stytch Session JWTs](https://stytch.com/docs/guides/sessions/using-jwts) guide for more
       * information.
       * @param data {@link SessionsAuthenticateRequest}
       * @returns {@link SessionsAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/sessions/authenticate`,
          headers,
          data
        });
      }
      /**
       * Revoke a Session, immediately invalidating all of its session tokens. You can revoke a session in three
       * ways: using its ID, or using one of its session tokens, or one of its JWTs. This endpoint requires
       * exactly one of those to be included in the request. It will return an error if multiple are present.
       * @param data {@link SessionsRevokeRequest}
       * @returns {@link SessionsRevokeResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      revoke(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/sessions/revoke`,
          headers,
          data
        });
      }
      /**
       * Migrate a session from an external OIDC compliant endpoint. Stytch will call the external UserInfo
       * endpoint defined in your Stytch Project settings in the [Dashboard](https://stytch.com/docs/dashboard),
       * and then perform a lookup using the `session_token`. If the response contains a valid email address,
       * Stytch will attempt to match that email address with an existing User and create a Stytch Session. You
       * will need to create the user before using this endpoint.
       * @param data {@link SessionsMigrateRequest}
       * @returns {@link SessionsMigrateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      migrate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/sessions/migrate`,
          headers,
          data
        });
      }
      /**
       * Use this endpoint to exchange a Connected Apps Access Token back into a Stytch Session for the
       * underlying User.
       * This session can be used with the Stytch SDKs and APIs.
       *
       * The Access Token must contain the `full_access` scope and must not be more than 5 minutes old. Access
       * Tokens may only be exchanged a single time.
       * @param data {@link SessionsExchangeAccessTokenRequest}
       * @returns {@link SessionsExchangeAccessTokenResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      exchangeAccessToken(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/sessions/exchange_access_token`,
          headers,
          data
        });
      }
      /**
       * Get the JSON Web Key Set (JWKS) for a project.
       *
       * JWKS are rotated every ~6 months. Upon rotation, new JWTs will be signed using the new key, and both
       * keys will be returned by this endpoint for a period of 1 month.
       *
       * JWTs have a set lifetime of 5 minutes, so there will be a 5 minute period where some JWTs will be signed
       * by the old JWKS, and some JWTs will be signed by the new JWKS. The correct JWKS to use for validation is
       * determined by matching the `kid` value of the JWT and JWKS.
       *
       * If you're using one of our [backend SDKs](https://stytch.com/docs/sdks), the JWKS rotation will be
       * handled for you.
       *
       * If you're using your own JWT validation library, many have built-in support for JWKS rotation, and
       * you'll just need to supply this API endpoint. If not, your application should decide which JWKS to use
       * for validation by inspecting the `kid` value.
       *
       * See our [How to use Stytch Session JWTs](https://stytch.com/docs/guides/sessions/using-jwts) guide for
       * more information.
       * @param params {@link SessionsGetJWKSRequest}
       * @returns {@link SessionsGetJWKSResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      getJWKS(params) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/sessions/jwks/${params.project_id}`,
          headers,
          params: {}
        });
      }
      // MANUAL(authenticateJwt)(SERVICE_METHOD)
      // ADDIMPORT: import { JwtConfig, authenticateSessionJwtLocal } from "../shared/sessions";
      /** Parse a JWT and verify the signature, preferring local verification over remote.
       *
       * If max_token_age_seconds is set, remote verification will be forced if the JWT was issued at
       * (based on the "iat" claim) more than that many seconds ago.
       *
       * To force remote validation for all tokens, set max_token_age_seconds to zero or use the
       * authenticate method instead.
       */
      async authenticateJwt(params) {
        try {
          const session = await this.authenticateJwtLocal(params);
          return {
            session,
            session_jwt: params.session_jwt
          };
        } catch (err) {
          return this.authenticate({
            session_jwt: params.session_jwt
          });
        }
      }
      /** Parse a JWT and verify the signature locally (without calling /authenticate in the API).
       *
       * If max_token_age_seconds is set, this will return an error if the JWT was issued (based on the "iat"
       * claim) more than max_token_age_seconds seconds ago.
       *
       * If max_token_age_seconds is explicitly set to zero, all tokens will be considered too old,
       * even if they are otherwise valid.
       *
       * The value for current_date is used to compare timestamp claims ("exp", "nbf", "iat"). It
       * defaults to the current date (new Date()).
       *
       * The value for clock_tolerance_seconds is the maximum allowable difference when comparing
       * timestamps. It defaults to zero.
       */
      async authenticateJwtLocal(params) {
        const sess = await (0, _sessions.authenticateSessionJwtLocal)(this.jwksClient, this.jwtOptions, params.session_jwt, {
          clock_tolerance_seconds: params.clock_tolerance_seconds,
          max_token_age_seconds: params.max_token_age_seconds,
          current_date: params.current_date
        });
        return {
          session_id: sess.session_id,
          attributes: sess.attributes,
          authentication_factors: sess.authentication_factors,
          user_id: sess.sub,
          started_at: sess.started_at,
          last_accessed_at: sess.last_accessed_at,
          expires_at: sess.expires_at,
          custom_claims: sess.custom_claims
        };
      }
      // ENDMANUAL(authenticateJwt)
    };
    exports.Sessions = Sessions;
  }
});

// node_modules/stytch/dist/b2c/totps.js
var require_totps = __commonJS({
  "node_modules/stytch/dist/b2c/totps.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.TOTPs = void 0;
    require_method_options();
    var _shared = require_shared();
    var TOTPs = class {
      static {
        __name(this, "TOTPs");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Create a new TOTP instance for a user. The user can use the authenticator application of their choice to
       * scan the QR code or enter the secret.
       * @param data {@link TOTPsCreateRequest}
       * @returns {@link TOTPsCreateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      create(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/totps`,
          headers,
          data
        });
      }
      /**
       * Authenticate a TOTP code entered by a user.
       * @param data {@link TOTPsAuthenticateRequest}
       * @returns {@link TOTPsAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/totps/authenticate`,
          headers,
          data
        });
      }
      /**
       * Retrieve the recovery codes for a TOTP instance tied to a User.
       * @param data {@link TOTPsRecoveryCodesRequest}
       * @returns {@link TOTPsRecoveryCodesResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      recoveryCodes(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/totps/recovery_codes`,
          headers,
          data
        });
      }
      /**
       * Authenticate a recovery code for a TOTP instance.
       * @param data {@link TOTPsRecoverRequest}
       * @returns {@link TOTPsRecoverResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      recover(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/totps/recover`,
          headers,
          data
        });
      }
    };
    exports.TOTPs = TOTPs;
  }
});

// node_modules/stytch/dist/b2c/users.js
var require_users = __commonJS({
  "node_modules/stytch/dist/b2c/users.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Users = exports.UserSearchIterator = void 0;
    require_method_options();
    var _shared = require_shared();
    var mode = /* @__PURE__ */ function(mode2) {
      mode2[mode2["pending"] = 0] = "pending";
      mode2[mode2["inProgress"] = 1] = "inProgress";
      mode2[mode2["complete"] = 2] = "complete";
      return mode2;
    }(mode || {});
    var UserSearchIterator = class {
      static {
        __name(this, "UserSearchIterator");
      }
      constructor(client, data) {
        this.client = client;
        this.data = data;
        this.mode = mode.pending;
      }
      async next() {
        const res = await this.client.search(this.data);
        this.data = {
          ...this.data,
          cursor: res.results_metadata.next_cursor
        };
        if (!this.data.cursor) {
          this.mode = mode.complete;
        } else {
          this.mode = mode.inProgress;
        }
        return res.results;
      }
      hasNext() {
        return this.mode !== mode.complete;
      }
      async *[Symbol.asyncIterator]() {
        while (this.hasNext()) {
          yield this.next();
        }
      }
    };
    exports.UserSearchIterator = UserSearchIterator;
    var Users = class {
      static {
        __name(this, "Users");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Add a User to Stytch. A `user_id` is returned in the response that can then be used to perform other
       * operations within Stytch. An `email` or a `phone_number` is required.
       * @param data {@link UsersCreateRequest}
       * @returns {@link UsersCreateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      create(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/users`,
          headers,
          data
        });
      }
      /**
       * Get information about a specific User.
       * @param params {@link UsersGetRequest}
       * @returns {@link UsersGetResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      get(params) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/users/${params.user_id}`,
          headers,
          params: {}
        });
      }
      /**
       * Search for Users within your Stytch Project.
       *
       * Use the `query` object to filter by different fields. See the `query.operands.filter_value`
       * documentation below for a list of available filters.
       *
       * ### Export all User data
       *
       * Submit an empty `query` in your Search Users request to return all of your Stytch Project's Users.
       *
       * [This Github repository](https://github.com/stytchauth/stytch-node-export-users) contains a utility that
       * leverages the Search Users endpoint to export all of your User data to a CSV or JSON file.
       * @param data {@link UsersSearchRequest}
       * @returns {@link UsersSearchResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      search(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/users/search`,
          headers,
          data
        });
      }
      /**
       * Update a User's attributes.
       *
       * **Note:** In order to add a new email address or phone number to an existing User object, pass the new
       * email address or phone number into the respective `/send` endpoint for the authentication method of your
       * choice. If you specify the existing User's `user_id` while calling the `/send` endpoint, the new,
       * unverified email address or phone number will be added to the existing User object. If the user
       * successfully authenticates within 5 minutes of the `/send` request, the new email address or phone
       * number will be marked as verified and remain permanently on the existing Stytch User. Otherwise, it will
       * be removed from the User object, and any subsequent login requests using that phone number will create a
       * new User. We require this process to guard against an account takeover vulnerability.
       * @param data {@link UsersUpdateRequest}
       * @returns {@link UsersUpdateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      update(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "PUT",
          url: `/v1/users/${data.user_id}`,
          headers,
          data: {
            name: data.name,
            attributes: data.attributes,
            trusted_metadata: data.trusted_metadata,
            untrusted_metadata: data.untrusted_metadata,
            external_id: data.external_id
          }
        });
      }
      /**
       * Exchange a user's email address or phone number for another.
       *
       * Must pass either an `email_address` or a `phone_number`.
       *
       * This endpoint only works if the user has exactly one factor. You are able to exchange the type of factor
       * for another as well, i.e. exchange an `email_address` for a `phone_number`.
       *
       * Use this endpoint with caution as it performs an admin level action.
       * @param data {@link UsersExchangePrimaryFactorRequest}
       * @returns {@link UsersExchangePrimaryFactorResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      exchangePrimaryFactor(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "PUT",
          url: `/v1/users/${data.user_id}/exchange_primary_factor`,
          headers,
          data: {
            email_address: data.email_address,
            phone_number: data.phone_number
          }
        });
      }
      /**
       * Delete a User from Stytch.
       * @param data {@link UsersDeleteRequest}
       * @returns {@link UsersDeleteResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      delete(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "DELETE",
          url: `/v1/users/${data.user_id}`,
          headers,
          data: {}
        });
      }
      /**
       * Delete an email from a User.
       * @param data {@link UsersDeleteEmailRequest}
       * @returns {@link UsersDeleteEmailResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      deleteEmail(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "DELETE",
          url: `/v1/users/emails/${data.email_id}`,
          headers,
          data: {}
        });
      }
      /**
       * Delete a phone number from a User.
       * @param data {@link UsersDeletePhoneNumberRequest}
       * @returns {@link UsersDeletePhoneNumberResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      deletePhoneNumber(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "DELETE",
          url: `/v1/users/phone_numbers/${data.phone_id}`,
          headers,
          data: {}
        });
      }
      /**
       * Delete a WebAuthn registration from a User.
       * @param data {@link UsersDeleteWebAuthnRegistrationRequest}
       * @returns {@link UsersDeleteWebAuthnRegistrationResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      deleteWebAuthnRegistration(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "DELETE",
          url: `/v1/users/webauthn_registrations/${data.webauthn_registration_id}`,
          headers,
          data: {}
        });
      }
      /**
       * Delete a biometric registration from a User.
       * @param data {@link UsersDeleteBiometricRegistrationRequest}
       * @returns {@link UsersDeleteBiometricRegistrationResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      deleteBiometricRegistration(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "DELETE",
          url: `/v1/users/biometric_registrations/${data.biometric_registration_id}`,
          headers,
          data: {}
        });
      }
      /**
       * Delete a TOTP from a User.
       * @param data {@link UsersDeleteTOTPRequest}
       * @returns {@link UsersDeleteTOTPResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      deleteTOTP(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "DELETE",
          url: `/v1/users/totps/${data.totp_id}`,
          headers,
          data: {}
        });
      }
      /**
       * Delete a crypto wallet from a User.
       * @param data {@link UsersDeleteCryptoWalletRequest}
       * @returns {@link UsersDeleteCryptoWalletResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      deleteCryptoWallet(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "DELETE",
          url: `/v1/users/crypto_wallets/${data.crypto_wallet_id}`,
          headers,
          data: {}
        });
      }
      /**
       * Delete a password from a User.
       * @param data {@link UsersDeletePasswordRequest}
       * @returns {@link UsersDeletePasswordResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      deletePassword(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "DELETE",
          url: `/v1/users/passwords/${data.password_id}`,
          headers,
          data: {}
        });
      }
      /**
       * Delete an OAuth registration from a User.
       * @param data {@link UsersDeleteOAuthRegistrationRequest}
       * @returns {@link UsersDeleteOAuthRegistrationResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      deleteOAuthRegistration(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "DELETE",
          url: `/v1/users/oauth/${data.oauth_user_registration_id}`,
          headers,
          data: {}
        });
      }
      // MANUAL(searchAll)(SERVICE_METHOD)
      // Return an iterator over all search results.  Submit an empty `query` in the request to return all Users.
      searchAll(data) {
        return new UserSearchIterator(this, data);
      }
      // ENDMANUAL(searchAll)
    };
    exports.Users = Users;
  }
});

// node_modules/stytch/dist/b2c/webauthn.js
var require_webauthn = __commonJS({
  "node_modules/stytch/dist/b2c/webauthn.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.WebAuthn = void 0;
    require_method_options();
    var _shared = require_shared();
    var WebAuthn = class {
      static {
        __name(this, "WebAuthn");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Initiate the process of creating a new Passkey or WebAuthn registration.
       *
       * To optimize for Passkeys, set the `return_passkey_credential_options` field to `true`.
       *
       * After calling this endpoint, the browser will need to call
       * [navigator.credentials.create()](https://www.w3.org/TR/webauthn-2/#sctn-createCredential) with the data
       * from
       * [public_key_credential_creation_options](https://w3c.github.io/webauthn/#dictionary-makecredentialoptions)
       * passed to the [navigator.credentials.create()](https://www.w3.org/TR/webauthn-2/#sctn-createCredential)
       * request via the public key argument. We recommend using the `create()` wrapper provided by the
       * webauthn-json library.
       *
       * If you are not using the [webauthn-json](https://github.com/github/webauthn-json) library, the
       * `public_key_credential_creation_options` will need to be converted to a suitable public key by
       * unmarshalling the JSON, base64 decoding the user ID field, and converting user ID and the challenge
       * fields into an array buffer.
       * @param data {@link WebAuthnRegisterStartRequest}
       * @returns {@link WebAuthnRegisterStartResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      registerStart(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/webauthn/register/start`,
          headers,
          data
        });
      }
      /**
       * Complete the creation of a WebAuthn registration by passing the response from the
       * [navigator.credentials.create()](https://www.w3.org/TR/webauthn-2/#sctn-createCredential) request to
       * this endpoint as the `public_key_credential` parameter.
       *
       * If the [webauthn-json](https://github.com/github/webauthn-json) library's `create()` method was used,
       * the response can be passed directly to the
       * [register endpoint](https://stytch.com/docs/api/webauthn-register). If not, some fields (the client data
       * and the attestation object) from the
       * [navigator.credentials.create()](https://www.w3.org/TR/webauthn-2/#sctn-createCredential) response will
       * need to be converted from array buffers to strings and marshalled into JSON.
       * @param data {@link WebAuthnRegisterRequest}
       * @returns {@link WebAuthnRegisterResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      register(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/webauthn/register`,
          headers,
          data
        });
      }
      /**
       * Initiate the authentication of a Passkey or WebAuthn registration.
       *
       * To optimize for Passkeys, set the `return_passkey_credential_options` field to `true`.
       *
       * After calling this endpoint, the browser will need to call
       * [navigator.credentials.get()](https://www.w3.org/TR/webauthn-2/#sctn-getAssertion) with the data from
       * `public_key_credential_request_options` passed to the
       * [navigator.credentials.get()](https://www.w3.org/TR/webauthn-2/#sctn-getAssertion) request via the
       * public key argument. We recommend using the `get()` wrapper provided by the webauthn-json library.
       *
       * If you are not using the [webauthn-json](https://github.com/github/webauthn-json) library, `the
       * public_key_credential_request_options` will need to be converted to a suitable public key by
       * unmarshalling the JSON and converting some the fields to array buffers.
       * @param data {@link WebAuthnAuthenticateStartRequest}
       * @returns {@link WebAuthnAuthenticateStartResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticateStart(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/webauthn/authenticate/start`,
          headers,
          data
        });
      }
      /**
       * Complete the authentication of a Passkey or WebAuthn registration by passing the response from the
       * [navigator.credentials.get()](https://www.w3.org/TR/webauthn-2/#sctn-getAssertion) request to the
       * authenticate endpoint.
       *
       * If the [webauthn-json](https://github.com/github/webauthn-json) library's `get()` method was used, the
       * response can be passed directly to the
       * [authenticate endpoint](https://stytch.com/docs/api/webauthn-authenticate). If not some fields from the
       * [navigator.credentials.get()](https://www.w3.org/TR/webauthn-2/#sctn-getAssertion) response will need to
       * be converted from array buffers to strings and marshalled into JSON.
       * @param data {@link WebAuthnAuthenticateRequest}
       * @returns {@link WebAuthnAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/webauthn/authenticate`,
          headers,
          data
        });
      }
      /**
       * Updates a Passkey or WebAuthn registration.
       * @param data {@link WebAuthnUpdateRequest}
       * @returns {@link WebAuthnUpdateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      update(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "PUT",
          url: `/v1/webauthn/${data.webauthn_registration_id}`,
          headers,
          data: {
            name: data.name
          }
        });
      }
      /**
       * List the public key credentials of the WebAuthn Registrations or Passkeys registered to a specific User.
       * @param params {@link WebAuthnListCredentialsRequest}
       * @returns {@link WebAuthnListCredentialsResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      listCredentials(params) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/webauthn/credentials/${params.user_id}/${params.domain}`,
          headers,
          params: {}
        });
      }
    };
    exports.WebAuthn = WebAuthn;
  }
});

// node_modules/stytch/dist/b2c/idp.js
var require_idp = __commonJS({
  "node_modules/stytch/dist/b2c/idp.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.IDP = void 0;
    var jose = _interopRequireWildcard((init_browser(), __toCommonJS(browser_exports)));
    var _shared = require_shared();
    var _errors = require_errors();
    function _getRequireWildcardCache(nodeInterop) {
      if (typeof WeakMap !== "function") return null;
      var cacheBabelInterop = /* @__PURE__ */ new WeakMap();
      var cacheNodeInterop = /* @__PURE__ */ new WeakMap();
      return (_getRequireWildcardCache = /* @__PURE__ */ __name(function(nodeInterop2) {
        return nodeInterop2 ? cacheNodeInterop : cacheBabelInterop;
      }, "_getRequireWildcardCache"))(nodeInterop);
    }
    __name(_getRequireWildcardCache, "_getRequireWildcardCache");
    function _interopRequireWildcard(obj, nodeInterop) {
      if (!nodeInterop && obj && obj.__esModule) {
        return obj;
      }
      if (obj === null || typeof obj !== "object" && typeof obj !== "function") {
        return { default: obj };
      }
      var cache = _getRequireWildcardCache(nodeInterop);
      if (cache && cache.has(obj)) {
        return cache.get(obj);
      }
      var newObj = {};
      var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor;
      for (var key in obj) {
        if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) {
          var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null;
          if (desc && (desc.get || desc.set)) {
            Object.defineProperty(newObj, key, desc);
          } else {
            newObj[key] = obj[key];
          }
        }
      }
      newObj.default = obj;
      if (cache) {
        cache.set(obj, newObj);
      }
      return newObj;
    }
    __name(_interopRequireWildcard, "_interopRequireWildcard");
    var IDP = class {
      static {
        __name(this, "IDP");
      }
      constructor(fetchConfig, jwtConfig) {
        this.fetchConfig = fetchConfig;
        this.jwtConfig = jwtConfig;
        this.jwksClient = jwtConfig.jwks;
      }
      async introspectTokenNetwork(data) {
        const fetchConfig = {
          ...this.fetchConfig,
          headers: {
            ["User-Agent"]: this.fetchConfig.headers["User-Agent"],
            "Content-Type": "application/x-www-form-urlencoded"
          }
        };
        const params = {
          token: data.token,
          client_id: data.client_id
        };
        if (data.client_secret && data.client_secret.length > 0) {
          params.client_secret = data.client_secret;
        }
        if (data.token_type_hint && data.token_type_hint.length > 0) {
          params.token_type_hint = data.token_type_hint;
        }
        let response;
        try {
          response = await (0, _shared.request)(fetchConfig, {
            method: "POST",
            url: `/v1/public/${this.jwtConfig.projectID}/oauth2/introspect`,
            dataRaw: new URLSearchParams(params)
          });
        } catch (err) {
          throw new _errors.ClientError("token_invalid", "Could not introspect token", err);
        }
        if (!response.active) {
          throw new _errors.ClientError("token_invalid", "Token was not active", null);
        }
        const {
          /* eslint-disable @typescript-eslint/no-unused-vars */
          aud: _aud,
          exp: _exp,
          iat: _iat,
          iss: _iss,
          nbf: _nbf,
          sub: _sub,
          status_code: _status_code,
          scope: _scope,
          active: _active,
          request_id: _request_id,
          token_type: _token_type,
          client_id: _client_id,
          /* eslint-enable @typescript-eslint/no-unused-vars */
          ...customClaims
        } = response;
        return {
          subject: _sub,
          scope: _scope,
          audience: _aud,
          expires_at: _exp,
          issued_at: _iat,
          issuer: _iss,
          not_before: _nbf,
          custom_claims: customClaims,
          token_type: _token_type
        };
      }
      async introspectTokenLocal(tokenJWT, options) {
        const jwtOptions = {
          audience: this.jwtConfig.projectID,
          issuer: this.jwtConfig.issuers,
          typ: "JWT"
        };
        const now = options?.current_date || /* @__PURE__ */ new Date();
        let payload;
        try {
          const token = await jose.jwtVerify(tokenJWT, this.jwksClient, {
            ...jwtOptions,
            clockTolerance: options?.clock_tolerance_seconds,
            currentDate: now
          });
          payload = token.payload;
        } catch (err) {
          throw new _errors.ClientError("jwt_invalid", "Could not verify JWT", err);
        }
        const {
          /* eslint-disable @typescript-eslint/no-unused-vars */
          aud: _aud,
          exp: _exp,
          iat: _iat,
          iss: _iss,
          jti: _jti,
          nbf: _nbf,
          sub: _sub,
          scope: _scope,
          /* eslint-enable @typescript-eslint/no-unused-vars */
          ...custom_claims
        } = payload;
        return {
          subject: _sub,
          expires_at: _exp,
          audience: _aud,
          issued_at: _iat,
          issuer: _iss,
          not_before: _nbf,
          scope: _scope,
          token_type: "access_token",
          custom_claims
        };
      }
    };
    exports.IDP = IDP;
  }
});

// node_modules/stytch/dist/b2c/client.js
var require_client2 = __commonJS({
  "node_modules/stytch/dist/b2c/client.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Client = void 0;
    var jose = _interopRequireWildcard((init_browser(), __toCommonJS(browser_exports)));
    var _client = require_client();
    var _crypto_wallets = require_crypto_wallets();
    var _fraud = require_fraud();
    var _impersonation = require_impersonation();
    var _sessions = require_sessions();
    var _m2m = require_m2m();
    var _magic_links = require_magic_links();
    var _oauth = require_oauth();
    var _otps = require_otps();
    var _passwords = require_passwords();
    var _project = require_project();
    var _sessions2 = require_sessions2();
    var _totps = require_totps();
    var _users = require_users();
    var _webauthn = require_webauthn();
    var _idp = require_idp();
    function _getRequireWildcardCache(nodeInterop) {
      if (typeof WeakMap !== "function") return null;
      var cacheBabelInterop = /* @__PURE__ */ new WeakMap();
      var cacheNodeInterop = /* @__PURE__ */ new WeakMap();
      return (_getRequireWildcardCache = /* @__PURE__ */ __name(function(nodeInterop2) {
        return nodeInterop2 ? cacheNodeInterop : cacheBabelInterop;
      }, "_getRequireWildcardCache"))(nodeInterop);
    }
    __name(_getRequireWildcardCache, "_getRequireWildcardCache");
    function _interopRequireWildcard(obj, nodeInterop) {
      if (!nodeInterop && obj && obj.__esModule) {
        return obj;
      }
      if (obj === null || typeof obj !== "object" && typeof obj !== "function") {
        return { default: obj };
      }
      var cache = _getRequireWildcardCache(nodeInterop);
      if (cache && cache.has(obj)) {
        return cache.get(obj);
      }
      var newObj = {};
      var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor;
      for (var key in obj) {
        if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) {
          var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null;
          if (desc && (desc.get || desc.set)) {
            Object.defineProperty(newObj, key, desc);
          } else {
            newObj[key] = obj[key];
          }
        }
      }
      newObj.default = obj;
      if (cache) {
        cache.set(obj, newObj);
      }
      return newObj;
    }
    __name(_interopRequireWildcard, "_interopRequireWildcard");
    var Client = class extends _client.BaseClient {
      static {
        __name(this, "Client");
      }
      constructor(config) {
        super(config);
        this.jwtConfig = {
          // Only allow JWTs that were meant for this project.
          projectID: config.project_id,
          // Fetch the signature verification keys for this project as needed.
          jwks: jose.createRemoteJWKSet(new URL(`/v1/sessions/jwks/${config.project_id}`, this.fetchConfig.baseURL)),
          issuers: [`stytch.com/${config.project_id}`, (0, _sessions.trimTrailingSlash)(this.fetchConfig.baseURL)]
        };
        this.cryptoWallets = new _crypto_wallets.CryptoWallets(this.fetchConfig);
        this.fraud = new _fraud.Fraud(this.fetchConfig);
        this.impersonation = new _impersonation.Impersonation(this.fetchConfig);
        this.m2m = new _m2m.M2M(this.fetchConfig, this.jwtConfig);
        this.magicLinks = new _magic_links.MagicLinks(this.fetchConfig);
        this.oauth = new _oauth.OAuth(this.fetchConfig);
        this.otps = new _otps.OTPs(this.fetchConfig);
        this.passwords = new _passwords.Passwords(this.fetchConfig);
        this.project = new _project.Project(this.fetchConfig);
        this.sessions = new _sessions2.Sessions(this.fetchConfig, this.jwtConfig);
        this.totps = new _totps.TOTPs(this.fetchConfig);
        this.users = new _users.Users(this.fetchConfig);
        this.webauthn = new _webauthn.WebAuthn(this.fetchConfig);
        this.idp = new _idp.IDP(this.fetchConfig, this.jwtConfig);
      }
    };
    exports.Client = Client;
  }
});

// node_modules/stytch/dist/b2b/discovery_intermediate_sessions.js
var require_discovery_intermediate_sessions = __commonJS({
  "node_modules/stytch/dist/b2b/discovery_intermediate_sessions.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.IntermediateSessions = void 0;
    require_method_options();
    var _shared = require_shared();
    var IntermediateSessions = class {
      static {
        __name(this, "IntermediateSessions");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Exchange an Intermediate Session for a fully realized
       * [Member Session](https://stytch.com/docs/b2b/api/session-object) in a desired
       * [Organization](https://stytch.com/docs/b2b/api/organization-object).
       * This operation consumes the Intermediate Session.
       *
       * This endpoint can be used to accept invites and create new members via domain matching.
       *
       * If the is required to complete MFA to log in to the, the returned value of `member_authenticated` will
       * be `false`.
       * The `intermediate_session_token` will not be consumed and instead will be returned in the response.
       * The `intermediate_session_token` can be passed into the
       * [OTP SMS Authenticate endpoint](https://stytch.com/docs/b2b/api/authenticate-otp-sms) to complete the
       * MFA step and acquire a full member session.
       * The `intermediate_session_token` can also be used with the
       * [Exchange Intermediate Session endpoint](https://stytch.com/docs/b2b/api/exchange-intermediate-session)
       * or the
       * [Create Organization via Discovery endpoint](https://stytch.com/docs/b2b/api/create-organization-via-discovery) to join a different Organization or create a new one.
       * The `session_duration_minutes` and `session_custom_claims` parameters will be ignored.
       *
       * If the Member is logging in via an OAuth provider that does not fully verify the email, the returned
       * value of `member_authenticated` will be `false`.
       * The `intermediate_session_token` will not be consumed and instead will be returned in the response.
       * The `primary_required` field details the authentication flow the Member must perform in order to
       * [complete a step-up authentication](https://stytch.com/docs/b2b/guides/oauth/auth-flows) into the
       * organization. The `intermediate_session_token` must be passed into that authentication flow.
       * @param data {@link B2BDiscoveryIntermediateSessionsExchangeRequest}
       * @returns {@link B2BDiscoveryIntermediateSessionsExchangeResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      exchange(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/discovery/intermediate_sessions/exchange`,
          headers,
          data
        });
      }
    };
    exports.IntermediateSessions = IntermediateSessions;
  }
});

// node_modules/stytch/dist/b2b/discovery_organizations.js
var require_discovery_organizations = __commonJS({
  "node_modules/stytch/dist/b2b/discovery_organizations.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Organizations = void 0;
    require_method_options();
    var _shared = require_shared();
    var Organizations = class {
      static {
        __name(this, "Organizations");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * If an end user does not want to join any already-existing, or has no possible Organizations to join,
       * this endpoint can be used to create a new
       * [Organization](https://stytch.com/docs/b2b/api/organization-object) and
       * [Member](https://stytch.com/docs/b2b/api/member-object).
       *
       * This operation consumes the Intermediate Session.
       *
       * This endpoint will also create an initial Member Session for the newly created Member.
       *
       * The created by this endpoint will automatically be granted the `stytch_admin` Role. See the
       * [RBAC guide](https://stytch.com/docs/b2b/guides/rbac/stytch-default) for more details on this Role.
       *
       * If the new Organization is created with a `mfa_policy` of `REQUIRED_FOR_ALL`, the newly created Member
       * will need to complete an MFA step to log in to the Organization.
       * The `intermediate_session_token` will not be consumed and instead will be returned in the response.
       * The `intermediate_session_token` can be passed into the
       * [OTP SMS Authenticate endpoint](https://stytch.com/docs/b2b/api/authenticate-otp-sms) to complete the
       * MFA step and acquire a full member session.
       * The `intermediate_session_token` can also be used with the
       * [Exchange Intermediate Session endpoint](https://stytch.com/docs/b2b/api/exchange-intermediate-session)
       * or the
       * [Create Organization via Discovery endpoint](https://stytch.com/docs/b2b/api/create-organization-via-discovery) to join a different Organization or create a new one.
       * The `session_duration_minutes` and `session_custom_claims` parameters will be ignored.
       * @param data {@link B2BDiscoveryOrganizationsCreateRequest}
       * @returns {@link B2BDiscoveryOrganizationsCreateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      create(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/discovery/organizations/create`,
          headers,
          data
        });
      }
      /**
       * List all possible organization relationships connected to a
       * [Member Session](https://stytch.com/docs/b2b/api/session-object) or Intermediate Session.
       *
       * When a Member Session is passed in, relationships with a type of `active_member`, `pending_member`, or
       * `invited_member`
       * will be returned, and any membership can be assumed by calling the
       * [Exchange Session](https://stytch.com/docs/b2b/api/exchange-session) endpoint.
       *
       * When an Intermediate Session is passed in, all relationship types - `active_member`, `pending_member`,
       * `invited_member`,
       * `eligible_to_join_by_email_domain`, and `eligible_to_join_by_oauth_tenant` - will be returned,
       * and any membership can be assumed by calling the
       * [Exchange Intermediate Session](https://stytch.com/docs/b2b/api/exchange-intermediate-session) endpoint.
       *
       * This endpoint requires either an `intermediate_session_token`, `session_jwt` or `session_token` be
       * included in the request.
       * It will return an error if multiple are present.
       *
       * This operation does not consume the Intermediate Session or Session Token passed in.
       * @param data {@link B2BDiscoveryOrganizationsListRequest}
       * @returns {@link B2BDiscoveryOrganizationsListResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      list(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/discovery/organizations`,
          headers,
          data
        });
      }
    };
    exports.Organizations = Organizations;
  }
});

// node_modules/stytch/dist/b2b/discovery.js
var require_discovery = __commonJS({
  "node_modules/stytch/dist/b2b/discovery.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Discovery = void 0;
    require_method_options();
    var _discovery_intermediate_sessions = require_discovery_intermediate_sessions();
    var _discovery_organizations = require_discovery_organizations();
    var Discovery = class {
      static {
        __name(this, "Discovery");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
        this.intermediateSessions = new _discovery_intermediate_sessions.IntermediateSessions(this.fetchConfig);
        this.organizations = new _discovery_organizations.Organizations(this.fetchConfig);
      }
    };
    exports.Discovery = Discovery;
  }
});

// node_modules/stytch/dist/b2b/impersonation.js
var require_impersonation2 = __commonJS({
  "node_modules/stytch/dist/b2b/impersonation.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Impersonation = void 0;
    require_method_options();
    var _shared = require_shared();
    var Impersonation = class {
      static {
        __name(this, "Impersonation");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Authenticate an impersonation token to impersonate a. This endpoint requires an impersonation token that
       * is not expired or previously used.
       * A Stytch session will be created for the impersonated member with a 60 minute duration. Impersonated
       * sessions cannot be extended.
       *
       * Prior to this step, you can generate an impersonation token by visiting the Stytch dashboard, viewing a
       * member, and clicking the `Impersonate Member` button.
       * @param data {@link B2BImpersonationAuthenticateRequest}
       * @returns {@link B2BImpersonationAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/impersonation/authenticate`,
          headers,
          data
        });
      }
    };
    exports.Impersonation = Impersonation;
  }
});

// node_modules/stytch/dist/b2b/magic_links_discovery.js
var require_magic_links_discovery = __commonJS({
  "node_modules/stytch/dist/b2b/magic_links_discovery.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Discovery = void 0;
    require_method_options();
    var _shared = require_shared();
    var Discovery = class {
      static {
        __name(this, "Discovery");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Authenticates the Discovery Magic Link token and exchanges it for an Intermediate Session Token.
       * Intermediate Session Tokens can be used for various Discovery login flows and are valid for 10 minutes.
       * @param data {@link B2BMagicLinksDiscoveryAuthenticateRequest}
       * @returns {@link B2BMagicLinksDiscoveryAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/magic_links/discovery/authenticate`,
          headers,
          data
        });
      }
    };
    exports.Discovery = Discovery;
  }
});

// node_modules/stytch/dist/b2b/magic_links_email_discovery.js
var require_magic_links_email_discovery = __commonJS({
  "node_modules/stytch/dist/b2b/magic_links_email_discovery.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Discovery = void 0;
    require_method_options();
    var _shared = require_shared();
    var Discovery = class {
      static {
        __name(this, "Discovery");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Send a discovery magic link to an email address. The magic link is valid for 60 minutes.
       * @param data {@link B2BMagicLinksEmailDiscoverySendRequest}
       * @returns {@link B2BMagicLinksEmailDiscoverySendResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      send(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/magic_links/email/discovery/send`,
          headers,
          data
        });
      }
    };
    exports.Discovery = Discovery;
  }
});

// node_modules/stytch/dist/b2b/magic_links_email.js
var require_magic_links_email2 = __commonJS({
  "node_modules/stytch/dist/b2b/magic_links_email.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Email = void 0;
    var _method_options = require_method_options();
    var _magic_links_email_discovery = require_magic_links_email_discovery();
    var _shared = require_shared();
    var Email = class {
      static {
        __name(this, "Email");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
        this.discovery = new _magic_links_email_discovery.Discovery(this.fetchConfig);
      }
      /**
       * Send either a login or signup magic link to a Member. A new, pending, or invited Member will receive a
       * signup Email Magic Link. Members will have a `pending` status until they successfully authenticate. An
       * active Member will receive a login Email Magic Link.
       *
       * The magic link is valid for 60 minutes.
       * @param data {@link B2BMagicLinksEmailLoginOrSignupRequest}
       * @returns {@link B2BMagicLinksEmailLoginOrSignupResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      loginOrSignup(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/magic_links/email/login_or_signup`,
          headers,
          data
        });
      }
      /**
       * Send an invite email to a new to join an. The Member will be created with an `invited` status until they
       * successfully authenticate. Sending invites to `pending` Members will update their status to `invited`.
       * Sending invites to already `active` Members will return an error.
       *
       * The magic link invite will be valid for 1 week.
       *
       * ## Revoke an invite
       *
       * To revoke an existing invite, use the [Delete Member](https://stytch.com/docs/b2b/api/delete-member)
       * endpoint. This will both delete the invited Member from the target Organization and revoke all existing
       * invite emails.
       * @param data {@link B2BMagicLinksEmailInviteRequest}
       * @param options {@link B2BMagicLinksEmailInviteRequestOptions}
       * @returns {@link B2BMagicLinksEmailInviteResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      invite(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/magic_links/email/invite`,
          headers,
          data
        });
      }
    };
    exports.Email = Email;
  }
});

// node_modules/stytch/dist/b2b/magic_links.js
var require_magic_links2 = __commonJS({
  "node_modules/stytch/dist/b2b/magic_links.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.MagicLinks = void 0;
    require_method_options();
    var _magic_links_discovery = require_magic_links_discovery();
    var _magic_links_email = require_magic_links_email2();
    var _shared = require_shared();
    var MagicLinks = class {
      static {
        __name(this, "MagicLinks");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
        this.email = new _magic_links_email.Email(this.fetchConfig);
        this.discovery = new _magic_links_discovery.Discovery(this.fetchConfig);
      }
      /**
       * Authenticate a with a Magic Link. This endpoint requires a Magic Link token that is not expired or
       * previously used. If the Member’s status is `pending` or `invited`, they will be updated to `active`.
       * Provide the `session_duration_minutes` parameter to set the lifetime of the session. If the
       * `session_duration_minutes` parameter is not specified, a Stytch session will be created with a 60 minute
       * duration.
       *
       * If the Member is required to complete MFA to log in to the, the returned value of `member_authenticated`
       * will be `false`, and an `intermediate_session_token` will be returned.
       * The `intermediate_session_token` can be passed into the
       * [OTP SMS Authenticate endpoint](https://stytch.com/docs/b2b/api/authenticate-otp-sms),
       * [TOTP Authenticate endpoint](https://stytch.com/docs/b2b/api/authenticate-totp),
       * or [Recovery Codes Recover endpoint](https://stytch.com/docs/b2b/api/recovery-codes-recover) to complete
       * the MFA step and acquire a full member session.
       * The `intermediate_session_token` can also be used with the
       * [Exchange Intermediate Session endpoint](https://stytch.com/docs/b2b/api/exchange-intermediate-session)
       * or the
       * [Create Organization via Discovery endpoint](https://stytch.com/docs/b2b/api/create-organization-via-discovery) to join a different Organization or create a new one.
       * The `session_duration_minutes` and `session_custom_claims` parameters will be ignored.
       *
       * If a valid `session_token` or `session_jwt` is passed in, the Member will not be required to complete an
       * MFA step.
       * @param data {@link B2BMagicLinksAuthenticateRequest}
       * @returns {@link B2BMagicLinksAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/magic_links/authenticate`,
          headers,
          data
        });
      }
    };
    exports.MagicLinks = MagicLinks;
  }
});

// node_modules/stytch/dist/b2b/oauth_discovery.js
var require_oauth_discovery = __commonJS({
  "node_modules/stytch/dist/b2b/oauth_discovery.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Discovery = void 0;
    require_method_options();
    var _shared = require_shared();
    var Discovery = class {
      static {
        __name(this, "Discovery");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Authenticates the Discovery token and exchanges it for an Intermediate
       * Session Token. Intermediate Session Tokens can be used for various Discovery login flows and are valid
       * for 10 minutes.
       * @param data {@link B2BOAuthDiscoveryAuthenticateRequest}
       * @returns {@link B2BOAuthDiscoveryAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/oauth/discovery/authenticate`,
          headers,
          data
        });
      }
    };
    exports.Discovery = Discovery;
  }
});

// node_modules/stytch/dist/b2b/oauth.js
var require_oauth2 = __commonJS({
  "node_modules/stytch/dist/b2b/oauth.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.OAuth = void 0;
    require_method_options();
    var _oauth_discovery = require_oauth_discovery();
    var _shared = require_shared();
    var OAuth = class {
      static {
        __name(this, "OAuth");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
        this.discovery = new _oauth_discovery.Discovery(this.fetchConfig);
      }
      /**
       * Authenticate a given a `token`. This endpoint verifies that the member completed the flow by verifying
       * that the token is valid and hasn't expired.  Provide the `session_duration_minutes` parameter to set the
       * lifetime of the session. If the `session_duration_minutes` parameter is not specified, a Stytch session
       * will be created with a 60 minute duration.
       *
       * If the Member is required to complete MFA to log in to the, the returned value of `member_authenticated`
       * will be `false`, and an `intermediate_session_token` will be returned.
       * The `intermediate_session_token` can be passed into the
       * [OTP SMS Authenticate endpoint](https://stytch.com/docs/b2b/api/authenticate-otp-sms) to complete the
       * MFA step and acquire a full member session.
       * The `intermediate_session_token` can also be used with the
       * [Exchange Intermediate Session endpoint](https://stytch.com/docs/b2b/api/exchange-intermediate-session)
       * or the
       * [Create Organization via Discovery endpoint](https://stytch.com/docs/b2b/api/create-organization-via-discovery) to join a different Organization or create a new one.
       * The `session_duration_minutes` and `session_custom_claims` parameters will be ignored.
       *
       * If a valid `session_token` or `session_jwt` is passed in, the Member will not be required to complete an
       * MFA step.
       *
       * If the Member is logging in via an OAuth provider that does not fully verify the email, the returned
       * value of `member_authenticated` will be `false`, and an `intermediate_session_token` will be returned.
       * The `primary_required` field details the authentication flow the Member must perform in order to
       * [complete a step-up authentication](https://stytch.com/docs/b2b/guides/oauth/auth-flows) into the
       * organization. The `intermediate_session_token` must be passed into that authentication flow.
       *
       * We’re actively accepting requests for new OAuth providers! Please [email us](mailto:support@stytch.com)
       * or [post in our community](https://stytch.com/docs/b2b/resources) if you are looking for an OAuth
       * provider that is not currently supported.
       * @param data {@link B2BOAuthAuthenticateRequest}
       * @returns {@link B2BOAuthAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/oauth/authenticate`,
          headers,
          data
        });
      }
    };
    exports.OAuth = OAuth;
  }
});

// node_modules/stytch/dist/b2b/organizations_members_oauth_providers.js
var require_organizations_members_oauth_providers = __commonJS({
  "node_modules/stytch/dist/b2b/organizations_members_oauth_providers.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.OAuthProviders = void 0;
    require_method_options();
    var _shared = require_shared();
    var OAuthProviders = class {
      static {
        __name(this, "OAuthProviders");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Retrieve the saved Google access token and ID token for a member. After a successful OAuth login, Stytch
       * will save the
       * issued access token and ID token from the identity provider. If a refresh token has been issued, Stytch
       * will refresh the
       * access token automatically.
       *
       * Google One Tap does not return access tokens. If the member has only authenticated through Google One
       * Tap and not through a regular Google OAuth flow, this endpoint will not return any tokens.
       *
       * __Note:__ Google does not issue a refresh token on every login, and refresh tokens may expire if unused.
       * To force a refresh token to be issued, pass the `?provider_prompt=consent` query param into the
       * [Start Google OAuth flow](https://stytch.com/docs/b2b/api/oauth-google-start) endpoint.
       * @param params {@link B2BOrganizationsMembersOAuthProvidersProviderInformationRequest}
       * @returns {@link B2BOrganizationsMembersOAuthProvidersGoogleResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      google(params) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/b2b/organizations/${params.organization_id}/members/${params.member_id}/oauth_providers/google`,
          headers,
          params: {
            include_refresh_token: params.include_refresh_token
          }
        });
      }
      /**
       * Retrieve the saved Microsoft access token and ID token for a member. After a successful OAuth login,
       * Stytch will save the
       * issued access token and ID token from the identity provider. If a refresh token has been issued, Stytch
       * will refresh the
       * access token automatically.
       * @param params {@link B2BOrganizationsMembersOAuthProvidersProviderInformationRequest}
       * @returns {@link B2BOrganizationsMembersOAuthProvidersMicrosoftResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      microsoft(params) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/b2b/organizations/${params.organization_id}/members/${params.member_id}/oauth_providers/microsoft`,
          headers,
          params: {
            include_refresh_token: params.include_refresh_token
          }
        });
      }
      /**
       * Retrieve the saved Slack access token and ID token for a member. After a successful OAuth login, Stytch
       * will save the
       * issued access token and ID token from the identity provider.
       * @param params {@link B2BOrganizationsMembersOAuthProvidersSlackRequest}
       * @returns {@link B2BOrganizationsMembersOAuthProvidersSlackResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      slack(params) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/b2b/organizations/${params.organization_id}/members/${params.member_id}/oauth_providers/slack`,
          headers,
          params: {}
        });
      }
      /**
       * Retrieve the saved Hubspot access token and ID token for a member. After a successful OAuth login,
       * Stytch will save the
       * issued access token and ID token from the identity provider. If a refresh token has been issued, Stytch
       * will refresh the
       * access token automatically.
       * @param params {@link B2BOrganizationsMembersOAuthProvidersProviderInformationRequest}
       * @returns {@link B2BOrganizationsMembersOAuthProvidersHubspotResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      hubspot(params) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/b2b/organizations/${params.organization_id}/members/${params.member_id}/oauth_providers/hubspot`,
          headers,
          params: {
            include_refresh_token: params.include_refresh_token
          }
        });
      }
      /**
       * Retrieve the saved GitHub access token for a Member. After a successful OAuth login, Stytch will save
       * the
       * issued access token from the identity provider. GitHub does not issue refresh tokens, but will
       * invalidate access
       * tokens after very long periods of inactivity.
       * @param params {@link B2BOrganizationsMembersOAuthProvidersProviderInformationRequest}
       * @returns {@link B2BOrganizationsMembersOAuthProvidersGithubResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      github(params) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/b2b/organizations/${params.organization_id}/members/${params.member_id}/oauth_providers/github`,
          headers,
          params: {
            include_refresh_token: params.include_refresh_token
          }
        });
      }
    };
    exports.OAuthProviders = OAuthProviders;
  }
});

// node_modules/stytch/dist/b2b/organizations_members.js
var require_organizations_members = __commonJS({
  "node_modules/stytch/dist/b2b/organizations_members.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Members = void 0;
    var _method_options = require_method_options();
    var _organizations_members_oauth_providers = require_organizations_members_oauth_providers();
    var _shared = require_shared();
    var Members = class {
      static {
        __name(this, "Members");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
        this.oauthProviders = new _organizations_members_oauth_providers.OAuthProviders(this.fetchConfig);
      }
      /**
       * Updates a specified by `organization_id` and `member_id`.
       * @param data {@link B2BOrganizationsMembersUpdateRequest}
       * @param options {@link B2BOrganizationsMembersUpdateRequestOptions}
       * @returns {@link B2BOrganizationsMembersUpdateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      update(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "PUT",
          url: `/v1/b2b/organizations/${data.organization_id}/members/${data.member_id}`,
          headers,
          data: {
            name: data.name,
            trusted_metadata: data.trusted_metadata,
            untrusted_metadata: data.untrusted_metadata,
            is_breakglass: data.is_breakglass,
            mfa_phone_number: data.mfa_phone_number,
            mfa_enrolled: data.mfa_enrolled,
            roles: data.roles,
            preserve_existing_sessions: data.preserve_existing_sessions,
            default_mfa_method: data.default_mfa_method,
            email_address: data.email_address,
            external_id: data.external_id,
            unlink_email: data.unlink_email
          }
        });
      }
      /**
       * Deletes a specified by `organization_id` and `member_id`.
       * @param data {@link B2BOrganizationsMembersDeleteRequest}
       * @param options {@link B2BOrganizationsMembersDeleteRequestOptions}
       * @returns {@link B2BOrganizationsMembersDeleteResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      delete(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "DELETE",
          url: `/v1/b2b/organizations/${data.organization_id}/members/${data.member_id}`,
          headers,
          data: {}
        });
      }
      /**
       * Reactivates a deleted's status and its associated email status (if applicable) to active, specified by
       * `organization_id` and `member_id`. This endpoint will only work for Members with at least one verified
       * email where their `email_address_verified` is `true`.
       * @param data {@link B2BOrganizationsMembersReactivateRequest}
       * @param options {@link B2BOrganizationsMembersReactivateRequestOptions}
       * @returns {@link B2BOrganizationsMembersReactivateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      reactivate(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "PUT",
          url: `/v1/b2b/organizations/${data.organization_id}/members/${data.member_id}/reactivate`,
          headers,
          data: {}
        });
      }
      /**
       * Delete a's MFA phone number.
       *
       * To change a Member's phone number, you must first call this endpoint to delete the existing phone number.
       *
       * Existing Member Sessions that include a phone number authentication factor will not be revoked if the
       * phone number is deleted, and MFA will not be enforced until the Member logs in again.
       * If you wish to enforce MFA immediately after a phone number is deleted, you can do so by prompting the
       * Member to enter a new phone number
       * and calling the [OTP SMS send](https://stytch.com/docs/b2b/api/otp-sms-send) endpoint, then calling the
       * [OTP SMS Authenticate](https://stytch.com/docs/b2b/api/authenticate-otp-sms) endpoint.
       * @param data {@link B2BOrganizationsMembersDeleteMFAPhoneNumberRequest}
       * @param options {@link B2BOrganizationsMembersDeleteMFAPhoneNumberRequestOptions}
       * @returns {@link B2BOrganizationsMembersDeleteMFAPhoneNumberResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      deleteMFAPhoneNumber(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "DELETE",
          url: `/v1/b2b/organizations/${data.organization_id}/members/mfa_phone_numbers/${data.member_id}`,
          headers,
          data: {}
        });
      }
      /**
       * Delete a Member's MFA TOTP registration.
       *
       * To mint a new registration for a Member, you must first call this endpoint to delete the existing
       * registration.
       *
       * Existing Member Sessions that include the TOTP authentication factor will not be revoked if the
       * registration is deleted, and MFA will not be enforced until the Member logs in again.
       * @param data {@link B2BOrganizationsMembersDeleteTOTPRequest}
       * @param options {@link B2BOrganizationsMembersDeleteTOTPRequestOptions}
       * @returns {@link B2BOrganizationsMembersDeleteTOTPResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      deleteTOTP(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "DELETE",
          url: `/v1/b2b/organizations/${data.organization_id}/members/${data.member_id}/totp`,
          headers,
          data: {}
        });
      }
      /**
       * Search for Members within specified Organizations. An array with at least one `organization_id` is
       * required. Submitting an empty `query` returns all non-deleted Members within the specified Organizations.
       *
       * *All fuzzy search filters require a minimum of three characters.
       * @param data {@link B2BOrganizationsMembersSearchRequest}
       * @param options {@link B2BOrganizationsMembersSearchRequestOptions}
       * @returns {@link B2BOrganizationsMembersSearchResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      search(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/organizations/members/search`,
          headers,
          data
        });
      }
      /**
       * Delete a's password.
       * @param data {@link B2BOrganizationsMembersDeletePasswordRequest}
       * @param options {@link B2BOrganizationsMembersDeletePasswordRequestOptions}
       * @returns {@link B2BOrganizationsMembersDeletePasswordResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      deletePassword(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "DELETE",
          url: `/v1/b2b/organizations/${data.organization_id}/members/passwords/${data.member_password_id}`,
          headers,
          data: {}
        });
      }
      /**
       * Get a Member by `member_id`. This endpoint does not require an `organization_id`, enabling you to get
       * members across organizations. This is a dangerous operation. Incorrect use may open you up to indirect
       * object reference (IDOR) attacks. We recommend using the
       * [Get Member](https://stytch.com/docs/b2b/api/get-member) API instead.
       * @param params {@link B2BOrganizationsMembersDangerouslyGetRequest}
       * @returns {@link B2BOrganizationsMembersGetResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      dangerouslyGet(params) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/b2b/organizations/members/dangerously_get/${params.member_id}`,
          headers,
          params: {
            include_deleted: params.include_deleted
          }
        });
      }
      /**
       * Retrieve the saved OIDC access tokens and ID tokens for a member. After a successful OIDC login, Stytch
       * will save the
       * issued access token and ID token from the identity provider. If a refresh token has been issued, Stytch
       * will refresh the
       * access token automatically.
       * @param params {@link B2BOrganizationsMembersOIDCProviderInformationRequest}
       * @returns {@link B2BOrganizationsMembersOIDCProvidersResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      oidcProviders(params) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/b2b/organizations/${params.organization_id}/members/${params.member_id}/oidc_providers`,
          headers,
          params: {
            include_refresh_token: params.include_refresh_token
          }
        });
      }
      /**
       * Unlinks a retired email address from a specified by their `organization_id` and `member_id`. The email
       * address
       * to be retired can be identified in the request body by either its `email_id`, its `email_address`, or
       * both. If using
       * both identifiers they must refer to the same email.
       *
       * A previously active email address can be marked as retired in one of two ways:
       *
       * - It's replaced with a new primary email address during an explicit Member update.
       * - A new email address is surfaced by an OAuth, SAML or OIDC provider. In this case the new email address
       * becomes the
       *   Member's primary email address and the old primary email address is retired.
       *
       * A retired email address cannot be used by other Members in the same Organization. However, unlinking
       * retired email
       * addresses allows them to be subsequently re-used by other Organization Members. Retired email addresses
       * can be viewed
       * on the [Member object](https://stytch.com/docs/b2b/api/member-object).
       *  %}
       * @param data {@link B2BOrganizationsMembersUnlinkRetiredEmailRequest}
       * @param options {@link B2BOrganizationsMembersUnlinkRetiredEmailRequestOptions}
       * @returns {@link B2BOrganizationsMembersUnlinkRetiredEmailResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      unlinkRetiredEmail(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/organizations/${data.organization_id}/members/${data.member_id}/unlink_retired_email`,
          headers,
          data: {
            email_id: data.email_id,
            email_address: data.email_address
          }
        });
      }
      /**
       * Creates a. An `organization_id` and `email_address` are required.
       * @param data {@link B2BOrganizationsMembersCreateRequest}
       * @param options {@link B2BOrganizationsMembersCreateRequestOptions}
       * @returns {@link B2BOrganizationsMembersCreateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      create(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/organizations/${data.organization_id}/members`,
          headers,
          data: {
            email_address: data.email_address,
            name: data.name,
            trusted_metadata: data.trusted_metadata,
            untrusted_metadata: data.untrusted_metadata,
            create_member_as_pending: data.create_member_as_pending,
            is_breakglass: data.is_breakglass,
            mfa_phone_number: data.mfa_phone_number,
            mfa_enrolled: data.mfa_enrolled,
            roles: data.roles,
            external_id: data.external_id
          }
        });
      }
      /**
       * Get a Member by `member_id` or `email_address`.
       * @param params {@link B2BOrganizationsMembersGetRequest}
       * @returns {@link B2BOrganizationsMembersGetResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      get(params) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/b2b/organizations/${params.organization_id}/member`,
          headers,
          params: {
            ...params
          }
        });
      }
    };
    exports.Members = Members;
  }
});

// node_modules/stytch/dist/b2b/organizations.js
var require_organizations = __commonJS({
  "node_modules/stytch/dist/b2b/organizations.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Organizations = void 0;
    var _method_options = require_method_options();
    var _organizations_members = require_organizations_members();
    var _shared = require_shared();
    var Organizations = class {
      static {
        __name(this, "Organizations");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
        this.members = new _organizations_members.Members(this.fetchConfig);
      }
      /**
       * Creates an. An `organization_name` and a unique `organization_slug` are required.
       *
       * By default, `email_invites` and `sso_jit_provisioning` will be set to `ALL_ALLOWED`, and `mfa_policy`
       * will be set to `OPTIONAL` if no Organization authentication settings are explicitly defined in the
       * request.
       *
       * *See the [Organization authentication settings](https://stytch.com/docs/b2b/api/org-auth-settings)
       * resource to learn more about fields like `email_jit_provisioning`, `email_invites`,
       * `sso_jit_provisioning`, etc., and their behaviors.
       * @param data {@link B2BOrganizationsCreateRequest}
       * @returns {@link B2BOrganizationsCreateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      create(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/organizations`,
          headers,
          data
        });
      }
      /**
       * Returns an specified by `organization_id`.
       * @param params {@link B2BOrganizationsGetRequest}
       * @returns {@link B2BOrganizationsGetResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      get(params) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/b2b/organizations/${params.organization_id}`,
          headers,
          params: {}
        });
      }
      /**
       * Updates an specified by `organization_id`. An Organization must always have at least one auth setting
       * set to either `RESTRICTED` or `ALL_ALLOWED` in order to provision new Members.
       *
       * *See the [Organization authentication settings](https://stytch.com/docs/b2b/api/org-auth-settings)
       * resource to learn more about fields like `email_jit_provisioning`, `email_invites`,
       * `sso_jit_provisioning`, etc., and their behaviors.
       * @param data {@link B2BOrganizationsUpdateRequest}
       * @param options {@link B2BOrganizationsUpdateRequestOptions}
       * @returns {@link B2BOrganizationsUpdateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      update(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "PUT",
          url: `/v1/b2b/organizations/${data.organization_id}`,
          headers,
          data: {
            organization_name: data.organization_name,
            organization_slug: data.organization_slug,
            organization_logo_url: data.organization_logo_url,
            trusted_metadata: data.trusted_metadata,
            sso_default_connection_id: data.sso_default_connection_id,
            sso_jit_provisioning: data.sso_jit_provisioning,
            sso_jit_provisioning_allowed_connections: data.sso_jit_provisioning_allowed_connections,
            email_allowed_domains: data.email_allowed_domains,
            email_jit_provisioning: data.email_jit_provisioning,
            email_invites: data.email_invites,
            auth_methods: data.auth_methods,
            allowed_auth_methods: data.allowed_auth_methods,
            mfa_policy: data.mfa_policy,
            rbac_email_implicit_role_assignments: data.rbac_email_implicit_role_assignments,
            mfa_methods: data.mfa_methods,
            allowed_mfa_methods: data.allowed_mfa_methods,
            oauth_tenant_jit_provisioning: data.oauth_tenant_jit_provisioning,
            allowed_oauth_tenants: data.allowed_oauth_tenants,
            claimed_email_domains: data.claimed_email_domains
          }
        });
      }
      /**
       * Deletes an specified by `organization_id`. All Members of the Organization will also be deleted.
       * @param data {@link B2BOrganizationsDeleteRequest}
       * @param options {@link B2BOrganizationsDeleteRequestOptions}
       * @returns {@link B2BOrganizationsDeleteResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      delete(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "DELETE",
          url: `/v1/b2b/organizations/${data.organization_id}`,
          headers,
          data: {}
        });
      }
      /**
       * Search for Organizations. If you send a request with no body params, no filtering will be applied and
       * the endpoint will return all Organizations. All fuzzy search filters require a minimum of three
       * characters.
       * @param data {@link B2BOrganizationsSearchRequest}
       * @returns {@link B2BOrganizationsSearchResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      search(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/organizations/search`,
          headers,
          data
        });
      }
      /**
       * @param params {@link B2BOrganizationsMetricsRequest}
       * @returns {@link B2BOrganizationsMetricsResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      metrics(params) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/b2b/organizations/${params.organization_id}/metrics`,
          headers,
          params: {}
        });
      }
    };
    exports.Organizations = Organizations;
  }
});

// node_modules/stytch/dist/b2b/otp_email_discovery.js
var require_otp_email_discovery = __commonJS({
  "node_modules/stytch/dist/b2b/otp_email_discovery.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Discovery = void 0;
    require_method_options();
    var _shared = require_shared();
    var Discovery = class {
      static {
        __name(this, "Discovery");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Send a discovery OTP to an email address. The OTP is valid for 10 minutes. Only the most recently sent
       * OTP is valid: when an OTP is sent, all OTPs previously sent to the same email address are invalidated,
       * even if unused or unexpired.
       * @param data {@link B2BOTPEmailDiscoverySendRequest}
       * @returns {@link B2BOTPEmailDiscoverySendResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      send(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/otps/email/discovery/send`,
          headers,
          data
        });
      }
      /**
       * Authenticates the OTP and returns an intermediate session token. Intermediate session tokens can be used
       * for various Discovery login flows and are valid for 10 minutes.
       * @param data {@link B2BOTPEmailDiscoveryAuthenticateRequest}
       * @returns {@link B2BOTPEmailDiscoveryAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/otps/email/discovery/authenticate`,
          headers,
          data
        });
      }
    };
    exports.Discovery = Discovery;
  }
});

// node_modules/stytch/dist/b2b/otp_email.js
var require_otp_email = __commonJS({
  "node_modules/stytch/dist/b2b/otp_email.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Email = void 0;
    require_method_options();
    var _otp_email_discovery = require_otp_email_discovery();
    var _shared = require_shared();
    var Email = class {
      static {
        __name(this, "Email");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
        this.discovery = new _otp_email_discovery.Discovery(this.fetchConfig);
      }
      /**
       * Send either a login or signup email OTP to a Member. A new, pending, or invited Member will receive a
       * signup email OTP. Non-active members will have a pending status until they successfully authenticate. An
       * active Member will receive a login email OTP.
       *
       * The OTP is valid for 10 minutes. Only the most recently sent OTP is valid: when an OTP is sent, all OTPs
       * previously sent to the same email address are invalidated, even if unused or unexpired.
       * @param data {@link B2BOTPEmailLoginOrSignupRequest}
       * @returns {@link B2BOTPEmailLoginOrSignupResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      loginOrSignup(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/otps/email/login_or_signup`,
          headers,
          data
        });
      }
      /**
       * Authenticate a with a one-time passcode (OTP). This endpoint requires an OTP that is not expired or
       * previously used.
       * OTPs have a default expiry of 10 minutes. If the Member’s status is `pending` or `invited`, they will be
       * updated to `active`.
       * Provide the `session_duration_minutes` parameter to set the lifetime of the session. If the
       * `session_duration_minutes` parameter is not specified, a Stytch session will be created with a 60 minute
       * duration.
       *
       * If the Member is required to complete MFA to log in to the, the returned value of `member_authenticated`
       * will be `false`, and an `intermediate_session_token` will be returned.
       * The `intermediate_session_token` can be passed into the
       * [OTP SMS Authenticate endpoint](https://stytch.com/docs/b2b/api/authenticate-otp-sms),
       * [TOTP Authenticate endpoint](https://stytch.com/docs/b2b/api/authenticate-totp),
       * or [Recovery Codes Recover endpoint](https://stytch.com/docs/b2b/api/recovery-codes-recover) to complete
       * the MFA step and acquire a full member session.
       * The `intermediate_session_token` can also be used with the
       * [Exchange Intermediate Session endpoint](https://stytch.com/docs/b2b/api/exchange-intermediate-session)
       * or the
       * [Create Organization via Discovery endpoint](https://stytch.com/docs/b2b/api/create-organization-via-discovery) to join a different Organization or create a new one.
       * The `session_duration_minutes` and `session_custom_claims` parameters will be ignored.
       *
       * If a valid `session_token` or `session_jwt` is passed in, the Member will not be required to complete an
       * MFA step.
       * @param data {@link B2BOTPEmailAuthenticateRequest}
       * @returns {@link B2BOTPEmailAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/otps/email/authenticate`,
          headers,
          data
        });
      }
    };
    exports.Email = Email;
  }
});

// node_modules/stytch/dist/b2b/otp_sms.js
var require_otp_sms = __commonJS({
  "node_modules/stytch/dist/b2b/otp_sms.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Sms = void 0;
    require_method_options();
    var _shared = require_shared();
    var Sms = class {
      static {
        __name(this, "Sms");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Send a One-Time Passcode (OTP) to a's phone number.
       *
       * If the Member already has a phone number, the `mfa_phone_number` field is not needed; the endpoint will
       * send an OTP to the number associated with the Member.
       * If the Member does not have a phone number, the endpoint will send an OTP to the `mfa_phone_number`
       * provided and link the `mfa_phone_number` with the Member.
       *
       * An error will be thrown if the Member already has a phone number and the provided `mfa_phone_number`
       * does not match the existing one.
       *
       * OTP codes expire after two minutes. Note that sending another OTP code before the first has expired will
       * invalidate the first code.
       *
       * If a Member has a phone number and is enrolled in MFA, then after a successful primary authentication
       * event (e.g. [email magic link](https://stytch.com/docs/b2b/api/authenticate-magic-link) or
       * [SSO](https://stytch.com/docs/b2b/api/sso-authenticate) login is complete), an SMS OTP will
       * automatically be sent to their phone number. In that case, this endpoint should only be used for
       * subsequent authentication events, such as prompting a Member for an OTP again after a period of
       * inactivity.
       *
       * Passing an intermediate session token, session token, or session JWT is not required, but if passed must
       * match the Member ID passed.
       *
       * ### Cost to send SMS OTP
       * Before configuring SMS or WhatsApp OTPs, please review how Stytch
       * [bills the costs of international OTPs](https://stytch.com/pricing) and understand how to protect your
       * app against [toll fraud](https://stytch.com/docs/guides/passcodes/toll-fraud/overview).
       *
       * Even when international SMS is enabled, we do not support sending SMS to countries on our
       * [Unsupported countries list](https://stytch.com/docs/guides/passcodes/unsupported-countries).
       *
       * __Note:__ SMS to phone numbers outside of the US and Canada is disabled by default for customers who did
       * not use SMS prior to October 2023. If you're interested in sending international SMS, please reach out
       * to [support@stytch.com](mailto:support@stytch.com?subject=Enable%20international%20SMS).
       * @param data {@link B2BOTPSmsSendRequest}
       * @returns {@link B2BOTPSmsSendResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      send(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/otps/sms/send`,
          headers,
          data
        });
      }
      /**
       * SMS OTPs may not be used as a primary authentication mechanism. They can be used to complete an MFA
       * requirement, or they can be used as a step-up factor to be added to an existing session.
       *
       * This endpoint verifies that the one-time passcode (OTP) is valid and hasn't expired or been previously
       * used. OTP codes expire after two minutes.
       *
       * A given Member may only have a single active OTP code at any given time. If a Member requests another
       * OTP code before the first one has expired, the first one will be invalidated.
       *
       * Exactly one of `intermediate_session_token`, `session_token`, or `session_jwt` must be provided in the
       * request.
       * If an intermediate session token is provided, this operation will consume it.
       *
       * Intermediate session tokens are generated upon successful calls to primary authenticate methods in the
       * case where MFA is required,
       * such as [email magic link authenticate](https://stytch.com/docs/b2b/api/authenticate-magic-link),
       * or upon successful calls to discovery authenticate methods, such as
       * [email magic link discovery authenticate](https://stytch.com/docs/b2b/api/authenticate-discovery-magic-link).
       *
       * If the's MFA policy is `REQUIRED_FOR_ALL`, a successful OTP authentication will change the's
       * `mfa_enrolled` status to `true` if it is not already `true`.
       * If the Organization's MFA policy is `OPTIONAL`, the Member's MFA enrollment can be toggled by passing in
       * a value for the `set_mfa_enrollment` field.
       * The Member's MFA enrollment can also be toggled through the
       * [Update Member](https://stytch.com/docs/b2b/api/update-member) endpoint.
       *
       * Provide the `session_duration_minutes` parameter to set the lifetime of the session. If the
       * `session_duration_minutes` parameter is not specified, a Stytch session will be created with a duration
       * of 60 minutes.
       * @param data {@link B2BOTPSmsAuthenticateRequest}
       * @returns {@link B2BOTPSmsAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/otps/sms/authenticate`,
          headers,
          data
        });
      }
    };
    exports.Sms = Sms;
  }
});

// node_modules/stytch/dist/b2b/otp.js
var require_otp = __commonJS({
  "node_modules/stytch/dist/b2b/otp.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.OTPs = void 0;
    require_method_options();
    var _otp_email = require_otp_email();
    var _otp_sms = require_otp_sms();
    var OTPs = class {
      static {
        __name(this, "OTPs");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
        this.sms = new _otp_sms.Sms(this.fetchConfig);
        this.email = new _otp_email.Email(this.fetchConfig);
      }
    };
    exports.OTPs = OTPs;
  }
});

// node_modules/stytch/dist/b2b/passwords_discovery_email.js
var require_passwords_discovery_email = __commonJS({
  "node_modules/stytch/dist/b2b/passwords_discovery_email.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Email = void 0;
    require_method_options();
    var _shared = require_shared();
    var Email = class {
      static {
        __name(this, "Email");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Initiates a password reset for the email address provided, when cross-org passwords are enabled. This
       * will trigger an email to be sent to the address, containing a magic link that will allow them to set a
       * new password and authenticate.
       *
       * This endpoint adapts to your Project's password strength configuration.
       * If you're using [zxcvbn](https://stytch.com/docs/guides/passwords/strength-policy), the default, your
       * passwords are considered valid
       * if the strength score is >= 3. If you're using
       * [LUDS](https://stytch.com/docs/guides/passwords/strength-policy), your passwords are
       * considered valid if they meet the requirements that you've set with Stytch.
       * You may update your password strength configuration in the
       * [stytch dashboard](https://stytch.com/dashboard/password-strength-config).
       * @param data {@link B2BPasswordsDiscoveryEmailResetStartRequest}
       * @returns {@link B2BPasswordsDiscoveryEmailResetStartResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      resetStart(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/passwords/discovery/email/reset/start`,
          headers,
          data
        });
      }
      /**
       * Reset the password associated with an email and start an intermediate session. This endpoint checks that
       * the password reset token is valid, hasn’t expired, or already been used.
       *
       * The provided password needs to meet the project's password strength requirements, which can be checked
       * in advance with the password strength endpoint. If the token and password are accepted, the password is
       * securely stored for future authentication and the user is authenticated.
       *
       * Resetting a password will start an intermediate session and return a list of discovered organizations
       * the session can be exchanged into.
       * @param data {@link B2BPasswordsDiscoveryEmailResetRequest}
       * @returns {@link B2BPasswordsDiscoveryEmailResetResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      reset(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/passwords/discovery/email/reset`,
          headers,
          data
        });
      }
    };
    exports.Email = Email;
  }
});

// node_modules/stytch/dist/b2b/passwords_discovery.js
var require_passwords_discovery = __commonJS({
  "node_modules/stytch/dist/b2b/passwords_discovery.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Discovery = void 0;
    require_method_options();
    var _passwords_discovery_email = require_passwords_discovery_email();
    var _shared = require_shared();
    var Discovery = class {
      static {
        __name(this, "Discovery");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
        this.email = new _passwords_discovery_email.Email(this.fetchConfig);
      }
      /**
       * Authenticate an email/password combination in the discovery flow. This authenticate flow is only valid
       * for cross-org passwords use cases, and is not tied to a specific organization.
       *
       * If you have breach detection during authentication enabled in your
       * [password strength policy](https://stytch.com/docs/b2b/guides/passwords/strength-policies) and the
       * member's credentials have appeared in the HaveIBeenPwned dataset, this endpoint will return a
       * `member_reset_password` error even if the member enters a correct password. We force a password reset in
       * this case to ensure that the member is the legitimate owner of the email address and not a malicious
       * actor abusing the compromised credentials.
       *
       * If successful, this endpoint will create a new intermediate session and return a list of discovered
       * organizations that can be session exchanged into.
       * @param data {@link B2BPasswordsDiscoveryAuthenticateRequest}
       * @returns {@link B2BPasswordsDiscoveryAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/passwords/discovery/authenticate`,
          headers,
          data
        });
      }
    };
    exports.Discovery = Discovery;
  }
});

// node_modules/stytch/dist/b2b/passwords_email.js
var require_passwords_email2 = __commonJS({
  "node_modules/stytch/dist/b2b/passwords_email.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Email = void 0;
    var _method_options = require_method_options();
    var _shared = require_shared();
    var Email = class {
      static {
        __name(this, "Email");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Initiates a password reset for the email address provided. This will trigger an email to be sent to the
       * address, containing a magic link that will allow them to set a new password and authenticate.
       *
       * This endpoint adapts to your Project's password strength configuration.
       * If you're using [zxcvbn](https://stytch.com/docs/guides/passwords/strength-policy), the default, your
       * passwords are considered valid
       * if the strength score is >= 3. If you're using
       * [LUDS](https://stytch.com/docs/guides/passwords/strength-policy), your passwords are
       * considered valid if they meet the requirements that you've set with Stytch.
       * You may update your password strength configuration in the
       * [stytch dashboard](https://stytch.com/dashboard/password-strength-config).
       * @param data {@link B2BPasswordsEmailResetStartRequest}
       * @returns {@link B2BPasswordsEmailResetStartResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      resetStart(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/passwords/email/reset/start`,
          headers,
          data
        });
      }
      /**
       * Reset the's password and authenticate them. This endpoint checks that the password reset token is valid,
       * hasn’t expired, or already been used.
       *
       * The provided password needs to meet our password strength requirements, which can be checked in advance
       * with the password strength endpoint. If the token and password are accepted, the password is securely
       * stored for future authentication and the user is authenticated.
       *
       * If the Member is required to complete MFA to log in to the Organization, the returned value of
       * `member_authenticated` will be `false`, and an `intermediate_session_token` will be returned.
       * The `intermediate_session_token` can be passed into the
       * [OTP SMS Authenticate endpoint](https://stytch.com/docs/b2b/api/authenticate-otp-sms) to complete the
       * MFA step and acquire a full member session.
       * The `session_duration_minutes` and `session_custom_claims` parameters will be ignored.
       *
       * If a valid `session_token` or `session_jwt` is passed in, the Member will not be required to complete an
       * MFA step.
       *
       * Note that a successful password reset by email will revoke all active sessions for the `member_id`.
       * @param data {@link B2BPasswordsEmailResetRequest}
       * @returns {@link B2BPasswordsEmailResetResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      reset(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/passwords/email/reset`,
          headers,
          data
        });
      }
      /**
       * Require a password be reset by the associated email address. This endpoint is only functional for
       * cross-org password use cases.
       * @param data {@link B2BPasswordsEmailRequireResetRequest}
       * @param options {@link B2BPasswordsEmailRequireResetRequestOptions}
       * @returns {@link B2BPasswordsEmailRequireResetResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      requireReset(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/passwords/email/require_reset`,
          headers,
          data
        });
      }
    };
    exports.Email = Email;
  }
});

// node_modules/stytch/dist/b2b/passwords_existing_password.js
var require_passwords_existing_password2 = __commonJS({
  "node_modules/stytch/dist/b2b/passwords_existing_password.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.ExistingPassword = void 0;
    require_method_options();
    var _shared = require_shared();
    var ExistingPassword = class {
      static {
        __name(this, "ExistingPassword");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Reset the’s password using their existing password.
       *
       * This endpoint adapts to your Project's password strength configuration.
       * If you're using [zxcvbn](https://stytch.com/docs/guides/passwords/strength-policy), the default, your
       * passwords are considered valid
       * if the strength score is >= 3. If you're using
       * [LUDS](https://stytch.com/docs/guides/passwords/strength-policy), your passwords are
       * considered valid if they meet the requirements that you've set with Stytch.
       * You may update your password strength configuration in the
       * [stytch dashboard](https://stytch.com/dashboard/password-strength-config).
       *
       * If the Member is required to complete MFA to log in to the Organization, the returned value of
       * `member_authenticated` will be `false`, and an `intermediate_session_token` will be returned.
       * The `intermediate_session_token` can be passed into the
       * [OTP SMS Authenticate endpoint](https://stytch.com/docs/b2b/api/authenticate-otp-sms) to complete the
       * MFA step and acquire a full member session.
       * The `session_duration_minutes` and `session_custom_claims` parameters will be ignored.
       *
       * If a valid `session_token` or `session_jwt` is passed in, the Member will not be required to complete an
       * MFA step.
       *
       * Note that a successful password reset via an existing password will revoke all active sessions for the
       * `member_id`.
       * @param data {@link B2BPasswordsExistingPasswordResetRequest}
       * @returns {@link B2BPasswordsExistingPasswordResetResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      reset(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/passwords/existing_password/reset`,
          headers,
          data
        });
      }
    };
    exports.ExistingPassword = ExistingPassword;
  }
});

// node_modules/stytch/dist/b2b/passwords_session.js
var require_passwords_session2 = __commonJS({
  "node_modules/stytch/dist/b2b/passwords_session.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Sessions = void 0;
    require_method_options();
    var _shared = require_shared();
    var Sessions = class {
      static {
        __name(this, "Sessions");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Reset the's password using their existing session. The endpoint will error if the session does not
       * contain an authentication factor that has been issued within the last 5 minutes. Either `session_token`
       * or `session_jwt` should be provided.
       *
       * Note that a successful password reset via an existing session will revoke all active sessions for the
       * `member_id`, except for the one used during the reset flow.
       * @param data {@link B2BPasswordsSessionResetRequest}
       * @returns {@link B2BPasswordsSessionResetResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      reset(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/passwords/session/reset`,
          headers,
          data
        });
      }
    };
    exports.Sessions = Sessions;
  }
});

// node_modules/stytch/dist/b2b/passwords.js
var require_passwords2 = __commonJS({
  "node_modules/stytch/dist/b2b/passwords.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Passwords = void 0;
    require_method_options();
    var _passwords_discovery = require_passwords_discovery();
    var _passwords_email = require_passwords_email2();
    var _passwords_existing_password = require_passwords_existing_password2();
    var _shared = require_shared();
    var _passwords_session = require_passwords_session2();
    var Passwords = class {
      static {
        __name(this, "Passwords");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
        this.email = new _passwords_email.Email(this.fetchConfig);
        this.sessions = new _passwords_session.Sessions(this.fetchConfig);
        this.existingPassword = new _passwords_existing_password.ExistingPassword(this.fetchConfig);
        this.discovery = new _passwords_discovery.Discovery(this.fetchConfig);
      }
      /**
       * This API allows you to check whether the user’s provided password is valid, and to provide feedback to
       * the user on how to increase the strength of their password.
       *
       * This endpoint adapts to your Project's password strength configuration. If you're using
       * [zxcvbn](https://stytch.com/docs/guides/passwords/strength-policy), the default, your passwords are
       * considered valid if the strength score is >= 3. If you're using
       * [LUDS](https://stytch.com/docs/guides/passwords/strength-policy), your passwords are considered valid if
       * they meet the requirements that you've set with Stytch. You may update your password strength
       * configuration in the [stytch dashboard](https://stytch.com/dashboard/password-strength-config).
       *
       * ## Password feedback
       * The zxcvbn_feedback and luds_feedback objects contains relevant fields for you to relay feedback to
       * users that failed to create a strong enough password.
       *
       * If you're using [zxcvbn](https://stytch.com/docs/guides/passwords/strength-policy), the feedback object
       * will contain warning and suggestions for any password that does not meet the
       * [zxcvbn](https://stytch.com/docs/guides/passwords/strength-policy) strength requirements. You can return
       * these strings directly to the user to help them craft a strong password.
       *
       * If you're using [LUDS](https://stytch.com/docs/guides/passwords/strength-policy), the feedback object
       * will contain a collection of fields that the user failed or passed. You'll want to prompt the user to
       * create a password that meets all requirements that they failed.
       * @param data {@link B2BPasswordsStrengthCheckRequest}
       * @returns {@link B2BPasswordsStrengthCheckResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      strengthCheck(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/passwords/strength_check`,
          headers,
          data
        });
      }
      /**
       * Adds an existing password to a member's email that doesn't have a password yet. We support migrating
       * members from passwords stored with bcrypt, scrypt, argon2, MD-5, SHA-1, and PBKDF2. This endpoint has a
       * rate limit of 100 requests per second.
       *
       * The member's email will be marked as verified when you use this endpoint. If you are using
       * **cross-organization passwords**, call this method separately for each `organization_id` associated with
       * the given `email_address` to ensure the email is verified across all of their organizations.
       * @param data {@link B2BPasswordsMigrateRequest}
       * @returns {@link B2BPasswordsMigrateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      migrate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/passwords/migrate`,
          headers,
          data
        });
      }
      /**
       * Authenticate a member with their email address and password. This endpoint verifies that the member has
       * a password currently set, and that the entered password is correct.
       *
       * If you have breach detection during authentication enabled in your
       * [password strength policy](https://stytch.com/docs/b2b/guides/passwords/strength-policies) and the
       * member's credentials have appeared in the HaveIBeenPwned dataset, this endpoint will return a
       * `member_reset_password` error even if the member enters a correct password. We force a password reset in
       * this case to ensure that the member is the legitimate owner of the email address and not a malicious
       * actor abusing the compromised credentials.
       *
       * If the is required to complete MFA to log in to the, the returned value of `member_authenticated` will
       * be `false`, and an `intermediate_session_token` will be returned.
       * The `intermediate_session_token` can be passed into the
       * [OTP SMS Authenticate endpoint](https://stytch.com/docs/b2b/api/authenticate-otp-sms) to complete the
       * MFA step and acquire a full member session.
       * The `session_duration_minutes` and `session_custom_claims` parameters will be ignored.
       *
       * If a valid `session_token` or `session_jwt` is passed in, the Member will not be required to complete an
       * MFA step.
       * @param data {@link B2BPasswordsAuthenticateRequest}
       * @returns {@link B2BPasswordsAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/passwords/authenticate`,
          headers,
          data
        });
      }
    };
    exports.Passwords = Passwords;
  }
});

// node_modules/stytch/dist/b2b/rbac_local.js
var require_rbac_local = __commonJS({
  "node_modules/stytch/dist/b2b/rbac_local.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.PolicyCache = void 0;
    exports.performAuthorizationCheck = performAuthorizationCheck;
    exports.performScopeAuthorizationCheck = performScopeAuthorizationCheck;
    var _errors = require_errors();
    var MAX_AGE_MS = 1e3 * 60 * 5;
    var PolicyCache = class {
      static {
        __name(this, "PolicyCache");
      }
      constructor(rbac) {
        this.rbac = rbac;
      }
      fresh() {
        return !!this._timestamp && Date.now() < this._timestamp + MAX_AGE_MS;
      }
      async reload() {
        const policyResponse = await this.rbac.policy();
        this._policy = policyResponse.policy;
        this._timestamp = Date.now();
      }
      async getPolicy() {
        if (!this._policy || !this.fresh()) {
          await this.reload();
        }
        return this._policy;
      }
    };
    exports.PolicyCache = PolicyCache;
    function performAuthorizationCheck({
      policy,
      subjectRoles,
      subjectOrgID,
      authorizationCheck
    }) {
      if (subjectOrgID !== authorizationCheck.organization_id) {
        throw new _errors.ClientError("tenancy_mismatch", "Member belongs to different organization");
      }
      const hasPermission = policy.roles.filter((role) => subjectRoles.includes(role.role_id)).flatMap((role) => role.permissions).some((permission) => {
        const hasMatchingAction = permission.actions.includes(authorizationCheck.action) || permission.actions.includes("*");
        const hasMatchingResource = authorizationCheck.resource_id === permission.resource_id;
        return hasMatchingAction && hasMatchingResource;
      });
      if (!hasPermission) {
        throw new _errors.ClientError("invalid_permissions", "Member does not have permission to perform the requested action");
      }
    }
    __name(performAuthorizationCheck, "performAuthorizationCheck");
    function performScopeAuthorizationCheck({
      policy,
      tokenScopes,
      subjectOrgID,
      authorizationCheck
    }) {
      if (subjectOrgID !== authorizationCheck.organization_id) {
        throw new _errors.ClientError("tenancy_mismatch", "Member belongs to different organization");
      }
      const hasPermission = policy.scopes.filter((scope) => tokenScopes.includes(scope.scope)).flatMap((scope) => scope.permissions).some((permission) => {
        const hasMatchingAction = permission.actions.includes(authorizationCheck.action) || permission.actions.includes("*");
        const hasMatchingResource = authorizationCheck.resource_id === permission.resource_id;
        return hasMatchingAction && hasMatchingResource;
      });
      if (!hasPermission) {
        throw new _errors.ClientError("invalid_permissions", "Member does not have permission to perform the requested action");
      }
    }
    __name(performScopeAuthorizationCheck, "performScopeAuthorizationCheck");
  }
});

// node_modules/stytch/dist/b2b/rbac.js
var require_rbac = __commonJS({
  "node_modules/stytch/dist/b2b/rbac.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.RBAC = void 0;
    require_method_options();
    var _shared = require_shared();
    var RBAC = class {
      static {
        __name(this, "RBAC");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Get the active RBAC Policy for your current Stytch Project. An RBAC Policy is the canonical document
       * that stores all defined Resources and Roles within your RBAC permissioning model.
       *
       * When using the backend SDKs, the RBAC Policy will be cached to allow for local evaluations, eliminating
       * the need for an extra request to Stytch. The policy will be refreshed if an authorization check is
       * requested and the RBAC policy was last updated more than 5 minutes ago.
       *
       * Resources and Roles can be created and managed within the
       * [Dashboard](https://stytch.com/docs/dashboard/rbac). Additionally,
       * [Role assignment](https://stytch.com/docs/b2b/guides/rbac/role-assignment) can be programmatically
       * managed through certain Stytch API endpoints.
       *
       * Check out the [RBAC overview](https://stytch.com/docs/b2b/guides/rbac/overview) to learn more about
       * Stytch's RBAC permissioning model.
       * @param params {@link B2BRBACPolicyRequest}
       * @returns {@link B2BRBACPolicyResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      policy() {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/b2b/rbac/policy`,
          headers
        });
      }
    };
    exports.RBAC = RBAC;
  }
});

// node_modules/stytch/dist/b2b/recovery_codes.js
var require_recovery_codes = __commonJS({
  "node_modules/stytch/dist/b2b/recovery_codes.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.RecoveryCodes = void 0;
    require_method_options();
    var _shared = require_shared();
    var RecoveryCodes = class {
      static {
        __name(this, "RecoveryCodes");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Allows a to complete an MFA flow by consuming a recovery code. This consumes the recovery code and
       * returns a session token that can be used to authenticate the Member.
       * @param data {@link B2BRecoveryCodesRecoverRequest}
       * @returns {@link B2BRecoveryCodesRecoverResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      recover(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/recovery_codes/recover`,
          headers,
          data
        });
      }
      /**
       * Returns a's full set of active recovery codes.
       * @param params {@link B2BRecoveryCodesGetRequest}
       * @returns {@link B2BRecoveryCodesGetResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      get(params) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/b2b/recovery_codes/${params.organization_id}/${params.member_id}`,
          headers,
          params: {}
        });
      }
      /**
       * Rotate a's recovery codes. This invalidates all existing recovery codes and generates a new set of
       * recovery codes.
       * @param data {@link B2BRecoveryCodesRotateRequest}
       * @returns {@link B2BRecoveryCodesRotateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      rotate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/recovery_codes/rotate`,
          headers,
          data
        });
      }
    };
    exports.RecoveryCodes = RecoveryCodes;
  }
});

// node_modules/stytch/dist/b2b/scim_connection.js
var require_scim_connection = __commonJS({
  "node_modules/stytch/dist/b2b/scim_connection.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Connection = void 0;
    var _method_options = require_method_options();
    var _shared = require_shared();
    var Connection = class {
      static {
        __name(this, "Connection");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Update a SCIM Connection.
       * @param data {@link B2BSCIMConnectionUpdateRequest}
       * @param options {@link B2BSCIMConnectionUpdateRequestOptions}
       * @returns {@link B2BSCIMConnectionUpdateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      update(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "PUT",
          url: `/v1/b2b/scim/${data.organization_id}/connection/${data.connection_id}`,
          headers,
          data: {
            display_name: data.display_name,
            identity_provider: data.identity_provider,
            scim_group_implicit_role_assignments: data.scim_group_implicit_role_assignments
          }
        });
      }
      /**
       * Deletes a SCIM Connection.
       * @param data {@link B2BSCIMConnectionDeleteRequest}
       * @param options {@link B2BSCIMConnectionDeleteRequestOptions}
       * @returns {@link B2BSCIMConnectionDeleteResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      delete(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "DELETE",
          url: `/v1/b2b/scim/${data.organization_id}/connection/${data.connection_id}`,
          headers,
          data: {}
        });
      }
      /**
       * Start a SCIM token rotation.
       * @param data {@link B2BSCIMConnectionRotateStartRequest}
       * @param options {@link B2BSCIMConnectionRotateStartRequestOptions}
       * @returns {@link B2BSCIMConnectionRotateStartResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      rotateStart(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/scim/${data.organization_id}/connection/${data.connection_id}/rotate/start`,
          headers,
          data: {}
        });
      }
      /**
       * Completes a SCIM token rotation. This will complete the current token rotation process and update the
       * active token to be the new token supplied in the
       * [start SCIM token rotation](https://stytch.com/docs/b2b/api/scim-rotate-token-start) response.
       * @param data {@link B2BSCIMConnectionRotateCompleteRequest}
       * @param options {@link B2BSCIMConnectionRotateCompleteRequestOptions}
       * @returns {@link B2BSCIMConnectionRotateCompleteResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      rotateComplete(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/scim/${data.organization_id}/connection/${data.connection_id}/rotate/complete`,
          headers,
          data: {}
        });
      }
      /**
       * Cancel a SCIM token rotation. This will cancel the current token rotation process, keeping the original
       * token active.
       * @param data {@link B2BSCIMConnectionRotateCancelRequest}
       * @param options {@link B2BSCIMConnectionRotateCancelRequestOptions}
       * @returns {@link B2BSCIMConnectionRotateCancelResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      rotateCancel(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/scim/${data.organization_id}/connection/${data.connection_id}/rotate/cancel`,
          headers,
          data: {}
        });
      }
      /**
       * Gets a paginated list of all SCIM Groups associated with a given Connection.
       * @param params {@link B2BSCIMConnectionGetGroupsRequest}
       * @param options {@link B2BSCIMConnectionGetGroupsRequestOptions}
       * @returns {@link B2BSCIMConnectionGetGroupsResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      getGroups(params, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/b2b/scim/${params.organization_id}/connection/${params.connection_id}`,
          headers,
          params: {
            cursor: params.cursor,
            limit: params.limit
          }
        });
      }
      /**
       * Create a new SCIM Connection.
       * @param data {@link B2BSCIMConnectionCreateRequest}
       * @param options {@link B2BSCIMConnectionCreateRequestOptions}
       * @returns {@link B2BSCIMConnectionCreateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      create(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/scim/${data.organization_id}/connection`,
          headers,
          data: {
            display_name: data.display_name,
            identity_provider: data.identity_provider
          }
        });
      }
      /**
       * Get SCIM Connection.
       * @param params {@link B2BSCIMConnectionGetRequest}
       * @param options {@link B2BSCIMConnectionGetRequestOptions}
       * @returns {@link B2BSCIMConnectionGetResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      get(params, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/b2b/scim/${params.organization_id}/connection`,
          headers,
          params: {}
        });
      }
    };
    exports.Connection = Connection;
  }
});

// node_modules/stytch/dist/b2b/scim.js
var require_scim = __commonJS({
  "node_modules/stytch/dist/b2b/scim.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.SCIM = void 0;
    require_method_options();
    var _scim_connection = require_scim_connection();
    var SCIM = class {
      static {
        __name(this, "SCIM");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
        this.connection = new _scim_connection.Connection(this.fetchConfig);
      }
    };
    exports.SCIM = SCIM;
  }
});

// node_modules/stytch/dist/b2b/sessions.js
var require_sessions3 = __commonJS({
  "node_modules/stytch/dist/b2b/sessions.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.Sessions = void 0;
    var _method_options = require_method_options();
    var _shared = require_shared();
    var _sessions = require_sessions();
    var _rbac_local = require_rbac_local();
    var Sessions = class {
      static {
        __name(this, "Sessions");
      }
      constructor(fetchConfig, jwtConfig, policyCache) {
        this.fetchConfig = fetchConfig;
        this.jwksClient = jwtConfig.jwks;
        this.jwtOptions = {
          audience: jwtConfig.projectID,
          issuer: jwtConfig.issuers,
          typ: "JWT"
        };
        this.policyCache = policyCache;
      }
      /**
       * Retrieves all active Sessions for a Member.
       * @param params {@link B2BSessionsGetRequest}
       * @returns {@link B2BSessionsGetResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      get(params) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/b2b/sessions`,
          headers,
          params: {
            ...params
          }
        });
      }
      /**
       * Authenticates a Session and updates its lifetime by the specified `session_duration_minutes`. If the
       * `session_duration_minutes` is not specified, a Session will not be extended. This endpoint requires
       * either a `session_jwt` or `session_token` be included in the request. It will return an error if both
       * are present.
       *
       * You may provide a JWT that needs to be refreshed and is expired according to its `exp` claim. A new JWT
       * will be returned if both the signature and the underlying Session are still valid. See our
       * [How to use Stytch Session JWTs](https://stytch.com/docs/b2b/guides/sessions/resources/using-jwts) guide
       * for more information.
       *
       * If an `authorization_check` object is passed in, this method will also check if the Member is authorized
       * to perform the given action on the given Resource in the specified. A is authorized if their Member
       * Session contains a Role, assigned
       * [explicitly or implicitly](https://stytch.com/docs/b2b/guides/rbac/role-assignment), with adequate
       * permissions.
       * In addition, the `organization_id` passed in the authorization check must match the Member's
       * Organization.
       *
       * If the Member is not authorized to perform the specified action on the specified Resource, or if the
       * `organization_id` does not match the Member's Organization, a 403 error will be thrown.
       * Otherwise, the response will contain a list of Roles that satisfied the authorization check.
       * @param data {@link B2BSessionsAuthenticateRequest}
       * @returns {@link B2BSessionsAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/sessions/authenticate`,
          headers,
          data
        });
      }
      /**
       * Revoke a Session and immediately invalidate all its tokens. To revoke a specific Session, pass either
       * the `member_session_id`, `session_token`, or `session_jwt`. To revoke all Sessions for a Member, pass
       * the `member_id`.
       * @param data {@link B2BSessionsRevokeRequest}
       * @param options {@link B2BSessionsRevokeRequestOptions}
       * @returns {@link B2BSessionsRevokeResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      revoke(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/sessions/revoke`,
          headers,
          data
        });
      }
      /**
       * Use this endpoint to exchange a's existing session for another session in a different. This can be used
       * to accept an invite, but not to create a new member via domain matching.
       *
       * To create a new member via domain matching, use the
       * [Exchange Intermediate Session](https://stytch.com/docs/b2b/api/exchange-intermediate-session) flow
       * instead.
       *
       * Only Email Magic Link, OAuth, and SMS OTP factors can be transferred between sessions. Other
       * authentication factors, such as password factors, will not be transferred to the new session.
       * Any OAuth Tokens owned by the Member will not be transferred to the new Organization.
       * SMS OTP factors can be used to fulfill MFA requirements for the target Organization if both the original
       * and target Member have the same phone number and the phone number is verified for both Members.
       * HubSpot and Slack OAuth registrations will not be transferred between sessions. Instead, you will
       * receive a corresponding factor with type `"oauth_exchange_slack"` or `"oauth_exchange_hubspot"`
       *
       * If the Member is required to complete MFA to log in to the Organization, the returned value of
       * `member_authenticated` will be `false`, and an `intermediate_session_token` will be returned.
       * The `intermediate_session_token` can be passed into the
       * [OTP SMS Authenticate endpoint](https://stytch.com/docs/b2b/api/authenticate-otp-sms) to complete the
       * MFA step and acquire a full member session.
       * The `intermediate_session_token` can also be used with the
       * [Exchange Intermediate Session endpoint](https://stytch.com/docs/b2b/api/exchange-intermediate-session)
       * or the
       * [Create Organization via Discovery endpoint](https://stytch.com/docs/b2b/api/create-organization-via-discovery) to join a different Organization or create a new one.
       * The `session_duration_minutes` and `session_custom_claims` parameters will be ignored.
       * @param data {@link B2BSessionsExchangeRequest}
       * @returns {@link B2BSessionsExchangeResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      exchange(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/sessions/exchange`,
          headers,
          data
        });
      }
      /**
       * Use this endpoint to exchange a Connected Apps Access Token back into a Member Session for the
       * underlying Member.
       * This session can be used with the Stytch SDKs and APIs.
       *
       * The Access Token must contain the `full_access` scope and must not be more than 5 minutes old. Access
       * Tokens may only be exchanged a single time.
       *
       * Because the Member previously completed MFA and satisfied all Organization authentication requirements
       * at the time of the original Access Token issuance, this endpoint will never return an
       * `intermediate_session_token` or require MFA.
       * @param data {@link B2BSessionsExchangeAccessTokenRequest}
       * @returns {@link B2BSessionsExchangeAccessTokenResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      exchangeAccessToken(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/sessions/exchange_access_token`,
          headers,
          data
        });
      }
      /**
       * Migrate a session from an external OIDC compliant endpoint. Stytch will call the external UserInfo
       * endpoint defined in your Stytch Project settings in the [Dashboard](https://stytch.com/docs/dashboard),
       * and then perform a lookup using the `session_token`. If the response contains a valid email address,
       * Stytch will attempt to match that email address with an existing in your and create a Stytch Session.
       * You will need to create the member before using this endpoint.
       * @param data {@link B2BSessionsMigrateRequest}
       * @returns {@link B2BSessionsMigrateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      migrate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/sessions/migrate`,
          headers,
          data
        });
      }
      /**
       * Get the JSON Web Key Set (JWKS) for a project.
       *
       * JWKS are rotated every ~6 months. Upon rotation, new JWTs will be signed using the new key, and both
       * keys will be returned by this endpoint for a period of 1 month.
       *
       * JWTs have a set lifetime of 5 minutes, so there will be a 5 minute period where some JWTs will be signed
       * by the old JWKS, and some JWTs will be signed by the new JWKS. The correct JWKS to use for validation is
       * determined by matching the `kid` value of the JWT and JWKS.
       *
       * If you're using one of our [backend SDKs](https://stytch.com/docs/b2b/sdks), the JWKS rotation will be
       * handled for you.
       *
       * If you're using your own JWT validation library, many have built-in support for JWKS rotation, and
       * you'll just need to supply this API endpoint. If not, your application should decide which JWKS to use
       * for validation by inspecting the `kid` value.
       *
       * See our
       * [How to use Stytch Session JWTs](https://stytch.com/docs/b2b/guides/sessions/resources/using-jwts) guide
       * for more information.
       * @param params {@link B2BSessionsGetJWKSRequest}
       * @returns {@link B2BSessionsGetJWKSResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      getJWKS(params) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/b2b/sessions/jwks/${params.project_id}`,
          headers,
          params: {}
        });
      }
      // MANUAL(authenticateJwt)(SERVICE_METHOD)
      // ADDIMPORT: import { JwtConfig, authenticateSessionJwtLocal } from "../shared/sessions";
      // ADDIMPORT: import { performAuthorizationCheck } from "./rbac_local";
      /** Parse a JWT and verify the signature, preferring local verification over remote.
       *
       * If max_token_age_seconds is set, remote verification will be forced if the JWT was issued at
       * (based on the "iat" claim) more than that many seconds ago.
       *
       * To force remote validation for all tokens, set max_token_age_seconds to zero or use the
       * authenticate method instead.
       */
      async authenticateJwt(params) {
        try {
          const member_session = await this.authenticateJwtLocal(params);
          return {
            member_session,
            session_jwt: params.session_jwt
          };
        } catch (err) {
          return this.authenticate({
            session_jwt: params.session_jwt,
            authorization_check: params.authorization_check
          });
        }
      }
      /** Parse a JWT and verify the signature locally (without calling /authenticate in the API).
       *
       * If maxTokenAge is set, this will return an error if the JWT was issued (based on the "iat"
       * claim) more than maxTokenAge seconds ago.
       *
       * If max_token_age_seconds is explicitly set to zero, all tokens will be considered too old,
       * even if they are otherwise valid.
       *
       * The value for current_date is used to compare timestamp claims ("exp", "nbf", "iat"). It
       * defaults to the current date (new Date()).
       *
       * The value for clock_tolerance_seconds is the maximum allowable difference when comparing
       * timestamps. It defaults to zero.
       */
      async authenticateJwtLocal(params) {
        const sess = await (0, _sessions.authenticateSessionJwtLocal)(this.jwksClient, this.jwtOptions, params.session_jwt, {
          clock_tolerance_seconds: params.clock_tolerance_seconds,
          max_token_age_seconds: params.max_token_age_seconds,
          current_date: params.current_date
        });
        const organizationClaim = "https://stytch.com/organization";
        const {
          [organizationClaim]: orgClaimUntyped,
          ...claims
        } = sess.custom_claims;
        const orgClaim = orgClaimUntyped;
        if (params.authorization_check) {
          const policy = await this.policyCache.getPolicy();
          await (0, _rbac_local.performAuthorizationCheck)({
            policy,
            subjectRoles: sess.roles,
            subjectOrgID: orgClaim.organization_id,
            authorizationCheck: params.authorization_check
          });
        }
        return {
          member_session_id: sess.session_id,
          member_id: sess.sub,
          organization_id: orgClaim.organization_id,
          authentication_factors: sess.authentication_factors,
          started_at: sess.started_at,
          last_accessed_at: sess.last_accessed_at,
          expires_at: sess.expires_at,
          custom_claims: claims,
          roles: sess.roles
        };
      }
      // ENDMANUAL(authenticateJwt)
    };
    exports.Sessions = Sessions;
  }
});

// node_modules/stytch/dist/b2b/sso_external.js
var require_sso_external = __commonJS({
  "node_modules/stytch/dist/b2b/sso_external.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.External = void 0;
    var _method_options = require_method_options();
    var _shared = require_shared();
    var External = class {
      static {
        __name(this, "External");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Create a new External SSO Connection.
       * @param data {@link B2BSSOExternalCreateConnectionRequest}
       * @param options {@link B2BSSOExternalCreateConnectionRequestOptions}
       * @returns {@link B2BSSOExternalCreateConnectionResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      createConnection(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/sso/external/${data.organization_id}`,
          headers,
          data: {
            external_organization_id: data.external_organization_id,
            external_connection_id: data.external_connection_id,
            display_name: data.display_name,
            connection_implicit_role_assignments: data.connection_implicit_role_assignments,
            group_implicit_role_assignments: data.group_implicit_role_assignments
          }
        });
      }
      /**
       * Updates an existing External SSO connection.
       * @param data {@link B2BSSOExternalUpdateConnectionRequest}
       * @param options {@link B2BSSOExternalUpdateConnectionRequestOptions}
       * @returns {@link B2BSSOExternalUpdateConnectionResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      updateConnection(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "PUT",
          url: `/v1/b2b/sso/external/${data.organization_id}/connections/${data.connection_id}`,
          headers,
          data: {
            display_name: data.display_name,
            external_connection_implicit_role_assignments: data.external_connection_implicit_role_assignments,
            external_group_implicit_role_assignments: data.external_group_implicit_role_assignments
          }
        });
      }
    };
    exports.External = External;
  }
});

// node_modules/stytch/dist/b2b/sso_oidc.js
var require_sso_oidc = __commonJS({
  "node_modules/stytch/dist/b2b/sso_oidc.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.OIDC = void 0;
    var _method_options = require_method_options();
    var _shared = require_shared();
    var OIDC = class {
      static {
        __name(this, "OIDC");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Create a new OIDC Connection.
       * @param data {@link B2BSSOOIDCCreateConnectionRequest}
       * @param options {@link B2BSSOOIDCCreateConnectionRequestOptions}
       * @returns {@link B2BSSOOIDCCreateConnectionResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      createConnection(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/sso/oidc/${data.organization_id}`,
          headers,
          data: {
            display_name: data.display_name,
            identity_provider: data.identity_provider
          }
        });
      }
      /**
       * Updates an existing OIDC connection.
       *
       * When the value of `issuer` changes, Stytch will attempt to retrieve the
       * [OpenID Provider Metadata](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)
       * document found at `$/.well-known/openid-configuration`.
       * If the metadata document can be retrieved successfully, Stytch will use it to infer the values of
       * `authorization_url`, `token_url`, `jwks_url`, and `userinfo_url`.
       * The `client_id` and `client_secret` values cannot be inferred from the metadata document, and *must* be
       * passed in explicitly.
       *
       * If the metadata document cannot be retrieved, Stytch will still update the connection using values from
       * the request body.
       *
       * If the metadata document can be retrieved, and values are passed in the request body, the explicit
       * values passed in from the request body will take precedence over the values inferred from the metadata
       * document.
       *
       * Note that a newly created connection will not become active until all of the following fields are
       * provided:
       * * `issuer`
       * * `client_id`
       * * `client_secret`
       * * `authorization_url`
       * * `token_url`
       * * `userinfo_url`
       * * `jwks_url`
       * @param data {@link B2BSSOOIDCUpdateConnectionRequest}
       * @param options {@link B2BSSOOIDCUpdateConnectionRequestOptions}
       * @returns {@link B2BSSOOIDCUpdateConnectionResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      updateConnection(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "PUT",
          url: `/v1/b2b/sso/oidc/${data.organization_id}/connections/${data.connection_id}`,
          headers,
          data: {
            display_name: data.display_name,
            client_id: data.client_id,
            client_secret: data.client_secret,
            issuer: data.issuer,
            authorization_url: data.authorization_url,
            token_url: data.token_url,
            userinfo_url: data.userinfo_url,
            jwks_url: data.jwks_url,
            identity_provider: data.identity_provider,
            custom_scopes: data.custom_scopes,
            attribute_mapping: data.attribute_mapping
          }
        });
      }
    };
    exports.OIDC = OIDC;
  }
});

// node_modules/stytch/dist/b2b/sso_saml.js
var require_sso_saml = __commonJS({
  "node_modules/stytch/dist/b2b/sso_saml.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.SAML = void 0;
    var _method_options = require_method_options();
    var _shared = require_shared();
    var SAML = class {
      static {
        __name(this, "SAML");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Create a new SAML Connection.
       * @param data {@link B2BSSOSAMLCreateConnectionRequest}
       * @param options {@link B2BSSOSAMLCreateConnectionRequestOptions}
       * @returns {@link B2BSSOSAMLCreateConnectionResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      createConnection(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/sso/saml/${data.organization_id}`,
          headers,
          data: {
            display_name: data.display_name,
            identity_provider: data.identity_provider
          }
        });
      }
      /**
       * Updates an existing SAML connection.
       *
       * Note that a newly created connection will not become active until all of the following are provided:
       * * `idp_sso_url`
       * * `attribute_mapping`
       * * `idp_entity_id`
       * * `x509_certificate`
       * @param data {@link B2BSSOSAMLUpdateConnectionRequest}
       * @param options {@link B2BSSOSAMLUpdateConnectionRequestOptions}
       * @returns {@link B2BSSOSAMLUpdateConnectionResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      updateConnection(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "PUT",
          url: `/v1/b2b/sso/saml/${data.organization_id}/connections/${data.connection_id}`,
          headers,
          data: {
            idp_entity_id: data.idp_entity_id,
            display_name: data.display_name,
            attribute_mapping: data.attribute_mapping,
            x509_certificate: data.x509_certificate,
            idp_sso_url: data.idp_sso_url,
            saml_connection_implicit_role_assignments: data.saml_connection_implicit_role_assignments,
            saml_group_implicit_role_assignments: data.saml_group_implicit_role_assignments,
            alternative_audience_uri: data.alternative_audience_uri,
            identity_provider: data.identity_provider,
            signing_private_key: data.signing_private_key,
            nameid_format: data.nameid_format,
            alternative_acs_url: data.alternative_acs_url,
            idp_initiated_auth_disabled: data.idp_initiated_auth_disabled
          }
        });
      }
      /**
       * Used to update an existing SAML connection using an IDP metadata URL.
       *
       * A newly created connection will not become active until all the following are provided:
       * * `idp_sso_url`
       * * `idp_entity_id`
       * * `x509_certificate`
       * * `attribute_mapping` (must be supplied using [Update SAML Connection](update-saml-connection))
       * @param data {@link B2BSSOSAMLUpdateByURLRequest}
       * @param options {@link B2BSSOSAMLUpdateByURLRequestOptions}
       * @returns {@link B2BSSOSAMLUpdateByURLResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      updateByURL(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "PUT",
          url: `/v1/b2b/sso/saml/${data.organization_id}/connections/${data.connection_id}/url`,
          headers,
          data: {
            metadata_url: data.metadata_url
          }
        });
      }
      /**
       * Delete a SAML verification certificate.
       *
       * You may need to do this when rotating certificates from your IdP, since Stytch allows a maximum of 5
       * certificates per connection. There must always be at least one certificate per active connection.
       * @param data {@link B2BSSOSAMLDeleteVerificationCertificateRequest}
       * @param options {@link B2BSSOSAMLDeleteVerificationCertificateRequestOptions}
       * @returns {@link B2BSSOSAMLDeleteVerificationCertificateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      deleteVerificationCertificate(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "DELETE",
          url: `/v1/b2b/sso/saml/${data.organization_id}/connections/${data.connection_id}/verification_certificates/${data.certificate_id}`,
          headers,
          data: {}
        });
      }
    };
    exports.SAML = SAML;
  }
});

// node_modules/stytch/dist/b2b/sso.js
var require_sso = __commonJS({
  "node_modules/stytch/dist/b2b/sso.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.SSO = void 0;
    var _method_options = require_method_options();
    var _sso_external = require_sso_external();
    var _sso_oidc = require_sso_oidc();
    var _shared = require_shared();
    var _sso_saml = require_sso_saml();
    var SSO = class {
      static {
        __name(this, "SSO");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
        this.oidc = new _sso_oidc.OIDC(this.fetchConfig);
        this.saml = new _sso_saml.SAML(this.fetchConfig);
        this.external = new _sso_external.External(this.fetchConfig);
      }
      /**
       * Get all SSO Connections owned by the organization.
       * @param params {@link B2BSSOGetConnectionsRequest}
       * @param options {@link B2BSSOGetConnectionsRequestOptions}
       * @returns {@link B2BSSOGetConnectionsResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      getConnections(params, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "GET",
          url: `/v1/b2b/sso/${params.organization_id}`,
          headers,
          params: {}
        });
      }
      /**
       * Delete an existing SSO connection.
       * @param data {@link B2BSSODeleteConnectionRequest}
       * @param options {@link B2BSSODeleteConnectionRequestOptions}
       * @returns {@link B2BSSODeleteConnectionResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      deleteConnection(data, options) {
        const headers = {};
        if (options?.authorization) {
          (0, _method_options.addAuthorizationHeaders)(headers, options.authorization);
        }
        return (0, _shared.request)(this.fetchConfig, {
          method: "DELETE",
          url: `/v1/b2b/sso/${data.organization_id}/connections/${data.connection_id}`,
          headers,
          data: {}
        });
      }
      /**
       * Authenticate a user given a token.
       * This endpoint verifies that the user completed the SSO Authentication flow by verifying that the token
       * is valid and hasn't expired.
       * Provide the `session_duration_minutes` parameter to set the lifetime of the session.
       * If the `session_duration_minutes` parameter is not specified, a Stytch session will be created with a 60
       * minute duration.
       * To link this authentication event to an existing Stytch session, include either the `session_token` or
       * `session_jwt` param.
       *
       * If the is required to complete MFA to log in to the, the returned value of `member_authenticated` will
       * be `false`, and an `intermediate_session_token` will be returned.
       * The `intermediate_session_token` can be passed into the
       * [OTP SMS Authenticate endpoint](https://stytch.com/docs/b2b/api/authenticate-otp-sms),
       * [TOTP Authenticate endpoint](https://stytch.com/docs/b2b/api/authenticate-totp),
       * or [Recovery Codes Recover endpoint](https://stytch.com/docs/b2b/api/recovery-codes-recover) to complete
       * the MFA step and acquire a full member session.
       * The `session_duration_minutes` and `session_custom_claims` parameters will be ignored.
       *
       * If a valid `session_token` or `session_jwt` is passed in, the Member will not be required to complete an
       * MFA step.
       * @param data {@link B2BSSOAuthenticateRequest}
       * @returns {@link B2BSSOAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/sso/authenticate`,
          headers,
          data
        });
      }
    };
    exports.SSO = SSO;
  }
});

// node_modules/stytch/dist/b2b/totps.js
var require_totps2 = __commonJS({
  "node_modules/stytch/dist/b2b/totps.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.TOTPs = void 0;
    require_method_options();
    var _shared = require_shared();
    var TOTPs = class {
      static {
        __name(this, "TOTPs");
      }
      constructor(fetchConfig) {
        this.fetchConfig = fetchConfig;
      }
      /**
       * Create a new TOTP instance for a. The Member can use the authenticator application of their choice to
       * scan the QR code or enter the secret.
       *
       * Passing an intermediate session token, session token, or session JWT is not required, but if passed must
       * match the Member ID passed.
       * @param data {@link B2BTOTPsCreateRequest}
       * @returns {@link B2BTOTPsCreateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      create(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/totp`,
          headers,
          data
        });
      }
      /**
       * Authenticate a Member provided TOTP.
       * @param data {@link B2BTOTPsAuthenticateRequest}
       * @returns {@link B2BTOTPsAuthenticateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      authenticate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/totp/authenticate`,
          headers,
          data
        });
      }
      /**
       * Migrate an existing TOTP instance for a. Recovery codes are not required and will be minted for the
       * Member if not provided.
       * @param data {@link B2BTOTPsMigrateRequest}
       * @returns {@link B2BTOTPsMigrateResponse}
       * @async
       * @throws A {@link StytchError} on a non-2xx response from the Stytch API
       * @throws A {@link RequestError} when the Stytch API cannot be reached
       */
      migrate(data) {
        const headers = {};
        return (0, _shared.request)(this.fetchConfig, {
          method: "POST",
          url: `/v1/b2b/totp/migrate`,
          headers,
          data
        });
      }
    };
    exports.TOTPs = TOTPs;
  }
});

// node_modules/stytch/dist/b2b/idp.js
var require_idp2 = __commonJS({
  "node_modules/stytch/dist/b2b/idp.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.IDP = void 0;
    var jose = _interopRequireWildcard((init_browser(), __toCommonJS(browser_exports)));
    var _shared = require_shared();
    var _rbac_local = require_rbac_local();
    var _errors = require_errors();
    function _getRequireWildcardCache(nodeInterop) {
      if (typeof WeakMap !== "function") return null;
      var cacheBabelInterop = /* @__PURE__ */ new WeakMap();
      var cacheNodeInterop = /* @__PURE__ */ new WeakMap();
      return (_getRequireWildcardCache = /* @__PURE__ */ __name(function(nodeInterop2) {
        return nodeInterop2 ? cacheNodeInterop : cacheBabelInterop;
      }, "_getRequireWildcardCache"))(nodeInterop);
    }
    __name(_getRequireWildcardCache, "_getRequireWildcardCache");
    function _interopRequireWildcard(obj, nodeInterop) {
      if (!nodeInterop && obj && obj.__esModule) {
        return obj;
      }
      if (obj === null || typeof obj !== "object" && typeof obj !== "function") {
        return { default: obj };
      }
      var cache = _getRequireWildcardCache(nodeInterop);
      if (cache && cache.has(obj)) {
        return cache.get(obj);
      }
      var newObj = {};
      var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor;
      for (var key in obj) {
        if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) {
          var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null;
          if (desc && (desc.get || desc.set)) {
            Object.defineProperty(newObj, key, desc);
          } else {
            newObj[key] = obj[key];
          }
        }
      }
      newObj.default = obj;
      if (cache) {
        cache.set(obj, newObj);
      }
      return newObj;
    }
    __name(_interopRequireWildcard, "_interopRequireWildcard");
    var IDP = class {
      static {
        __name(this, "IDP");
      }
      constructor(fetchConfig, jwtConfig, policyCache) {
        this.fetchConfig = fetchConfig;
        this.jwtConfig = jwtConfig;
        this.jwksClient = jwtConfig.jwks;
        this.policyCache = policyCache;
      }
      async introspectTokenNetwork(data, options) {
        const fetchConfig = {
          ...this.fetchConfig,
          headers: {
            ["User-Agent"]: this.fetchConfig.headers["User-Agent"],
            "Content-Type": "application/x-www-form-urlencoded"
          }
        };
        const params = {
          token: data.token,
          client_id: data.client_id
        };
        if (data.client_secret && data.client_secret.length > 0) {
          params.client_secret = data.client_secret;
        }
        if (data.token_type_hint && data.token_type_hint.length > 0) {
          params.token_type_hint = data.token_type_hint;
        }
        let response;
        try {
          response = await (0, _shared.request)(fetchConfig, {
            method: "POST",
            url: `/v1/public/${this.jwtConfig.projectID}/oauth2/introspect`,
            dataRaw: new URLSearchParams(params)
          });
        } catch (err) {
          throw new _errors.ClientError("token_invalid", "Could not introspect token", err);
        }
        if (!response.active) {
          throw new _errors.ClientError("token_invalid", "Token was not active", null);
        }
        const {
          /* eslint-disable @typescript-eslint/no-unused-vars */
          aud: _aud,
          exp: _exp,
          iat: _iat,
          iss: _iss,
          nbf: _nbf,
          sub: _sub,
          status_code: _status_code,
          scope: _scope,
          active: _active,
          request_id: _request_id,
          token_type: _token_type,
          client_id: _client_id,
          "https://stytch.com/organization": _organization_claim,
          /* eslint-enable @typescript-eslint/no-unused-vars */
          ...customClaims
        } = response;
        if (options?.authorization_check) {
          const policy = await this.policyCache.getPolicy();
          const organization_id = _organization_claim["organization_id"];
          (0, _rbac_local.performScopeAuthorizationCheck)({
            policy,
            subjectOrgID: organization_id,
            tokenScopes: _scope.trim().split(" "),
            authorizationCheck: options.authorization_check
          });
        }
        const organization = {
          organization_id: _organization_claim.organization_id,
          slug: _organization_claim.slug
        };
        return {
          subject: _sub,
          scope: _scope,
          audience: _aud,
          expires_at: _exp,
          issued_at: _iat,
          issuer: _iss,
          not_before: _nbf,
          token_type: _token_type,
          organization,
          custom_claims: customClaims
        };
      }
      async introspectTokenLocal(tokenJWT, options) {
        const jwtOptions = {
          audience: this.jwtConfig.projectID,
          issuer: this.jwtConfig.issuers,
          typ: "JWT"
        };
        const now = options?.current_date || /* @__PURE__ */ new Date();
        let payload;
        try {
          const token = await jose.jwtVerify(tokenJWT, this.jwksClient, {
            ...jwtOptions,
            clockTolerance: options?.clock_tolerance_seconds,
            currentDate: now
          });
          payload = token.payload;
        } catch (err) {
          throw new _errors.ClientError("jwt_invalid", "Could not verify JWT", err);
        }
        const {
          /* eslint-disable @typescript-eslint/no-unused-vars */
          aud: _aud,
          exp: _exp,
          iat: _iat,
          iss: _iss,
          jti: _jti,
          nbf: _nbf,
          sub: _sub,
          scope: _scope,
          "https://stytch.com/organization": _organization_claim,
          /* eslint-enable @typescript-eslint/no-unused-vars */
          ...custom_claims
        } = payload;
        if (options?.authorization_check) {
          const policy = await this.policyCache.getPolicy();
          (0, _rbac_local.performScopeAuthorizationCheck)({
            policy,
            subjectOrgID: _organization_claim["organization_id"],
            tokenScopes: _scope.trim().split(" "),
            authorizationCheck: options.authorization_check
          });
        }
        const organization = {
          organization_id: _organization_claim.organization_id,
          slug: _organization_claim.slug
        };
        return {
          subject: _sub,
          expires_at: _exp,
          audience: _aud,
          issued_at: _iat,
          issuer: _iss,
          not_before: _nbf,
          scope: _scope,
          token_type: "access_token",
          organization,
          custom_claims
        };
      }
    };
    exports.IDP = IDP;
  }
});

// node_modules/stytch/dist/b2b/client.js
var require_client3 = __commonJS({
  "node_modules/stytch/dist/b2b/client.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    exports.B2BClient = void 0;
    var jose = _interopRequireWildcard((init_browser(), __toCommonJS(browser_exports)));
    var _client = require_client();
    var _discovery = require_discovery();
    var _fraud = require_fraud();
    var _impersonation = require_impersonation2();
    var _sessions = require_sessions();
    var _m2m = require_m2m();
    var _magic_links = require_magic_links2();
    var _oauth = require_oauth2();
    var _organizations = require_organizations();
    var _otp = require_otp();
    var _passwords = require_passwords2();
    var _rbac_local = require_rbac_local();
    var _project = require_project();
    var _rbac = require_rbac();
    var _recovery_codes = require_recovery_codes();
    var _scim = require_scim();
    var _sessions2 = require_sessions3();
    var _sso = require_sso();
    var _totps = require_totps2();
    var _idp = require_idp2();
    function _getRequireWildcardCache(nodeInterop) {
      if (typeof WeakMap !== "function") return null;
      var cacheBabelInterop = /* @__PURE__ */ new WeakMap();
      var cacheNodeInterop = /* @__PURE__ */ new WeakMap();
      return (_getRequireWildcardCache = /* @__PURE__ */ __name(function(nodeInterop2) {
        return nodeInterop2 ? cacheNodeInterop : cacheBabelInterop;
      }, "_getRequireWildcardCache"))(nodeInterop);
    }
    __name(_getRequireWildcardCache, "_getRequireWildcardCache");
    function _interopRequireWildcard(obj, nodeInterop) {
      if (!nodeInterop && obj && obj.__esModule) {
        return obj;
      }
      if (obj === null || typeof obj !== "object" && typeof obj !== "function") {
        return { default: obj };
      }
      var cache = _getRequireWildcardCache(nodeInterop);
      if (cache && cache.has(obj)) {
        return cache.get(obj);
      }
      var newObj = {};
      var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor;
      for (var key in obj) {
        if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) {
          var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null;
          if (desc && (desc.get || desc.set)) {
            Object.defineProperty(newObj, key, desc);
          } else {
            newObj[key] = obj[key];
          }
        }
      }
      newObj.default = obj;
      if (cache) {
        cache.set(obj, newObj);
      }
      return newObj;
    }
    __name(_interopRequireWildcard, "_interopRequireWildcard");
    var B2BClient = class extends _client.BaseClient {
      static {
        __name(this, "B2BClient");
      }
      constructor(config) {
        super(config);
        this.jwtConfig = {
          // Only allow JWTs that were meant for this project.
          projectID: config.project_id,
          // Fetch the signature verification keys for this project as needed.
          jwks: jose.createRemoteJWKSet(new URL(`/v1/b2b/sessions/jwks/${config.project_id}`, this.fetchConfig.baseURL)),
          issuers: [`stytch.com/${config.project_id}`, (0, _sessions.trimTrailingSlash)(this.fetchConfig.baseURL)]
        };
        const policyCache = new _rbac_local.PolicyCache(new _rbac.RBAC(this.fetchConfig));
        this.discovery = new _discovery.Discovery(this.fetchConfig);
        this.fraud = new _fraud.Fraud(this.fetchConfig);
        this.impersonation = new _impersonation.Impersonation(this.fetchConfig);
        this.m2m = new _m2m.M2M(this.fetchConfig, this.jwtConfig);
        this.magicLinks = new _magic_links.MagicLinks(this.fetchConfig);
        this.oauth = new _oauth.OAuth(this.fetchConfig);
        this.otps = new _otp.OTPs(this.fetchConfig);
        this.organizations = new _organizations.Organizations(this.fetchConfig);
        this.passwords = new _passwords.Passwords(this.fetchConfig);
        this.project = new _project.Project(this.fetchConfig);
        this.rbac = new _rbac.RBAC(this.fetchConfig);
        this.recoveryCodes = new _recovery_codes.RecoveryCodes(this.fetchConfig);
        this.scim = new _scim.SCIM(this.fetchConfig);
        this.sso = new _sso.SSO(this.fetchConfig);
        this.sessions = new _sessions2.Sessions(this.fetchConfig, this.jwtConfig, policyCache);
        this.totps = new _totps.TOTPs(this.fetchConfig);
        this.idp = new _idp.IDP(this.fetchConfig, this.jwtConfig, policyCache);
      }
    };
    exports.B2BClient = B2BClient;
  }
});

// node_modules/stytch/dist/b2c/index.js
var require_b2c = __commonJS({
  "node_modules/stytch/dist/b2c/index.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
  }
});

// node_modules/stytch/dist/b2b/index.js
var require_b2b = __commonJS({
  "node_modules/stytch/dist/b2b/index.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
  }
});

// node_modules/stytch/dist/index.js
var require_dist = __commonJS({
  "node_modules/stytch/dist/index.js"(exports) {
    "use strict";
    init_checked_fetch();
    init_strip_cf_connecting_ip_header();
    init_modules_watch_stub();
    Object.defineProperty(exports, "__esModule", {
      value: true
    });
    var _exportNames = {
      Client: true,
      B2BClient: true,
      envs: true
    };
    Object.defineProperty(exports, "B2BClient", {
      enumerable: true,
      get: /* @__PURE__ */ __name(function() {
        return _client2.B2BClient;
      }, "get")
    });
    Object.defineProperty(exports, "Client", {
      enumerable: true,
      get: /* @__PURE__ */ __name(function() {
        return _client.Client;
      }, "get")
    });
    exports.envs = exports.default = void 0;
    var _client = require_client2();
    var _client2 = require_client3();
    var _index = require_b2c();
    Object.keys(_index).forEach(function(key) {
      if (key === "default" || key === "__esModule") return;
      if (Object.prototype.hasOwnProperty.call(_exportNames, key)) return;
      if (key in exports && exports[key] === _index[key]) return;
      Object.defineProperty(exports, key, {
        enumerable: true,
        get: /* @__PURE__ */ __name(function() {
          return _index[key];
        }, "get")
      });
    });
    var _index2 = require_b2b();
    Object.keys(_index2).forEach(function(key) {
      if (key === "default" || key === "__esModule") return;
      if (Object.prototype.hasOwnProperty.call(_exportNames, key)) return;
      if (key in exports && exports[key] === _index2[key]) return;
      Object.defineProperty(exports, key, {
        enumerable: true,
        get: /* @__PURE__ */ __name(function() {
          return _index2[key];
        }, "get")
      });
    });
    var _envs = _interopRequireWildcard(require_envs());
    exports.envs = _envs;
    var _errors = require_errors();
    Object.keys(_errors).forEach(function(key) {
      if (key === "default" || key === "__esModule") return;
      if (Object.prototype.hasOwnProperty.call(_exportNames, key)) return;
      if (key in exports && exports[key] === _errors[key]) return;
      Object.defineProperty(exports, key, {
        enumerable: true,
        get: /* @__PURE__ */ __name(function() {
          return _errors[key];
        }, "get")
      });
    });
    function _getRequireWildcardCache(nodeInterop) {
      if (typeof WeakMap !== "function") return null;
      var cacheBabelInterop = /* @__PURE__ */ new WeakMap();
      var cacheNodeInterop = /* @__PURE__ */ new WeakMap();
      return (_getRequireWildcardCache = /* @__PURE__ */ __name(function(nodeInterop2) {
        return nodeInterop2 ? cacheNodeInterop : cacheBabelInterop;
      }, "_getRequireWildcardCache"))(nodeInterop);
    }
    __name(_getRequireWildcardCache, "_getRequireWildcardCache");
    function _interopRequireWildcard(obj, nodeInterop) {
      if (!nodeInterop && obj && obj.__esModule) {
        return obj;
      }
      if (obj === null || typeof obj !== "object" && typeof obj !== "function") {
        return { default: obj };
      }
      var cache = _getRequireWildcardCache(nodeInterop);
      if (cache && cache.has(obj)) {
        return cache.get(obj);
      }
      var newObj = {};
      var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor;
      for (var key in obj) {
        if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) {
          var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null;
          if (desc && (desc.get || desc.set)) {
            Object.defineProperty(newObj, key, desc);
          } else {
            newObj[key] = obj[key];
          }
        }
      }
      newObj.default = obj;
      if (cache) {
        cache.set(obj, newObj);
      }
      return newObj;
    }
    __name(_interopRequireWildcard, "_interopRequireWildcard");
    var _default = exports.default = {
      Client: _client.Client,
      B2BClient: _client2.B2BClient
    };
  }
});

// .wrangler/tmp/bundle-eygzm5/middleware-loader.entry.ts
init_checked_fetch();
init_strip_cf_connecting_ip_header();
init_modules_watch_stub();

// .wrangler/tmp/bundle-eygzm5/middleware-insertion-facade.js
init_checked_fetch();
init_strip_cf_connecting_ip_header();
init_modules_watch_stub();

// src/index.ts
init_checked_fetch();
init_strip_cf_connecting_ip_header();
init_modules_watch_stub();
var import_stytch = __toESM(require_dist(), 1);
var ROLES = [{
  name: "newbie",
  value: "10"
}, {
  name: "novice",
  value: "20"
}, {
  name: "head baker",
  value: "30"
}, {
  name: "baker overlord",
  value: "40"
}];
function monkeyPatchStytchClientSettings(client) {
  client.fetchConfig.cache = void 0;
}
__name(monkeyPatchStytchClientSettings, "monkeyPatchStytchClientSettings");
var src_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const DEFAULT_HEADERS = {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": env.APP_DOMAIN,
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type,Authorization"
    };
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: DEFAULT_HEADERS
      });
    }
    const stytchClient = new import_stytch.default.B2BClient({
      project_id: env.STYTCH_PROJECT_ID || "",
      secret: env.STYTCH_SECRET || ""
    });
    monkeyPatchStytchClientSettings(stytchClient);
    if (url.pathname === "/api/leaderboard" && request.method === "GET") {
      try {
        const orgs = await stytchClient.organizations.search({
          limit: 10
        });
        const members = await stytchClient.organizations.members.search({
          limit: 200,
          organization_ids: orgs.organizations.map((org) => org.organization_id)
        });
        const leaderboard = members.members.map((member) => ({
          name: member.email_address,
          baked: member.trusted_metadata?.baked,
          organization: orgs.organizations.find((org) => org.organization_id === member.organization_id)?.organization_name
        })).sort((a, b) => b.baked - a.baked);
        return new Response(JSON.stringify({ leaderboard }), {
          headers: DEFAULT_HEADERS
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 401,
          headers: DEFAULT_HEADERS
        });
      }
    }
    if (url.pathname === "/api/validate" && request.method === "POST") {
      try {
        const body = await request.json();
        const { telemetryId } = body;
        const response = await stytchClient.fraud.fingerprint.lookup({
          telemetry_id: telemetryId
        });
        return new Response(JSON.stringify({ verdict: response.verdict }), {
          headers: DEFAULT_HEADERS
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 401,
          headers: DEFAULT_HEADERS
        });
      }
    }
    const sessionToken = request.headers.get("Authorization")?.split(" ")[1];
    if (!sessionToken) return new Response("Unauthorized", { status: 401, headers: DEFAULT_HEADERS });
    const session = await stytchClient.sessions.authenticate({ session_token: sessionToken });
    if (!session) return new Response("Unauthorized", { status: 401, headers: DEFAULT_HEADERS });
    if (url.pathname === "/api/feed" && request.method === "POST") {
      try {
        const body = await request.json();
        const { count } = body;
        const response = await stytchClient.organizations.members.update({
          organization_id: session.organization.organization_id,
          member_id: session.member.member_id,
          trusted_metadata: {
            baked: count + (session.member.trusted_metadata?.baked || 0)
          }
        });
        return new Response(JSON.stringify({ response }), {
          headers: DEFAULT_HEADERS
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 401,
          headers: DEFAULT_HEADERS
        });
      }
    }
    if (url.pathname === "/api/promote" && request.method === "GET") {
      try {
        const roles = ROLES.filter((role) => role.value <= session.member.trusted_metadata?.baked);
        await stytchClient.organizations.members.update({
          organization_id: session.organization.organization_id,
          member_id: session.member.member_id,
          roles: roles.map((role) => role.name)
        });
        return new Response(JSON.stringify({ role: roles.slice(-1)[0].name || "nobody" }), {
          headers: DEFAULT_HEADERS
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 401,
          headers: DEFAULT_HEADERS
        });
      }
    }
    return new Response("Not found", { status: 404, headers: DEFAULT_HEADERS });
  }
};

// node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
init_checked_fetch();
init_strip_cf_connecting_ip_header();
init_modules_watch_stub();
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
init_checked_fetch();
init_strip_cf_connecting_ip_header();
init_modules_watch_stub();
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-eygzm5/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = src_default;

// node_modules/wrangler/templates/middleware/common.ts
init_checked_fetch();
init_strip_cf_connecting_ip_header();
init_modules_watch_stub();
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-eygzm5/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=index.js.map
