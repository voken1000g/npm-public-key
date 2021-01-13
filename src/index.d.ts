/// <reference types="node" />
export declare function compress(input: Buffer): Buffer;
export declare function decompress(input: Buffer): Buffer;

export declare function isCompressed(input: Buffer): Boolean;
export declare function assertCompressed(input: Buffer): Buffer;

export declare function isUncompressed(input: Buffer): Boolean;
export declare function assertUncompressed(input: Buffer): Buffer;

export declare function fromHex(vpriv: String): Buffer;
export declare function fromVPub(vpriv: String): Buffer;
export declare function fromPrivateKey(vpriv: Buffer): Buffer;
export declare function toVPub(input: Buffer): String;

export declare class InvalidStartError extends Error {
  code: String
}

export declare class InvalidLengthError extends Error {
  code: String
}

export declare class InvalidPublicKeyError extends Error {
  code: String
}

export declare class InvalidUncompressedPublicKey extends Error {
  code: String
}
