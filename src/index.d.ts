/// <reference types="node" />
export declare function compress(input: Buffer): Buffer;
export declare function decompress(input: Buffer): Buffer;
export declare function fromVPub(vpriv: String): Buffer;
export declare function fromPrivateKey(vpriv: Buffer): Buffer;
export declare function toVPub(input: Buffer): String;

export declare class InvalidStartError extends Error {
  code: String
}

export declare class InvalidLength extends Error {
  code: String
}
