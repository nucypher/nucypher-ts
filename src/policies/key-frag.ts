import {
  Capsule,
  encrypt,
  KeyFrag,
  PublicKey,
  Signature,
  Signer,
  VerifiedKeyFrag,
} from 'umbral-pre';

import { CAPSULE_LENGTH } from '../crypto/constants';
import {
  bytesEqual,
  decodeVariableLengthMessage,
  encodeVariableLengthMessage,
  numberToBytes,
  split,
} from '../utils';
import { Versioned, VersionedParser, VersionTuple } from '../versioning';

import { HRAC } from './hrac';

export class EncryptedKeyFrag {
  constructor(
    private readonly capsule: Capsule,
    private readonly ciphertext: Uint8Array
  ) {}

  public static author(
    recipientKey: PublicKey,
    authorizedKeyFrag: AuthorizedKeyFrag
  ): EncryptedKeyFrag {
    const { capsule, ciphertext } = encrypt(
      recipientKey,
      authorizedKeyFrag.toBytes()
    );
    return new EncryptedKeyFrag(capsule, ciphertext);
  }

  public toBytes(): Uint8Array {
    return new Uint8Array([
      ...this.capsule.toBytes(),
      ...encodeVariableLengthMessage(this.ciphertext),
    ]);
  }

  public static take(bytes: Uint8Array): {
    readonly encryptedKeyFrag: EncryptedKeyFrag;
    readonly remainder: Uint8Array;
  } {
    const [capsuleBytes, remainder1] = split(bytes, CAPSULE_LENGTH);
    const [ciphertext, remainder] = decodeVariableLengthMessage(remainder1);
    const encryptedKeyFrag = new EncryptedKeyFrag(
      Capsule.fromBytes(capsuleBytes),
      ciphertext
    );
    return { encryptedKeyFrag, remainder };
  }

  public equals(other: EncryptedKeyFrag): boolean {
    return (
      bytesEqual(this.capsule.toBytes(), other.capsule.toBytes()) &&
      bytesEqual(this.ciphertext, other.ciphertext)
    );
  }
}

export class AuthorizedKeyFrag implements Versioned {
  private static readonly BRAND = 'AKFr';
  private static readonly VERSION: VersionTuple = [1, 0];
  private static readonly EXPIRATION_SIZE_BYTES = 4;

  constructor(
    private readonly signature: Signature,
    private readonly kFrag: KeyFrag,
    private readonly expiration: number
  ) {}

  public static constructByPublisher(
    publisherSigner: Signer,
    hrac: HRAC,
    verifiedKFrag: VerifiedKeyFrag,
    expiration: Date
  ): AuthorizedKeyFrag {
    const kFrag = KeyFrag.fromBytes(verifiedKFrag.toBytes());
    const expirationEpoch = Math.floor(expiration.getTime() / 1000);
    const signature = publisherSigner.sign(
      new Uint8Array([
        ...hrac.toBytes(),
        ...kFrag.toBytes(),
        ...numberToBytes(
          expirationEpoch,
          AuthorizedKeyFrag.EXPIRATION_SIZE_BYTES
        ),
      ])
    );
    return new AuthorizedKeyFrag(signature, kFrag, expirationEpoch);
  }

  private get header(): Uint8Array {
    return VersionedParser.encodeHeader(
      AuthorizedKeyFrag.BRAND,
      AuthorizedKeyFrag.VERSION
    );
  }

  public toBytes(): Uint8Array {
    return new Uint8Array([
      ...this.header,
      ...this.signature.toBytes(),
      ...this.kFrag.toBytes(),
      ...numberToBytes(
        this.expiration,
        AuthorizedKeyFrag.EXPIRATION_SIZE_BYTES
      ),
    ]);
  }
}
