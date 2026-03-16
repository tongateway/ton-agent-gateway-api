import { Address, beginCell, Cell, external, storeMessage } from '@ton/core';
import { sign } from '@ton/crypto';
import { bigintFromString } from '../utils/encoding';
import { Opcodes } from './opcodes';

export type SignedTransferInput = {
  vaultAddress: string;
  walletId: number;
  seqno: number;
  validUntil: number;
  to: string;
  amountNano: string;
  queryId?: string;
  payloadBoc?: string;
  secretKey: Buffer;
};

export type SignedTransferResult = {
  signedBodyBoc: string;
  externalMessageBoc: string;
  signatureHex: string;
  messageHashHex: string;
};

export function buildSignedTransferMessage(input: SignedTransferInput): SignedTransferResult {
  const vaultAddress = Address.parse(input.vaultAddress);
  const toAddress = Address.parse(input.to);
  const amount = bigintFromString(input.amountNano);
  const queryId = input.queryId ? bigintFromString(input.queryId) : 0n;

  const unsignedBodyBuilder = beginCell()
    .storeUint(Opcodes.signedExternal, 32)
    .storeUint(input.walletId, 32)
    .storeUint(input.validUntil, 32)
    .storeUint(input.seqno, 32)
    .storeUint(Opcodes.execTransfer, 32)
    .storeUint(queryId, 64)
    .storeCoins(amount)
    .storeAddress(toAddress)
    .storeBit(Boolean(input.payloadBoc));

  if (input.payloadBoc) {
    unsignedBodyBuilder.storeRef(Cell.fromBase64(input.payloadBoc));
  }

  const unsignedBody = unsignedBodyBuilder.endCell();
  const signature = sign(unsignedBody.hash(), input.secretKey);
  const signedBody = beginCell().storeSlice(unsignedBody.beginParse()).storeBuffer(signature).endCell();

  const externalMessage = external({
    to: vaultAddress,
    body: signedBody,
  });

  const externalMessageCell = beginCell().store(storeMessage(externalMessage)).endCell();

  return {
    signedBodyBoc: signedBody.toBoc().toString('base64'),
    externalMessageBoc: externalMessageCell.toBoc().toString('base64'),
    signatureHex: signature.toString('hex'),
    messageHashHex: unsignedBody.hash().toString('hex'),
  };
}

export function wrapSignedBodyIntoExternalMessage(vaultAddressRaw: string, signedBodyBoc: string): string {
  const vaultAddress = Address.parse(vaultAddressRaw);
  const signedBody = Cell.fromBase64(signedBodyBoc);

  const message = external({
    to: vaultAddress,
    body: signedBody,
  });

  return beginCell().store(storeMessage(message)).endCell().toBoc().toString('base64');
}
