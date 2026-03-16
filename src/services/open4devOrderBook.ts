import { Address, beginCell, Cell } from '@ton/core';
import { bigintFromString } from '../utils/encoding';
import { buildSignedTransferMessage, SignedTransferResult } from './tonMessage';

const OP_CODE_TON_TRANSFER = 0xcbcd047e;
const OP_CODE_JETTON_TRANSFER = 0x0f8a7ea5;

function assertUintBits(field: string, value: number, bits: number): void {
  const max = 2 ** bits;
  if (!Number.isInteger(value) || value < 0 || value >= max) {
    throw new Error(`${field} must be uint${bits} (0..${max - 1})`);
  }
}

function resolveCreatedAt(input?: number): number {
  const now = Math.floor(Date.now() / 1000);
  return input ?? now;
}

type BaseEnvelope = {
  vaultAddress: string;
  walletId: number;
  seqno: number;
  validUntil: number;
  queryId?: string;
  secretKey: Buffer;
};

export type CreateTonOrderPayloadInput = BaseEnvelope & {
  dexVaultTonAddress: string;
  sendValueNano: string;
  orderAmountNano: string;
  priceRateNano: string;
  slippage: number;
  toJettonMinter: string;
  providerFeeAddress: string;
  feeNum: number;
  feeDenom: number;
  matcherFeeNum: number;
  matcherFeeDenom: number;
  oppositeVaultAddress: string;
  createdAt?: number;
};

export type CreateJettonOrderPayloadInput = BaseEnvelope & {
  jettonWalletAddress: string;
  attachedTonAmountNano: string;
  jettonAmountNano: string;
  dexVaultAddress: string;
  ownerAddress: string;
  forwardTonAmountNano: string;
  priceRateNano: string;
  slippage: number;
  toJettonMinter?: string;
  providerFeeAddress: string;
  feeNum: number;
  feeDenom: number;
  matcherFeeNum: number;
  matcherFeeDenom: number;
  oppositeVaultAddress: string;
  customPayloadBoc?: string;
  createdAt?: number;
};

export type CreateOrderResult = SignedTransferResult & {
  orderPayloadBoc: string;
};

// --- Payload-only builders (for safe/deferred mode — no signing) ---

export type TonOrderPayloadInput = {
  dexVaultTonAddress: string;
  sendValueNano: string;
  orderAmountNano: string;
  priceRateNano: string;
  slippage: number;
  toJettonMinter: string;
  providerFeeAddress: string;
  feeNum: number;
  feeDenom: number;
  matcherFeeNum: number;
  matcherFeeDenom: number;
  oppositeVaultAddress: string;
  createdAt?: number;
};

export type JettonOrderPayloadInput = {
  jettonWalletAddress: string;
  attachedTonAmountNano: string;
  jettonAmountNano: string;
  dexVaultAddress: string;
  ownerAddress: string;
  forwardTonAmountNano: string;
  priceRateNano: string;
  slippage: number;
  toJettonMinter?: string;
  providerFeeAddress: string;
  feeNum: number;
  feeDenom: number;
  matcherFeeNum: number;
  matcherFeeDenom: number;
  oppositeVaultAddress: string;
  customPayloadBoc?: string;
  createdAt?: number;
  queryId?: string;
};

export type SafeOrderResult = {
  to: string;
  amountNano: string;
  payloadBoc: string;
};

export function buildTonOrderPayload(input: TonOrderPayloadInput): SafeOrderResult {
  assertUintBits('slippage', input.slippage, 30);
  assertUintBits('feeNum', input.feeNum, 14);
  assertUintBits('feeDenom', input.feeDenom, 14);
  assertUintBits('matcherFeeNum', input.matcherFeeNum, 14);
  assertUintBits('matcherFeeDenom', input.matcherFeeDenom, 14);

  const feeInfoCell = beginCell()
    .storeAddress(Address.parse(input.providerFeeAddress))
    .storeUint(input.feeNum, 14)
    .storeUint(input.feeDenom, 14)
    .storeUint(input.matcherFeeNum, 14)
    .storeUint(input.matcherFeeDenom, 14)
    .endCell();

  const orderPayload = beginCell()
    .storeUint(OP_CODE_TON_TRANSFER, 32)
    .storeCoins(bigintFromString(input.orderAmountNano))
    .storeRef(beginCell().storeAddress(Address.parse(input.toJettonMinter)).endCell())
    .storeCoins(bigintFromString(input.priceRateNano))
    .storeUint(input.slippage, 30)
    .storeRef(feeInfoCell)
    .storeUint(resolveCreatedAt(input.createdAt), 32)
    .storeAddress(Address.parse(input.oppositeVaultAddress))
    .endCell();

  return {
    to: input.dexVaultTonAddress,
    amountNano: input.sendValueNano,
    payloadBoc: orderPayload.toBoc().toString('base64'),
  };
}

export function buildJettonOrderPayload(input: JettonOrderPayloadInput): SafeOrderResult {
  assertUintBits('slippage', input.slippage, 30);
  assertUintBits('feeNum', input.feeNum, 14);
  assertUintBits('feeDenom', input.feeDenom, 14);
  assertUintBits('matcherFeeNum', input.matcherFeeNum, 14);
  assertUintBits('matcherFeeDenom', input.matcherFeeDenom, 14);

  const feeInfoCell = beginCell()
    .storeAddress(Address.parse(input.providerFeeAddress))
    .storeUint(input.feeNum, 14)
    .storeUint(input.feeDenom, 14)
    .storeUint(input.matcherFeeNum, 14)
    .storeUint(input.matcherFeeDenom, 14)
    .endCell();

  const forwardPayload = beginCell()
    .storeCoins(bigintFromString(input.priceRateNano))
    .storeMaybeRef(input.toJettonMinter ? beginCell().storeAddress(Address.parse(input.toJettonMinter)).endCell() : null)
    .storeUint(input.slippage, 30)
    .storeRef(feeInfoCell)
    .storeUint(resolveCreatedAt(input.createdAt), 32)
    .storeAddress(Address.parse(input.oppositeVaultAddress))
    .endCell();

  const jettonTransfer = beginCell()
    .storeUint(OP_CODE_JETTON_TRANSFER, 32)
    .storeUint(input.queryId ? bigintFromString(input.queryId) : 0n, 64)
    .storeCoins(bigintFromString(input.jettonAmountNano))
    .storeAddress(Address.parse(input.dexVaultAddress))
    .storeAddress(Address.parse(input.ownerAddress))
    .storeMaybeRef(input.customPayloadBoc ? Cell.fromBase64(input.customPayloadBoc) : null)
    .storeCoins(bigintFromString(input.forwardTonAmountNano))
    .storeBit(true)
    .storeRef(forwardPayload)
    .endCell();

  return {
    to: input.jettonWalletAddress,
    amountNano: input.attachedTonAmountNano,
    payloadBoc: jettonTransfer.toBoc().toString('base64'),
  };
}

// --- Full signed builders (for immediate execution — requires private key) ---

export function buildCreateTonOrderMessage(input: CreateTonOrderPayloadInput): CreateOrderResult {
  assertUintBits('slippage', input.slippage, 30);
  assertUintBits('feeNum', input.feeNum, 14);
  assertUintBits('feeDenom', input.feeDenom, 14);
  assertUintBits('matcherFeeNum', input.matcherFeeNum, 14);
  assertUintBits('matcherFeeDenom', input.matcherFeeDenom, 14);

  const feeInfoCell = beginCell()
    .storeAddress(Address.parse(input.providerFeeAddress))
    .storeUint(input.feeNum, 14)
    .storeUint(input.feeDenom, 14)
    .storeUint(input.matcherFeeNum, 14)
    .storeUint(input.matcherFeeDenom, 14)
    .endCell();

  const orderPayload = beginCell()
    .storeUint(OP_CODE_TON_TRANSFER, 32)
    .storeCoins(bigintFromString(input.orderAmountNano))
    .storeRef(beginCell().storeAddress(Address.parse(input.toJettonMinter)).endCell())
    .storeCoins(bigintFromString(input.priceRateNano))
    .storeUint(input.slippage, 30)
    .storeRef(feeInfoCell)
    .storeUint(resolveCreatedAt(input.createdAt), 32)
    .storeAddress(Address.parse(input.oppositeVaultAddress))
    .endCell();

  const signed = buildSignedTransferMessage({
    vaultAddress: input.vaultAddress,
    walletId: input.walletId,
    seqno: input.seqno,
    validUntil: input.validUntil,
    to: input.dexVaultTonAddress,
    amountNano: input.sendValueNano,
    queryId: input.queryId,
    payloadBoc: orderPayload.toBoc().toString('base64'),
    secretKey: input.secretKey,
  });

  return {
    ...signed,
    orderPayloadBoc: orderPayload.toBoc().toString('base64'),
  };
}

export function buildCreateJettonOrderMessage(input: CreateJettonOrderPayloadInput): CreateOrderResult {
  assertUintBits('slippage', input.slippage, 30);
  assertUintBits('feeNum', input.feeNum, 14);
  assertUintBits('feeDenom', input.feeDenom, 14);
  assertUintBits('matcherFeeNum', input.matcherFeeNum, 14);
  assertUintBits('matcherFeeDenom', input.matcherFeeDenom, 14);

  const feeInfoCell = beginCell()
    .storeAddress(Address.parse(input.providerFeeAddress))
    .storeUint(input.feeNum, 14)
    .storeUint(input.feeDenom, 14)
    .storeUint(input.matcherFeeNum, 14)
    .storeUint(input.matcherFeeDenom, 14)
    .endCell();

  const forwardPayload = beginCell()
    .storeCoins(bigintFromString(input.priceRateNano))
    .storeMaybeRef(input.toJettonMinter ? beginCell().storeAddress(Address.parse(input.toJettonMinter)).endCell() : null)
    .storeUint(input.slippage, 30)
    .storeRef(feeInfoCell)
    .storeUint(resolveCreatedAt(input.createdAt), 32)
    .storeAddress(Address.parse(input.oppositeVaultAddress))
    .endCell();

  const jettonTransfer = beginCell()
    .storeUint(OP_CODE_JETTON_TRANSFER, 32)
    .storeUint(input.queryId ? bigintFromString(input.queryId) : 0n, 64)
    .storeCoins(bigintFromString(input.jettonAmountNano))
    .storeAddress(Address.parse(input.dexVaultAddress))
    .storeAddress(Address.parse(input.ownerAddress))
    .storeMaybeRef(input.customPayloadBoc ? Cell.fromBase64(input.customPayloadBoc) : null)
    .storeCoins(bigintFromString(input.forwardTonAmountNano))
    .storeBit(true)
    .storeRef(forwardPayload)
    .endCell();

  const signed = buildSignedTransferMessage({
    vaultAddress: input.vaultAddress,
    walletId: input.walletId,
    seqno: input.seqno,
    validUntil: input.validUntil,
    to: input.jettonWalletAddress,
    amountNano: input.attachedTonAmountNano,
    queryId: input.queryId,
    payloadBoc: jettonTransfer.toBoc().toString('base64'),
    secretKey: input.secretKey,
  });

  return {
    ...signed,
    orderPayloadBoc: jettonTransfer.toBoc().toString('base64'),
  };
}
