import type { Confirmation, DeliveryState } from './api';
export const MAX_CARDS = 2000;
export function parseCards(input: string): string[] { return [...new Set(input.split(/[\s,，]+/).filter(Boolean))]; }
export function canDownload(state?: Confirmation | DeliveryState): boolean { return state?.canAccess === true && state.deliveryFormat === 'zip' && state.deliveryStatus === 'available'; }
// One browser cookie owns one selected order. Keep every card-authenticated
// action and its following state/download in the same serial operation.
export function createPublicRequests() {
  let sequence = 0;
  let active: number | undefined;
  return {
    begin() { if (active !== undefined) return null; active = ++sequence; return active; },
    current(token: number) { return active === token && sequence === token; },
    finish(token: number) { if (active !== token) return false; active = undefined; return sequence === token; },
    invalidate() { sequence++; active = undefined; },
  };
}
