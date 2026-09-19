export type ApiProblem = {
  status: number | undefined;
  code: string | undefined;
  retryAfterSeconds: number | undefined;
};

type ApiFailure = {
  status: number;
  body: unknown;
};

export function apiFailure(body: unknown, status: number): ApiFailure {
  return { body, status };
}

export function problem(error: unknown): ApiProblem {
  if (typeof error !== 'object' || error === null) {
    return { status: undefined, code: undefined, retryAfterSeconds: undefined };
  }
  const failure = error as Partial<ApiFailure>;
  const body = typeof failure.body === 'object' && failure.body !== null
    ? failure.body as Partial<ApiProblem>
    : {};
  return {
    status: failure.status ?? body.status,
    code: body.code,
    retryAfterSeconds: body.retryAfterSeconds,
  };
}
