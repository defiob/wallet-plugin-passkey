export interface LookupAccount {
  account: string
  permission: string
}

export interface LookupResponse {
  accounts: LookupAccount[]
  pubkey: string
  recursive: boolean
}

/**
 * Hit the reverse-lookup endpoint to find which (account, permission)s
 * have the given PUB_WA_… registered in their authority.
 *
 * `baseUrl` is a prefix the pubkey gets appended to directly (with a
 * single separating slash if missing).
 *
 * 404 is treated as "not found" → empty account list, no throw, so
 * callers can probe multiple candidates without error-handling each.
 * Other non-OK responses throw with the HTTP status so the user gets a
 * clearer message than a silent empty result.
 */
export async function reverseLookup(
  baseUrl: string,
  pubkey: string,
): Promise<LookupResponse> {
  const url = baseUrl.endsWith('/') ? baseUrl + pubkey : baseUrl + '/' + pubkey
  let res: Response
  try {
    res = await fetch(url, { method: 'GET' })
  } catch (err) {
    throw new Error(`Reverse-lookup network error: ${(err as Error).message}`)
  }
  if (res.status === 404) {
    return { accounts: [], pubkey, recursive: false }
  }
  if (!res.ok) {
    throw new Error(`Reverse-lookup failed with HTTP ${res.status}`)
  }
  const data = (await res.json()) as LookupResponse
  if (!Array.isArray(data.accounts)) data.accounts = []
  return data
}
