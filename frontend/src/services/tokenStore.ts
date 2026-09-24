// The access token lives only in this variable: not in localStorage or sessionStorage, so
// a cross-site-scripting bug cannot read it back later. A page reload clears it, and the
// httpOnly refresh cookie is used to get a new one.
let accessToken: string | null = null;

export const tokenStore = {
  get: (): string | null => accessToken,
  set: (token: string | null): void => {
    accessToken = token;
  },
};
