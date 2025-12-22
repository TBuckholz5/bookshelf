package auth

type ctxKey struct {
	name string
}

var CtxKeyClaims = ctxKey{"jwtClaims"}
