package bn256

func (e *G2) InCorrectSubgroup() bool {
	return new(G2).ScalarMult(e, Order).IsInfinity()
}

func (e *G2) IsInfinity() bool {
	return e.p.IsInfinity()
}

func (e *G1) InCorrectSubgroup() bool {
	return new(G1).ScalarMult(e, Order).IsInfinity()
}

func (e *G1) IsInfinity() bool {
	return e.p.IsInfinity()
}

// PairingCheck calculates the Optimal Ate pairing for a set of points.
func PairingCheck(a []*G1, b []*G2) bool {
	acc := new(gfP12).SetOne()

	for i := 0; i < len(a); i++ {
		if a[i].p.IsInfinity() || b[i].p.IsInfinity() {
			continue
		}

		acc.Mul(acc, miller(b[i].p, a[i].p))
	}

	return finalExponentiation(acc).IsOne()
}
