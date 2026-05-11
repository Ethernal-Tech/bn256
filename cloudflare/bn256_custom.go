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
