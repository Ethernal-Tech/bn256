package bn256

func (e *G2) InCorrectSubgroup() bool {
	tmp := new(G2)
	tmp = tmp.ScalarMult(e, Order)
	return tmp.IsInfinity()
}

func (e *G2) IsInfinity() bool {
	return e.p.IsInfinity()
}

func (e *G1) InCorrectSubgroup() bool {
	tmp := new(G1)
	tmp = tmp.ScalarMult(e, Order)
	return tmp.IsInfinity()
}

func (e *G1) IsInfinity() bool {
	return e.p.IsInfinity()
}
