/*
* Copyright (c) by CryptoLab inc.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/
#include "Ring2Utils.h"

#include "StringUtils.h"

//----------------------------------------------------------------------------------
//   APPROXIMATE EQUAL
//----------------------------------------------------------------------------------

bool Ring2Utils::approxEqualVectors(PolyVec& v1, PolyVec& v2, double epsilon, ZZ modqQ, long modQ, long degree) {
    if (v1.size() != v2.size()) return false;

	// context.decode(v1, msg.slots, msg.logp, msg.logq);


	bool flag = true;
    for (size_t i = 0; i < v1.size(); ++i) {
        long deg1 = deg(v1[i]);
        long deg2 = deg(v2[i]);
        long max_deg = max(deg1, deg2);
		// cout << "v1[i] = " << v1[i] << endl;
		// cout << "v2[i] = " << v2[i] << endl;
		Ring2Utils::subAndEqual(v1[i], v2[i], modqQ, degree);
		// cout << "v1[i] = " << v1[i] << endl;
		// cout << "v2[i] = " << v2[i] << endl;
		Ring2Utils::rightShiftAndEqual(v1[i], modQ, degree); 
		// cout << "diffx = " << v1[i] << endl;
		
        for (long j = 0; j <= max_deg; ++j) {
			double diff = fabs(to_double(v1[i][j]));
			// cout << "diff = " << diff << ", ";
            if (diff > epsilon) {
                cout << "Mismatch at poly " << i << ", term " << j << ": diff = " << diff << endl;
                return false;
            }

            if (diff != 0) {
                cout << "" << endl;
                flag = false;
            }			
        }
		// cout << ";" << endl;
    }
	
	if (flag) {
		cout << "These is no difference between the two polynomials." << endl;
	} else {
		cout << "These is a small error between the two polynomials." << endl;
	}

    return true;
}

// bool Ring2Utils::approxEqualVectors(PolyVec& v1, PolyVec& v2, double epsilon, ZZ modqQ, long modQ, long degree) {
//     if (v1.size() != v2.size()) return false;
// 	bool flag = true;
//     for (size_t i = 0; i < v1.size(); ++i) {
//         long deg1 = deg(v1[i]);
//         long deg2 = deg(v2[i]);
//         long max_deg = max(deg1, deg2);
// 		// cout << "v1[i] = " << v1[i] << endl;
// 		// cout << "v2[i] = " << v2[i] << endl;
// 		Ring2Utils::subAndEqual(v1[i], v2[i], modqQ, degree);
// 		// cout << "v1[i] = " << v1[i] << endl;
// 		// cout << "v2[i] = " << v2[i] << endl;
// 		Ring2Utils::rightShiftAndEqual(v1[i], modQ, degree); 
// 		// cout << "diffx = " << v1[i] << endl;
		
//         for (long j = 0; j <= max_deg; ++j) {
//             // ZZ coeff1 = (j <= deg1) ? coeff(v1[i], j) : ZZ(0);
//             // ZZ coeff2 = (j <= deg2) ? coeff(v2[i], j) : ZZ(0);
//             // double diff = fabs(to_double(coeff1 - coeff2));
// 			double diff = fabs(to_double(v1[i][j]));
// 			// cout << "diff = " << diff << ", ";
//             if (diff > epsilon) {
//                 cout << "Mismatch at poly " << i << ", term " << j << ": diff = " << diff << endl;
//                 return false;
//             }

//             if (diff != 0) {
//                 cout << "" << endl;
//                 flag = false;
//             }			
//         }
// 		// cout << ";" << endl;
//     }
	
// 	if (flag) {
// 		cout << "These is no difference between the two polynomials." << endl;
// 	} else {
// 		cout << "These is a small error between the two polynomials." << endl;
// 	}

//     return true;
// }

// bool Ring2Utils::approxEqualVectors(PolyVec& v1, PolyVec& v2, double epsilon) {
//     if (v1.size() != v2.size()) return false;

//     for (size_t i = 0; i < v1.size(); ++i) {
//         long deg1 = deg(v1[i]);
//         long deg2 = deg(v2[i]);
//         long max_deg = max(deg1, deg2);

//         for (long j = 0; j <= max_deg; ++j) {
//             ZZ coeff1 = (j <= deg1) ? coeff(v1[i], j) : ZZ(0);
//             ZZ coeff2 = (j <= deg2) ? coeff(v2[i], j) : ZZ(0);
//             double diff = fabs(to_double(coeff1 - coeff2));
//             if (diff > epsilon) {
//                 cout << "Mismatch at poly " << i << ", term " << j << ": diff = " << diff << endl;
//                 return false;
//             }
//         }
//     }
//     return true;
// }

//----------------------------------------------------------------------------------
//   MODULUS
//----------------------------------------------------------------------------------

void Ring2Utils::mod(ZZX& res, ZZX& p, ZZ& mod, const long degree) {
	res.SetLength(degree);
	for (long i = 0; i < degree; ++i) {
		rem(res.rep[i], p.rep[i], mod);
	}
}

void Ring2Utils::modAndEqual(ZZX& p, ZZ& mod, const long degree) {
	for (long i = 0; i < degree; ++i) {
		rem(p.rep[i], p.rep[i], mod);
	}
}


//----------------------------------------------------------------------------------
//   ADDITION & SUBSTRACTION
//----------------------------------------------------------------------------------


void Ring2Utils::add(ZZX& res, ZZX& p1, ZZX& p2, ZZ& mod, const long degree) {
	res.SetLength(degree);
	for (long i = 0; i < degree; ++i) {
		AddMod(res.rep[i], p1.rep[i], p2.rep[i], mod);
	}
}

ZZX Ring2Utils::add(ZZX& p1, ZZX& p2, ZZ& mod, const long degree) {
	ZZX res;
	add(res, p1, p2, mod, degree);
	return res;
}

void Ring2Utils::addAndEqual(ZZX& p1, ZZX& p2, ZZ& mod, const long degree) {
	for (long i = 0; i < degree; ++i) {
		// if (i < 4) {
		// 	cout << "operator p1 = " << p1[i] << endl;
		// 	cout << "operator p2 = " << p2[i] << endl;
		// }
		AddMod(p1.rep[i], p1.rep[i], p2.rep[i], mod);
		// if (i < 4) {
		// 	cout << "p1 + p2 = " << p1[i] << endl;
		// }
	}
}

void Ring2Utils::sub(ZZX& res, ZZX& p1, ZZX& p2, ZZ& mod, const long degree) {
	res.SetLength(degree);
	for (long i = 0; i < degree; ++i) {
		AddMod(res.rep[i], p1.rep[i], -p2.rep[i], mod);
	}
}

ZZX Ring2Utils::sub(ZZX& p1, ZZX& p2, ZZ& mod, const long degree) {
	ZZX res;
	sub(res, p1, p2, mod, degree);
	return res;
}

void Ring2Utils::subAndEqual(ZZX& p1, ZZX& p2, ZZ& mod, const long degree) {
	for (long i = 0; i < degree; ++i) {
		AddMod(p1.rep[i], p1.rep[i], -p2.rep[i], mod);
	}
}

void Ring2Utils::subAndEqual2(ZZX& p1, ZZX& p2, ZZ& mod, const long degree) {
	for (long i = 0; i < degree; ++i) {
		AddMod(p2.rep[i], p1.rep[i], -p2.rep[i], mod);
	}
}


//----------------------------------------------------------------------------------
//   MULTIPLICATION & SQUARING
//----------------------------------------------------------------------------------


void Ring2Utils::mult(ZZX& res, ZZX& p1, ZZX& p2, ZZ& mod, const long degree) {
	res.SetLength(degree);
	ZZX pp;
	mul(pp, p1, p2);
	pp.SetLength(2 * degree);
	for (long i = 0; i < degree; ++i) {
		rem(pp.rep[i], pp.rep[i], mod);
		rem(pp.rep[i + degree], pp.rep[i + degree], mod);
		SubMod(res.rep[i], pp.rep[i], pp.rep[i + degree], mod);
	}
}

ZZX Ring2Utils::mult(ZZX& p1, ZZX& p2, ZZ& mod, const long degree) {
	ZZX res;
	mult(res, p1, p2, mod, degree);
	return res;
}

void Ring2Utils::multAndEqual(ZZX& p1, ZZX& p2, ZZ& mod, const long degree) {
	ZZX pp;
	mul(pp, p1, p2);
	pp.SetLength(2 * degree);

	for (long i = 0; i < degree; ++i) {
		rem(pp.rep[i], pp.rep[i], mod);
		rem(pp.rep[i + degree], pp.rep[i + degree], mod);
		SubMod(p1.rep[i], pp.rep[i], pp.rep[i + degree], mod);
	}
}

void Ring2Utils::square(ZZX& res, ZZX& p, ZZ& mod, const long degree) {
	res.SetLength(degree);
	ZZX pp;
	sqr(pp, p);
	pp.SetLength(2 * degree);

	for (long i = 0; i < degree; ++i) {
		rem(pp.rep[i], pp.rep[i], mod);
		rem(pp.rep[i + degree], pp.rep[i + degree], mod);
		SubMod(res.rep[i], pp.rep[i], pp.rep[i + degree], mod);
	}
}

ZZX Ring2Utils::square(ZZX& p, ZZ& mod, const long degree) {
	ZZX res;
	square(res, p, mod, degree);
	return res;
}

void Ring2Utils::squareAndEqual(ZZX& p, ZZ& mod, const long degree) {
	ZZX pp;
	sqr(pp, p);
	pp.SetLength(2 * degree);

	for (long i = 0; i < degree; ++i) {
		rem(pp.rep[i], pp.rep[i], mod);
		rem(pp.rep[i + degree], pp.rep[i + degree], mod);
		SubMod(p.rep[i], pp.rep[i], pp.rep[i + degree], mod);
	}
}

void Ring2Utils::multByMonomial(ZZX& res, ZZX& p, const long monomialDeg, const long degree) {
	long shift = monomialDeg % (2 * degree);
	if(shift == 0) {
		res = p;
	} else {
		ZZX tmpx;
		tmpx.SetLength(degree);
		tmpx = (shift < degree) ? p : -p;
		shift %= degree;

		res.SetLength(degree);

		for (long i = 0; i < shift; ++i) {
			res.rep[i] = -tmpx.rep[degree - shift + i];
		}

		for (long i = shift; i < degree; ++i) {
			res.rep[i] = tmpx.rep[i - shift];
		}
	}
}

ZZX Ring2Utils::multByMonomial(ZZX& p, const long monomialDeg, const long degree) {
	ZZX res;
	multByMonomial(res, p, monomialDeg, degree);
	return res;
}

void Ring2Utils::multByMonomialAndEqual(ZZX& p, const long monomialDeg, const long degree) {
	long shift = monomialDeg % (2 * degree);
	if(shift == 0) {
		return;
	}
	ZZX tmpx;
	tmpx.SetLength(degree);
	tmpx = (shift < degree) ? p : -p;
	shift %= degree;
	for (long i = 0; i < shift; ++i) {
		p.rep[i] = -tmpx.rep[degree - shift + i];
	}

	for (long i = shift; i < degree; ++i) {
		p.rep[i] = tmpx.rep[i - shift];
	}
}

void Ring2Utils::multByConst(ZZX& res, ZZX& p, const ZZ& cnst, ZZ& mod, const long degree) {
	res.SetLength(degree);
	for (long i = 0; i < degree; ++i) {
		MulMod(res.rep[i], p.rep[i], cnst, mod);
	}
}

ZZX Ring2Utils::multByConst(ZZX& p, const ZZ& cnst, ZZ& mod, const long degree) {
	ZZX res;
	multByConst(res, p, cnst, mod, degree);
	return res;
}

void Ring2Utils::multByConstAndEqual(ZZX& p, const ZZ& cnst, ZZ& mod, const long degree) {
	for (long i = 0; i < degree; ++i) {
		MulMod(p.rep[i], p.rep[i], cnst, mod);
	}
}

void Ring2Utils::leftShift(ZZX& res, ZZX& p, const long bits, ZZ& mod, const long degree) {
	res.SetLength(degree);
	for (long i = 0; i < degree; ++i) {
		LeftShift(res.rep[i], p.rep[i], bits);
		rem(res.rep[i], res.rep[i], mod);
	}
}

void Ring2Utils::leftShiftAndEqual(ZZX& p, const long bits, ZZ& mod, const long degree) {
	for (long i = 0; i < degree; ++i) {
		LeftShift(p.rep[i], p.rep[i], bits);
		rem(p.rep[i], p.rep[i], mod);
	}
}

void Ring2Utils::doubleAndEqual(ZZX& p, ZZ& mod, const long degree) {
	for (long i = 0; i < degree; ++i) {
		LeftShift(p.rep[i], p.rep[i], 1);
		rem(p.rep[i], p.rep[i], mod);
	}
}

void Ring2Utils::rightShift(ZZX& res, ZZX& p, const long bits, const long degree) {
	res.SetLength(degree);
	for (long i = 0; i < degree; ++i) {
		// cout << "i = " << i << endl;
		RightShift(res.rep[i], p.rep[i], bits);
	}
}

void Ring2Utils::rightShiftAndEqual(ZZX& p, const long bits, const long degree) {
	// cout << "pi = [" << p[0] << ", " << p[1] << ", "<< p[1] << ", "<< p[3] << "]"<< endl;
	for (long i = 0; i < degree; ++i) {
		RightShift(p.rep[i], p.rep[i], bits);
	}
	// cout << "po = [" << p[0] << ", " << p[1] << ", "<< p[1] << ", "<< p[3] << "]"<< endl;
}


//----------------------------------------------------------------------------------
//   CONJUGATION ROTATION AND OTHER
//----------------------------------------------------------------------------------


void Ring2Utils::conjugate(ZZX& res, ZZX& p, const long degree) {
	res.SetLength(degree);
	res.rep[0] = p.rep[0];
	for (long i = 1; i < degree; ++i) {
		res.rep[i] = -p.rep[degree - i];
	}
}

void Ring2Utils::conjugateAndEqual(ZZX& p, const long degree) {
	for (long i = 0; i < degree / 2; ++i) {
		ZZ tmp = p.rep[i];
		p.rep[i] = p.rep[degree - i];
		p.rep[degree - i] = tmp;
	}
	p.rep[degree / 2] = -p.rep[degree / 2];
}

void Ring2Utils::inpower(ZZX& res, ZZX& p, const long pow, ZZ& mod, const long degree) {
	res.kill();
	res.SetLength(degree);
	for (long i = 0; i < degree; ++i) {
		long ipow = i * pow;
		long shift = ipow % (2 * degree);
		if(shift < degree) {
			AddMod(res.rep[shift % degree], res.rep[shift % degree], p.rep[i], mod);
		} else {
			AddMod(res.rep[shift % degree], res.rep[shift % degree], -p.rep[i], mod);
		}
	}
}

ZZX Ring2Utils::inpower(ZZX& p, const long pow, ZZ& mod, const long degree) {
	ZZX res;
	inpower(res, p, pow, mod, degree);
	return res;
}
