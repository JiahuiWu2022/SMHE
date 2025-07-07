/*
* Copyright (c) by Pengcheng Lab. and CryptoLab inc.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/
#include "MFScheme.h"
#include "TimeUtils.h"

#include <NTL/BasicThreadPool.h>
#include <NTL/RR.h>
#include <NTL/ZZ.h>
#include <NTL/ZZX.h>

#include "EvaluatorUtils.h"
#include "NumUtils.h"
#include "Ring2Utils.h"
#include "StringUtils.h"

//-----------------------------------------

MFScheme::MFScheme(Context& context) : context(context) {
}

MFScheme::MFScheme(MFSecretKey& mfSecretKey, Context& context) : context(context) {
	addMFEncKey(mfSecretKey);
	addMFMultKey(mfSecretKey);
};

MFScheme::MFScheme(MFSecretKey& mfSecretKey, ZZX& ax, Context& context) : context(context) {
	addMFEncKey(mfSecretKey, ax);
	addMFMultKey(mfSecretKey);
};


// //----------------------------------------------------------------------------------
// //   KEYS GENERATION
// //----------------------------------------------------------------------------------


void MFScheme::addMFEncKey(MFSecretKey& mfSecretKey) {
	ZZX ax, ex, bx;

	NumUtils::sampleUniform2(ax, context.N, context.logQQ);

	NumUtils::sampleGauss(ex, context.N, context.sigma);	

	Ring2Utils::mult(bx, mfSecretKey.sx, ax, context.QQ, context.N);

	Ring2Utils::sub(bx, ex, bx, context.QQ, context.N);

	mfKeyMap.insert(pair<long, MFKey>(ENCRYPTION, MFKey(ax, bx)));
}

void MFScheme::addMFEncKey(MFSecretKey& mfSecretKey, ZZX ax) {
	ZZX ex, bx;

	NumUtils::sampleGauss(ex, context.N, context.sigma);	

	Ring2Utils::mult(bx, mfSecretKey.sx, ax, context.QQ, context.N);

	Ring2Utils::sub(bx, ex, bx, context.QQ, context.N);

	mfKeyMap.insert(pair<long, MFKey>(ENCRYPTION, MFKey(ax, bx)));
}


void MFScheme::addMFMultKey(MFSecretKey& mfSecretKey) {
	ZZX ex, ax, bx, sxsx;

	Ring2Utils::mult(sxsx, mfSecretKey.sx, mfSecretKey.sx, context.Q, context.N);
	Ring2Utils::leftShiftAndEqual(sxsx, context.logQ, context.QQ, context.N);
	NumUtils::sampleUniform2(ax, context.N, context.logQQ);
	NumUtils::sampleGauss(ex, context.N, context.sigma);
	Ring2Utils::addAndEqual(ex, sxsx, context.QQ, context.N);
	Ring2Utils::mult(bx, mfSecretKey.sx, ax, context.QQ, context.N);
	Ring2Utils::sub(bx, ex, bx, context.QQ, context.N);

	mfKeyMap.insert(pair<long, MFKey>(MULTIPLICATION, MFKey(ax, bx)));
}

void MFScheme::addConjKey(MFSecretKey& secretKey) {
	ZZX ex, ax, bx, sxconj;

	Ring2Utils::conjugate(sxconj, secretKey.sx, context.N);
	Ring2Utils::leftShiftAndEqual(sxconj, context.logQ, context.QQ, context.N);
	NumUtils::sampleUniform2(ax, context.N, context.logQQ);
	NumUtils::sampleGauss(ex, context.N, context.sigma);
	Ring2Utils::addAndEqual(ex, sxconj, context.QQ, context.N);
	Ring2Utils::mult(bx, secretKey.sx, ax, context.QQ, context.N);
	Ring2Utils::sub(bx, ex, bx, context.QQ, context.N);

	mfKeyMap.insert(pair<long, MFKey>(CONJUGATION, MFKey(ax, bx)));
}

void MFScheme::addLeftRotKey(MFSecretKey& secretKey, long rot) {
	ZZX ex, ax, bx, sxrot;

	Ring2Utils::inpower(sxrot, secretKey.sx, context.rotGroup[rot], context.Q, context.N);
	Ring2Utils::leftShiftAndEqual(sxrot, context.logQ, context.QQ, context.N);
	NumUtils::sampleUniform2(ax, context.N, context.logQQ);
	NumUtils::sampleGauss(ex, context.N, context.sigma);
	Ring2Utils::addAndEqual(ex, sxrot, context.QQ, context.N);
	Ring2Utils::mult(bx, secretKey.sx, ax, context.QQ, context.N);
	Ring2Utils::sub(bx, ex, bx, context.QQ, context.N);

	leftRotKeyMap.insert(pair<long, MFKey>(rot, MFKey(ax, bx)));
}

void MFScheme::addLeftRotKeys(MFSecretKey& secretKey) {
	for (long i = 0; i < context.logNh; ++i) {
		long idx = 1 << i;
		if(leftRotKeyMap.find(idx) == leftRotKeyMap.end()) {
			addLeftRotKey(secretKey, idx);
		}
	}
}

void MFScheme::addRightRotKeys(MFSecretKey& secretKey) {
	for (long i = 0; i < context.logNh; ++i) {
		long idx = context.N/2 - (1 << i);
		if(leftRotKeyMap.find(idx) == leftRotKeyMap.end()) {
			addLeftRotKey(secretKey, idx);
		}
	}
}

void MFScheme::addSortKeys(MFSecretKey& secretKey, long size) {
	for (long i = 1; i < size; ++i) {
		if(leftRotKeyMap.find(i) == leftRotKeyMap.end()) {
			addLeftRotKey(secretKey, i);
		}
	}
}


//----------------------------------------------------------------------------------
//   ENCODING & DECODING
//----------------------------------------------------------------------------------


MFPlaintext MFScheme::encode(double* vals, long slots, long logp, long logq) {
	ZZX mx = context.encode(vals, slots, logp + context.logQ);
	return MFPlaintext(mx, logp, logq, slots, false);
}

MFPlaintext MFScheme::encode(complex<double>* vals, long slots, long logp, long logq) {
	/*
	函数功能：将slots个复数（vals中的slots个元素）编码为N维整数mx，mx看为N维多项式，其中2slots个维度值不为0，其他值为0
	具体计算：context.encode(vals, slots, logp + context.logQ)：mx = PIInv(EMBInv(vals) * 2^(logp + context.logQ)) = PIInv(EMBInv(vals)*p*Q)
	PIInv为原论文中的复数实部和虚部划分、存储函数
	*/
	ZZX mx = context.encode(vals, slots, logp + context.logQ); 
	return MFPlaintext(mx, logp, logq, slots, true);
}

complex<double>* MFScheme::decode(MFPlaintext& msg) {
	return context.decode(msg.mx, msg.slots, msg.logp, msg.logq);
}

MFPlaintext MFScheme::encodeSingle(complex<double> val, long logp, long logq) {
	ZZX mx = context.encodeSingle(val, logp + context.logQ); 
	return MFPlaintext(mx, logp, logq, 1, true);
}

MFPlaintext MFScheme::encodeSingle(double val, long logp, long logq) {
	ZZX mx = context.encodeSingle(val, logp + context.logQ);
	return MFPlaintext(mx, logp, logq, 1, false);
}

complex<double> MFScheme::decodeSingle(MFPlaintext& msg) {
	return context.decodeSingle(msg.mx, msg.logp, msg.logq, msg.isComplex);
}


//----------------------------------------------------------------------------------
//   ENCRYPTION & DECRYPTION
//----------------------------------------------------------------------------------


MFCiphertext MFScheme::encryptMsg(MFPlaintext& msg) {
	ZZX ax, bx, vx, ex;
	MFKey key = mfKeyMap.at(ENCRYPTION);
	ZZ qQ = context.qpowvec[msg.logq + context.logQ];

	NumUtils::sampleZO(vx, context.N);
	Ring2Utils::mult(ax, vx, key.ax, qQ, context.N);
	NumUtils::sampleGauss(ex, context.N, context.sigma);
	Ring2Utils::addAndEqual(ax, ex, qQ, context.N);

	Ring2Utils::mult(bx, vx, key.bx, qQ, context.N);
	NumUtils::sampleGauss(ex, context.N, context.sigma);
	Ring2Utils::addAndEqual(bx, ex, qQ, context.N);

	Ring2Utils::addAndEqual(bx, msg.mx, qQ, context.N);

	Ring2Utils::rightShiftAndEqual(ax, context.logQ, context.N); // ax >> Q-bits, i.e., ax = floor(ax/Q)
	Ring2Utils::rightShiftAndEqual(bx, context.logQ, context.N);

	return MFCiphertext(ax, bx, msg.logp, msg.logq, msg.slots, msg.isComplex);
}

MFCiphertext MFScheme::maskEncryptMsg(MFPlaintext& msg, ZZX& vx) { //Encrypt msg.mx, which is 0, i.e., msg.mx=0
	ZZX ax, bx, ex;
	MFKey key = mfKeyMap.at(ENCRYPTION);
	ZZ qQ = context.qpowvec[msg.logq + context.logQ];

	// NumUtils::sampleZO(vx, context.N);
	Ring2Utils::mult(ax, vx, key.ax, qQ, context.N);
	NumUtils::sampleGauss(ex, context.N, context.sigma);
	Ring2Utils::addAndEqual(ax, ex, qQ, context.N);

	Ring2Utils::mult(bx, vx, key.bx, qQ, context.N);
	NumUtils::sampleGauss(ex, context.N, context.sigma);
	Ring2Utils::addAndEqual(bx, ex, qQ, context.N);

	return MFCiphertext(ax, bx, msg.logp, msg.logq, msg.slots, msg.isComplex, msg.party_id);
}



/**
 * @brief For an RLWE secret s\in R and a message mx\in R, we call U=(u0,u1)\in R_Q^{\tau\times 2} 
 * a gadget encryption of mx under s if u0+s\cdot u1=mx\cdot g (mod Q).
 * 
 * @param msg message
 * @param mfSecretKey secret key
 * @param g gadget vector
 * @param context 
 * @return MFCiphertext 
 */
MFCiphertext MFScheme::gadgetEncryptMsg(MFPlaintext& msg, MFSecretKey& mfSecretKey, ZZX& logg, Context& context) {
    GadgetEncryption U;

    size_t tau = deg(logg) + 1;

    U.u0.resize(tau);
    U.u1.resize(tau);

	ZZ qQ = context.qpowvec[msg.logq + context.logQ];

	ZZX g; g.SetLength(tau);
    for (int i = 0; i < tau; i++) {
        g[i] = power(ZZ(2), conv<long>(logg[i])); 
    }

	ZZX gx, ex, rx, tmp1, tmp2;
	vector<ZZX> vex(tau);
	ZZX recovered_mx;
    for (int i = 0; i < tau; i++) {
        NumUtils::sampleGauss(ex, context.N, context.sigma);
		NumUtils::sampleZO(rx, context.N);
		vex[i] = ex;

		for (int j = 0; j < deg(msg.mx) + 1; j++) {
			if (j == 0) {
				SetCoeff(gx, j, g[i]);
			} else {
				SetCoeff(gx, j, 0);
			}			
		}

		Ring2Utils::mult(tmp1, mfSecretKey.sx, rx, qQ, context.N);		
		Ring2Utils::sub(tmp1, ex, tmp1, qQ, context.N); // ex - s*rx
		Ring2Utils::mult(tmp2, msg.mx, gx, qQ, context.N);
		Ring2Utils::add(U.u0[i], tmp2, tmp1, qQ, context.N); // mx*gx + (ex - sx*rx)

        U.u1[i] = rx;
	}

    return MFCiphertext(U.u1, U.u0, msg.logp, msg.logq, msg.slots, msg.isComplex, msg.party_id);
}

void MFScheme::verifyGadgetEncryption(MFPlaintext& msg, MFCiphertext& Gamma, MFSecretKey& mfSecretKey, ZZX& logg, Context& context) {
	size_t tau = deg(logg) + 1;
	vector<ZZX> vmx = Gamma.ax;
	vector<ZZX> mx(tau);
	ZZX sx = mfSecretKey.sx;

	ZZ qQ = context.qpowvec[msg.logq + context.logQ];

	ZZX tmp(tau);
	
	ZZX g; g.SetLength(tau);
    for (int i = 0; i < tau; i++) {
        g[i] = power(ZZ(2), conv<long>(logg[i])); 
    }

	ZZX gx; 
	long Q = 1 << context.logQ;
	ZZ Qz = to_ZZ(Q);
	for (int i = 0; i < tau; i++) {
		for (int j = 0; j < deg(msg.mx) + 1; j++) {
			if (j == 0) {
				SetCoeff(gx, j, g[i]);
			} else {
				SetCoeff(gx, j, 0);
			}
		}

		Ring2Utils::mult(mx[i], msg.mx, gx, qQ, context.N);		
	}

	vmx = gadgetDecryption(Gamma, mfSecretKey, logg, context);

	
	complex<double>* res_mx = new complex<double>[msg.slots];
	complex<double>* res_vmx = new complex<double>[msg.slots];
	bool flag = false;
	for (int i = 0; i < tau; i++) {
		res_mx = context.decode(mx[i], msg.slots, msg.logp, msg.logq);
		res_vmx = context.decode(vmx[i], msg.slots, msg.logp, msg.logq);
		StringUtils::showcompare(res_mx, res_vmx, msg.slots, "gadgetEncrypt");
	}	
	cout << "Complete verifiying gadget encryption!" << endl;
}

/**
 * @brief Calulate U.u0 + sx\cdot U.u1 ==> Gamma.ax + sx\cdot Gamma.bx ==> mu\cdot g
 * 
 * @param Gamma 
 * @param mfSecretKey 
 * @param logg 
 * @param context 
 * @return vector<ZZX> 
 */
vector<ZZX> MFScheme::gadgetDecryption(MFCiphertext& Gamma, MFSecretKey& mfSecretKey, ZZX& logg, Context& context) {
	size_t tau = deg(logg) + 1;
	vector<ZZX> vmx = Gamma.bx;
	ZZX sx = mfSecretKey.sx;

	ZZ qQ = context.qpowvec[Gamma.logq + context.logQ];

	ZZX tmp(tau);
	for (int i = 0; i < tau; i++) {
		Ring2Utils::mult(tmp, Gamma.ax[i], mfSecretKey.sx, qQ, context.N);
		Ring2Utils::addAndEqual(vmx[i], tmp, qQ, context.N);
	}

	return vmx;
}


// revised 2025.05.23
MFPlaintext MFScheme::decryptMsg(MFSecretKey& mfSecretKey, MFCiphertext& cipher) {
	ZZ qQ = context.qpowvec[cipher.logq + context.logQ];

	ZZX mx;

	Ring2Utils::mult(mx, cipher.ax[0], mfSecretKey.sx, qQ, context.N);
	Ring2Utils::addAndEqual(mx, cipher.bx[0], qQ, context.N);
	
	return MFPlaintext(mx, cipher.logp, cipher.logq, cipher.slots, cipher.isComplex);
}

MFCiphertext MFScheme::partDecryptMsg(ZZX sx, MFCiphertext& cipher, long party_id){
	ZZ qQ = context.qpowvec[cipher.logq + cipher.logq];

	ZZX mx, ex;
	NumUtils::sampleGauss(ex, context.N, context.sigma);

	ZZX ax = cipher.ax[party_id-1];
	Ring2Utils::multAndEqual(ax, sx, qQ, context.N);
	Ring2Utils::addAndEqual(ax, ex, qQ, context.N);
	cipher.ax[0] = ax;

	return MFCiphertext(cipher.ax[0], cipher.bx[0], cipher.logp, cipher.logq, cipher.slots, cipher.isComplex, party_id);
}

MFPlaintext MFScheme::fullDecryptMsg(MFCiphertext& cipher1, MFCiphertext& cipher2) {
	ZZ qQ = context.qpowvec[cipher1.logq + cipher1.logq];
	ZZX mx;
	mx.SetLength(deg(cipher1.ax[0])+1);
	Ring2Utils::addAndEqual(mx, cipher1.bx[0], qQ, context.N);
	Ring2Utils::addAndEqual(mx, cipher1.ax[0], qQ, context.N);
	Ring2Utils::addAndEqual(mx, cipher2.ax[0], qQ, context.N);
	return MFPlaintext(mx, cipher1.logp, cipher1.logq, cipher1.slots, cipher1.isComplex, 0); // party_id=0 represents global plaintext
}

MFCiphertext MFScheme::encrypt(double* vals, long slots, long logp, long logq) {
	MFPlaintext msg = encode(vals, slots, logp, logq);
	return encryptMsg(msg);
}

MFCiphertext MFScheme::encrypt(complex<double>* vals, long slots, long logp, long logq) {
	MFPlaintext msg = encode(vals, slots, logp, logq);
	return encryptMsg(msg);
}

MaskResults MFScheme::maskEncrypt(MFSecretKey mfSecretKey, ZZX vx, complex<double>* vals, ZZX logg, long slots, long logp, long logq) {
	MaskResults MR;

	TimeUtils timeutils;
	MFPlaintext msg = encode(vals, slots, logp, logq);
	MR.cz = maskEncryptMsg(msg, vx);

	MFPlaintext msg_vx = MFPlaintext(vx, logp, logq, slots, true);

	// timeutils.start("Gadget EncryptMsg");
	MR.Gamma = gadgetEncryptMsg(msg_vx, mfSecretKey, logg, context);
	// timeutils.stop("Gadget EncryptMsg");

	return MR;
}

MaskResults MFScheme::maskEncrypt(MFSecretKey mfSecretKey, ZZX vx, ZZX mx, ZZX logg, long slots, long logp, long logq) {
	MaskResults MR;

	TimeUtils timeutils;
	MFPlaintext msg = MFPlaintext(mx, logp, logq, slots, true);

	// timeutils.start("Mask EncryptMsg");
	MR.cz = maskEncryptMsg(msg, vx);
	// timeutils.stop("Mask EncryptMsg");

	MFPlaintext msg_vx = MFPlaintext(vx, logp, logq, slots, true);

	// timeutils.start("Gadget EncryptMsg");
	MR.Gamma = gadgetEncryptMsg(msg_vx, mfSecretKey, logg, context);
	// timeutils.stop("Gadget EncryptMsg");

	return MR;
}


MFCiphertext MFScheme::maskExtend(MFCiphertext& Gamma, ZZX& logg, ZZX& bx, ZZX& bxx) {
	GadgetEncryption U;
	U.u0 = Gamma.bx;
	U.u1 = Gamma.ax;

	ZZX diff;
	ZZ qQ = context.qpowvec[Gamma.logq + Gamma.logq];
	Ring2Utils::sub(diff, bxx, bx, qQ, context.N);

	return externalProduct(diff, U, logg, context);
}

/**
 * @brief Let a\in R_Q and u\in R_Q^{\tau}. The external product of a and u is denoted as a\boxdot u = <h(a),u> (mod Q).
 * We also write a\boxdot U= (a\boxdot u0, a\boxdot u1) for U= (u0, u1) \in R_Q^{\tau\times 2}
 * 
 * @param a 
 * @param U 
 * @param g 
 * @param context 
 * @return MFCiphertext 
 */
MFCiphertext MFScheme::externalProduct(ZZX& ax, GadgetEncryption& U, ZZX& logg, Context& context) {
    ZZX acc0, acc1, tmp0, tmp1; 
	ZZ qQ = context.qpowvec[context.logQ + context.logQ];
	size_t tau = deg(logg) + 1;
	acc0.SetLength(deg(ax)+1);
	acc1.SetLength(deg(ax)+1);	

	// In external product, the cofficient of the big polynomial bb1 or bb2 should be all positive and thus we perform the follows.
	for (int i = 0; i <= deg(ax); i++) { 
		if (ax[i] < 0) {ax[i] += qQ;}
		if (ax[i] < 0) {ax[i] += qQ;}
	}	

	vector<ZZX> ha = gadgetDecompose(ax, logg, context); 

    for (long i = 0; i < ha.size(); i++) {
		Ring2Utils::mult(tmp0, ha[i], U.u0[i], qQ, context.N); 
		Ring2Utils::mult(tmp1, ha[i], U.u1[i], qQ, context.N);
		Ring2Utils::addAndEqual(acc0, tmp0, qQ, context.N);
		Ring2Utils::addAndEqual(acc1, tmp1, qQ, context.N);
    }

	return MFCiphertext(acc1, acc0, 0, context.logQ);
}

/**
 * @brief Verify whether <sk, ax\boxdot U> = <H(a), <sk,U>> = <H(a), \mu\cdot g+e> = a \cdot \mu + e
 * 
 * @param mfSecretKey 
 * @param ax 
 * @param U 
 * @param logg 
 * @param context 
 * @return true 
 * @return false 
 */
bool MFScheme::verifyExternalProduct(MFPlaintext& msg, MFSecretKey& mfSecretKey, ZZX& ax, MFCiphertext& Gamma, ZZX& logg, Context& context) {
	ZZX sx = mfSecretKey.sx;
	GadgetEncryption U;
	U.u0 = Gamma.bx;
	U.u1 = Gamma.ax;

	MFCiphertext externalCipher = externalProduct(ax, U, logg, context);

	ZZ qQ = context.qpowvec[msg.logq + context.logQ];
	long degree = deg(ax) + 1;

	vector<ZZX> hax = gadgetDecompose(ax, logg, context);  
	vector<ZZX> vmx = gadgetDecryption(Gamma, mfSecretKey, logg, context); // vmx = <sk, U>

	//-------------------------------------------------------------------------------------------
	// Verify whether gadegt decryption is correct: <sk, U> = vmx =? mx = mu\cdot g 
	size_t tau = deg(logg) + 1;
	ZZX g; g.SetLength(tau);
    for (int i = 0; i < tau; i++) {
        g[i] = power(ZZ(2), conv<long>(logg[i])); 
    }

	ZZX gx, ex; vector<ZZX> mx(tau);
	for (int i = 0; i < tau; i++) {
		for (int j = 0; j < deg(msg.mx) + 1; j++) {
			if (j == 0) {
				SetCoeff(gx, j, g[i]);
			} else {
				SetCoeff(gx, j, 0);
			}
		}
		Ring2Utils::mult(mx[i], msg.mx, gx, qQ, context.N);
	}

	complex<double>* res_mx = new complex<double>[msg.slots];
	complex<double>* res_vmx = new complex<double>[msg.slots];
	bool flag = false;
	for (int i = 0; i < tau; i++) {
		res_mx = context.decode(mx[i], msg.slots, msg.logp, msg.logq);
		res_vmx = context.decode(vmx[i], msg.slots, msg.logp, msg.logq);
		StringUtils::showcompare(res_mx, res_vmx, msg.slots, "gadgetEncrypt");
	}	
	//-------------------------------------------------------------------------------------------

	//-------------------------------------------------------------------------------------------
	// Verify whether the two decrypted results are equal ==> dec_extprod = <sk, ax\boxdot U> =? innerProd = <H(a), <sk,U>>.
	// Decryption of external product: <sk, ax\boxdot U>
	ZZX dec_extprod; 
	
	MFPlaintext cx1Dec = decryptMsg(mfSecretKey, externalCipher); 
	dec_extprod = cx1Dec.mx;

	// Decryption of a gadget encryption: <H(a), <sk,U>>
	ZZX tmp1, innerProd; innerProd.SetLength(degree);
	for (int i = 0; i < hax.size(); i++) {
		Ring2Utils::mult(tmp1, hax[i], vmx[i], qQ, context.N); 
		Ring2Utils::addAndEqual(innerProd, tmp1, qQ, context.N); 
	}
	// Ring2Utils::rightShiftAndEqual(innerProd, context.logQ, context.N); 

	ZZX diffx;
	Ring2Utils::sub(diffx, dec_extprod, innerProd, qQ, context.N);	
	for (int i = 0; i < degree; i++) {
		if (diffx[i] != 0) {
			cout << "External Product1: <sk, ax boxdot U> != <H(a), <sk,U>>" << endl;
			return false;
		}
	}
	cout << "External Product1: <sk, ax boxdot U> = <H(a), <sk,U>>" << endl;
	//-------------------------------------------------------------------------------------------

	// Verify whether <H(a), <sk,U>> = innerProd =? hau = <H(a), \mu\cdot g+e> 
	ZZX tmp2, hau; hau.SetLength(degree);
	double epsilon = 1e-5;
	for (int i = 0; i < hax.size(); i++) {
		Ring2Utils::mult(tmp2, hax[i], mx[i], qQ, context.N); 
		Ring2Utils::addAndEqual(hau, tmp2, qQ, context.N); 
	}

	cout << "External Product2: <H(a), <sk,U>> = innerProd =? hau = <H(a), mu g+e>" << endl;
	complex<double>* res_innerProd = new complex<double>[msg.slots];
	complex<double>* res_hau = new complex<double>[msg.slots];
	res_innerProd = context.decode(innerProd, msg.slots, msg.logp, msg.logq);
	res_hau = context.decode(hau, msg.slots, msg.logp, msg.logq);
	StringUtils::showcompare(res_innerProd, res_hau, msg.slots, "externalProduct");
	//We have verified that decode(<sk,U>) ~= decode(mu g+e) and thus <H(a), <sk,U>> != <H(a), mu g+e> without decoding
	// and decode(<H(a), <sk,U>>) ~= decode(<H(a), mu g+e>)

	ZZX diffx2;
	long error = 1000000;
	Ring2Utils::sub(diffx2, hau, innerProd, qQ, context.N);	
	for (int i = 0; i < degree; i++) {
		double abs_diff = fabs(to_double(diffx2[i]));
		if (abs_diff > error) {
			cout << "External Product2: <H(a), <sk,U>> = innerProd != hau = <H(a), mu g+e>" << endl;
			cout << "External Product2: innerProd[0] = " << innerProd[0] << endl;
			cout << "External Product2:       hau[0] = " << hau[0] << endl;
			return false;
		}
	}
	cout << "External Product2: innerProd[0] = " << innerProd[0] << endl;
	cout << "External Product2:       hau[0] = " << hau[0] << endl;
	cout << "External Product2: <H(a), <sk,U>> = innerProd == hau = <H(a), mu g+e>" << endl;
	//-------------------------------------------------------------------------------------------

	// Verify whether hua = <H(a), \mu\cdot g+e> =? a \cdot \mu + e
	ZZX au;
	// double epsilon = 1e-5;
	Ring2Utils::mult(au, ax, msg.mx, qQ, context.N); 
	ZZX diffx3;
	Ring2Utils::sub(diffx3, hau, au, qQ, context.N);
	cout << "External Product3:  au[0] = " << au[0] << endl;
	cout << "External Product3: hau[0] = " << hau[0] << endl;
	for (int i = 0; i < degree; i++) {
		if (diffx3[i] != 0) {
			cout << "External Product3: hua = <H(a), mu g+e> != a mu + e" << endl;
			return false;
		}
	}
	cout << "External Product3: hua = <H(a), mu g+e> == a mu + e" << endl;

	ZZX diffx4;
	Ring2Utils::sub(diffx4, dec_extprod, au, qQ, context.N);
	for (int i = 0; i < degree; i++) {
		double abs_diff4 = fabs(to_double(diffx4[i]));
		if (abs_diff4 > error) {
			cout << "External Product4: <H(a), <sk,U>> = innerProd != au = a mu + e" << endl;
			return false;
		}
	}	
	cout << "External Product4: <H(a), <sk,U>> = innerProd == au = a mu + e" << endl;	

	return true;	
}	


/**
 * @brief Convert ax\in R into H\in R^{\tau} ==> <H,g> = a (mod Q), g\in R_{\tau} (CCS19 MKHE)
 * 
 * @param ax 
 * @param logg 
 * @param context 
 * @return vector<ZZX> 
 */
vector<ZZX> MFScheme::gadgetDecompose(ZZX ax, ZZX& logg, Context context) {
	long degree = deg(ax) + 1;
    size_t tau = deg(logg) + 1;
	vector<ZZX> H(tau); 
    ZZX hx, tmpx;   

    for (int i = tau - 1; i >= 0; --i) {
		Ring2Utils::rightShift(hx, ax, conv<long>(logg[i]), degree); // ax >> logg[i]-bits, i.e., ax = floor(ax/2^logg[i])
		Ring2Utils::leftShift(tmpx, hx, conv<long>(logg[i]), context.QQ, degree);
		Ring2Utils::subAndEqual(ax, tmpx, context.QQ, degree);
		H[i] = hx;
    } 	
	
    return H;
}

bool MFScheme::verifyDecomposition(ZZX ax, vector<ZZX>& H, ZZX& logg, Context context) {
	long degree = deg(ax) + 1;
    size_t tau = deg(logg) + 1;
	ZZX reconstructed, tmpx; 
	reconstructed.SetLength(degree);
    for (int i = 0; i < tau; i++) {
		Ring2Utils::leftShift(tmpx, H[i], conv<long>(logg[i]), context.QQ, degree);
		Ring2Utils::addAndEqual(reconstructed, tmpx, context.QQ, degree);
    }

    return ax == reconstructed;
}


MFCiphertext MFScheme::encryptZeros(long slots, long logp, long logq) {
	MFCiphertext czeros = encryptSingle(0.0, logp, logq);
	czeros.isComplex = true;
	czeros.slots = slots;
	return czeros;
}


complex<double>* MFScheme::decrypt(MFSecretKey& secretKey, MFCiphertext& cipher) {
	MFPlaintext msg = decryptMsg(secretKey, cipher);
	return decode(msg);
}

MFCiphertext MFScheme::partDecrypt(ZZX sx, MFCiphertext& cipher, long party_id) {
	MFCiphertext pdmsg = partDecryptMsg(sx, cipher, party_id);
	return pdmsg;
}

complex<double>* MFScheme::fullDecrypt(MFCiphertext& cipher1, MFCiphertext& cipher2){
	MFPlaintext msg = fullDecryptMsg(cipher1, cipher2);
	return decode(msg);
}

MFCiphertext MFScheme::encryptSingle(double val, long logp, long logq) {
	MFPlaintext msg = encodeSingle(val, logp,  logq);
	return encryptMsg(msg);
}

MFCiphertext MFScheme::encryptSingle(complex<double> val, long logp, long logq) {
	MFPlaintext msg = encodeSingle(val, logp,  logq);
	return encryptMsg(msg);
}

complex<double> MFScheme::decryptSingle(MFSecretKey& secretKey, MFCiphertext& cipher) {
	MFPlaintext msg = decryptMsg(secretKey, cipher);
	return decodeSingle(msg);
}


//----------------------------------------------------------------------------------
//   HOMOMORPHIC OPERATIONS
//----------------------------------------------------------------------------------


MFCiphertext MFScheme::negate(MFCiphertext& cipher) {
	return MFCiphertext(-cipher.ax[0], -cipher.bx[0], cipher.logp, cipher.logq, cipher.slots, cipher.isComplex);
}

void MFScheme::negateAndEqual(MFCiphertext& cipher) {
	cipher.ax[0] = -cipher.ax[0];
	cipher.bx[0] = -cipher.bx[0];
}

MFCiphertext MFScheme::add(MFCiphertext& cipher1, MFCiphertext& cipher2, MaskResults& MR1, MaskResults& MR2) {
	ZZ qQ = context.qpowvec[cipher1.logq + cipher1.logq];
	ZZX bx;
	vector<ZZX> ax(2, ZZX::zero());
	
	// bar{ct1} = ct1 + cx1 + cz2 = (bx1, ax1); bar{ct2} = ct2 + cx2 + cz1 = (bx2, ax2); Output CT = (bx1+bx2, ax1, ax2)
	Ring2Utils::add(bx, cipher1.bx[0], MR1.Gamma.bx[0], qQ, context.N); // c0^1+x0^1 for party1
	Ring2Utils::addAndEqual(bx, MR2.cz.bx[0], qQ, context.N); // bx=c0^1+x0^1+z0^2 for party1
	Ring2Utils::addAndEqual(bx, cipher2.bx[0], qQ, context.N);
	Ring2Utils::addAndEqual(bx, MR2.Gamma.bx[0], qQ, context.N);
	Ring2Utils::addAndEqual(bx, MR1.cz.bx[0], qQ, context.N);// (the 1st component of expanded aggregated ciphertext) ax = ax^1+ax^2: ax^2=c0^2+x0^2+z0^1 for party2 and plus party1's ax^1

	Ring2Utils::add(ax[0], cipher1.ax[0], MR1.Gamma.ax[0], qQ, context.N); // bx[0] = c1^1+x1^1 for party1
	Ring2Utils::addAndEqual(ax[0], MR2.cz.ax[0], qQ, context.N); // bx[0] = c1^1+x1^1+z1^2(the 2nd component of expanded aggregated ciphertext)

	Ring2Utils::add(ax[1], cipher2.ax[0], MR2.Gamma.ax[0], qQ, context.N); // bx[1] = c1^2+x1^2 for party2
	Ring2Utils::addAndEqual(ax[1], MR1.cz.ax[0], qQ, context.N); // bx[1] = c1^2+x1^2+z1^1 (the 3rd component of expanded aggregated ciphertext)

	// The returned aggregated ciphertext is (ax, bx[0], bx[1]), which is a vector containing 3 components.
	return MFCiphertext(ax, bx, cipher1.logp, cipher1.logq, cipher1.slots, cipher1.isComplex, cipher1.party_id);
}

void MFScheme::addAndEqual(MFCiphertext& cipher1, MFCiphertext& cipher2, MaskResults& MR1, MaskResults& MR2) {
	ZZ qQ = context.qpowvec[cipher1.logq + cipher1.logq];

	Ring2Utils::addAndEqual(cipher1.ax[0], MR1.Gamma.ax[0], qQ, context.N); 
	Ring2Utils::addAndEqual(cipher1.ax[0], MR2.cz.ax[0], qQ, context.N); 

	Ring2Utils::add(cipher1.ax[1], cipher2.ax[0], MR2.Gamma.ax[0], qQ, context.N); 
	Ring2Utils::addAndEqual(cipher1.ax[1], MR1.cz.ax[0], qQ, context.N);

	Ring2Utils::addAndEqual(cipher1.bx[0], cipher2.bx[0], qQ, context.N);
	Ring2Utils::addAndEqual(cipher1.bx[0], MR1.Gamma.bx[0], qQ, context.N);
	Ring2Utils::addAndEqual(cipher1.bx[0], MR2.cz.bx[0], qQ, context.N); 
	Ring2Utils::addAndEqual(cipher1.bx[0], MR2.Gamma.bx[0], qQ, context.N);
	Ring2Utils::addAndEqual(cipher1.bx[0], MR1.cz.bx[0], qQ, context.N);
}


MFCiphertext MFScheme::mult(MFCiphertext& cipher1, MFCiphertext& cipher2) {
	ZZ q = context.qpowvec[cipher1.logq];
	ZZ qQ = context.qpowvec[cipher1.logq + context.logQ];

	ZZX axbx1, axbx2, axax, bxbx, axmult, bxmult;
	MFKey key = mfKeyMap.at(MULTIPLICATION);

	Ring2Utils::add(axbx1, cipher1.ax[0], cipher1.bx[0], q, context.N);
	Ring2Utils::add(axbx2, cipher2.ax[0], cipher2.bx[0], q, context.N);
	Ring2Utils::multAndEqual(axbx1, axbx2, q, context.N);

	Ring2Utils::mult(axax, cipher1.ax[0], cipher2.ax[0], q, context.N);
	Ring2Utils::mult(bxbx, cipher1.bx[0], cipher2.bx[0], q, context.N);

	Ring2Utils::mult(axmult, axax, key.ax, qQ, context.N);
	Ring2Utils::mult(bxmult, axax, key.bx, qQ, context.N);

	Ring2Utils::rightShiftAndEqual(axmult, context.logQ, context.N);
	Ring2Utils::rightShiftAndEqual(bxmult, context.logQ, context.N);

	Ring2Utils::addAndEqual(axmult, axbx1, q, context.N);
	Ring2Utils::subAndEqual(axmult, bxbx, q, context.N);
	Ring2Utils::subAndEqual(axmult, axax, q, context.N);
	Ring2Utils::addAndEqual(bxmult, bxbx, q, context.N);

	return MFCiphertext(axmult, bxmult, cipher1.logp + cipher2.logp, cipher1.logq, cipher1.slots, cipher1.isComplex);
}

void MFScheme::multAndEqual(MFCiphertext& cipher1, MFCiphertext& cipher2) {
	ZZ q = context.qpowvec[cipher1.logq];
	ZZ qQ = context.qpowvec[cipher1.logq + context.logQ];
	ZZX axbx1, axbx2, axax, bxbx;
	MFKey key = mfKeyMap.at(MULTIPLICATION);

	Ring2Utils::add(axbx1, cipher1.ax[0], cipher1.bx[0], q, context.N);
	Ring2Utils::add(axbx2, cipher2.ax[0], cipher2.bx[0], q, context.N);
	Ring2Utils::multAndEqual(axbx1, axbx2, q, context.N);

	Ring2Utils::mult(axax, cipher1.ax[0], cipher2.ax[0], q, context.N);
	Ring2Utils::mult(bxbx, cipher1.bx[0], cipher2.bx[0], q, context.N);

	Ring2Utils::mult(cipher1.ax[0], axax, key.ax, qQ, context.N);
	Ring2Utils::mult(cipher1.bx[0], axax, key.bx, qQ, context.N);

	Ring2Utils::rightShiftAndEqual(cipher1.ax[0], context.logQ, context.N);
	Ring2Utils::rightShiftAndEqual(cipher1.bx[0], context.logQ, context.N);

	Ring2Utils::addAndEqual(cipher1.ax[0], axbx1, q, context.N);
	Ring2Utils::subAndEqual(cipher1.ax[0], bxbx, q, context.N);
	Ring2Utils::subAndEqual(cipher1.ax[0], axax, q, context.N);
	Ring2Utils::addAndEqual(cipher1.bx[0], bxbx, q, context.N);

	cipher1.logp += cipher2.logp;
}

MFCiphertext MFScheme::square(MFCiphertext& cipher) {
	ZZ q = context.qpowvec[cipher.logq];
	ZZ qQ = context.qpowvec[cipher.logq + context.logQ];
	ZZX axax, axbx, bxbx, bxmult, axmult;
	MFKey key = mfKeyMap.at(MULTIPLICATION);

	Ring2Utils::square(bxbx, cipher.bx[0], q, context.N);
	Ring2Utils::mult(axbx, cipher.ax[0], cipher.bx[0], q, context.N);
	Ring2Utils::addAndEqual(axbx, axbx, q, context.N);
	Ring2Utils::square(axax, cipher.ax[0], q, context.N);

	Ring2Utils::mult(axmult, axax, key.ax, qQ, context.N);
	Ring2Utils::mult(bxmult, axax, key.bx, qQ, context.N);

	Ring2Utils::rightShiftAndEqual(axmult, context.logQ, context.N);
	Ring2Utils::rightShiftAndEqual(bxmult, context.logQ, context.N);

	Ring2Utils::addAndEqual(axmult, axbx, q, context.N);
	Ring2Utils::addAndEqual(bxmult, bxbx, q, context.N);

	return MFCiphertext(axmult, bxmult, cipher.logp * 2, cipher.logq, cipher.slots, cipher.isComplex);
}

void MFScheme::squareAndEqual(MFCiphertext& cipher) {
	ZZ q = context.qpowvec[cipher.logq];
	ZZ qQ = context.qpowvec[cipher.logq + context.logQ];
	ZZX bxbx, axbx, axax;
	MFKey key = mfKeyMap.at(MULTIPLICATION);

	Ring2Utils::square(bxbx, cipher.bx[0], q, context.N);
	Ring2Utils::mult(axbx, cipher.bx[0], cipher.ax[0], q, context.N);
	Ring2Utils::addAndEqual(axbx, axbx, q, context.N);
	Ring2Utils::square(axax, cipher.ax[0], q, context.N);

	Ring2Utils::mult(cipher.ax[0], axax, key.ax, qQ, context.N);
	Ring2Utils::mult(cipher.bx[0], axax, key.bx, qQ, context.N);

	Ring2Utils::rightShiftAndEqual(cipher.ax[0], context.logQ, context.N);
	Ring2Utils::rightShiftAndEqual(cipher.bx[0], context.logQ, context.N);

	Ring2Utils::addAndEqual(cipher.ax[0], axbx, q, context.N);
	Ring2Utils::addAndEqual(cipher.bx[0], bxbx, q, context.N);
	cipher.logp *= 2;
}

MFCiphertext MFScheme::multByConst(MFCiphertext& cipher, double cnst, long logp) {
	ZZ q = context.qpowvec[cipher.logq];
	ZZX ax, bx;

	ZZ cnstZZ = EvaluatorUtils::scaleUpToZZ(cnst, logp);

	Ring2Utils::multByConst(ax, cipher.ax[0], cnstZZ, q, context.N);
	Ring2Utils::multByConst(bx, cipher.bx[0], cnstZZ, q, context.N);

	return MFCiphertext(ax, bx, cipher.logp + logp, cipher.logq, cipher.slots, cipher.isComplex);
}

MFCiphertext MFScheme::multByConst(MFCiphertext& cipher, RR& cnst, long logp) {
	ZZ q = context.qpowvec[cipher.logq];
	ZZX ax, bx;

	ZZ cnstZZ = EvaluatorUtils::scaleUpToZZ(cnst, logp);

	Ring2Utils::multByConst(ax, cipher.ax[0], cnstZZ, q, context.N);
	Ring2Utils::multByConst(bx, cipher.bx[0], cnstZZ, q, context.N);

	return MFCiphertext(ax, bx, cipher.logp + logp, cipher.logq, cipher.slots, cipher.isComplex);
}

MFCiphertext MFScheme::multByConst(MFCiphertext& cipher, complex<double> cnst, long logp) {
	ZZ q = context.qpowvec[cipher.logq];

	ZZX axr, bxr, axi, bxi;

	ZZ cnstrZZ = EvaluatorUtils::scaleUpToZZ(cnst.real(), logp);
	ZZ cnstiZZ = EvaluatorUtils::scaleUpToZZ(cnst.imag(), logp);

	Ring2Utils::multByMonomial(axi, cipher.ax[0], context.Nh, context.N);
	Ring2Utils::multByMonomial(bxi, cipher.bx[0], context.Nh, context.N);

	Ring2Utils::multByConst(axr, cipher.ax[0], cnstrZZ, q, context.N);
	Ring2Utils::multByConst(bxr, cipher.bx[0], cnstrZZ, q, context.N);

	Ring2Utils::multByConstAndEqual(axi, cnstiZZ, q, context.N);
	Ring2Utils::multByConstAndEqual(bxi, cnstiZZ, q, context.N);

	Ring2Utils::addAndEqual(axr, axi, q, context.N);
	Ring2Utils::addAndEqual(bxr, bxi, q, context.N);

	return MFCiphertext(axr, bxr, cipher.logp + logp, cipher.logq, cipher.slots, cipher.isComplex);
}


//----------------------------------------------------------------------------------
//   RESCALING & MODULUS DOWN
//----------------------------------------------------------------------------------


MFCiphertext MFScheme::reScaleBy(MFCiphertext& cipher, long bitsDown) {
	ZZX ax, bx;

	Ring2Utils::rightShift(ax, cipher.ax[0], bitsDown, context.N);
	Ring2Utils::rightShift(bx, cipher.bx[0], bitsDown, context.N);

	return MFCiphertext(ax, bx, cipher.logp - bitsDown, cipher.logq - bitsDown, cipher.slots, cipher.isComplex);
}

MFCiphertext MFScheme::reScaleTo(MFCiphertext& cipher, long newlogq) {
	ZZX ax, bx;
	long bitsDown = cipher.logq - newlogq;

	Ring2Utils::rightShift(ax, cipher.ax[0], bitsDown, context.N);
	Ring2Utils::rightShift(bx, cipher.bx[0], bitsDown, context.N);

	return MFCiphertext(ax, bx, cipher.logp - bitsDown, newlogq, cipher.slots, cipher.isComplex);
}

void MFScheme::reScaleByAndEqual(MFCiphertext& cipher, long bitsDown) {
	Ring2Utils::rightShiftAndEqual(cipher.ax[0], bitsDown, context.N);
	Ring2Utils::rightShiftAndEqual(cipher.bx[0], bitsDown, context.N);

	cipher.logq -= bitsDown;
	cipher.logp -= bitsDown;
}

void MFScheme::reScaleToAndEqual(MFCiphertext& cipher, long logq) {
	long bitsDown = cipher.logq - logq;
	cipher.logq = logq;
	cipher.logp -= bitsDown;

	Ring2Utils::rightShiftAndEqual(cipher.ax[0], bitsDown, context.N);
	Ring2Utils::rightShiftAndEqual(cipher.bx[0], bitsDown, context.N);
}

MFCiphertext MFScheme::modDownBy(MFCiphertext& cipher, long bitsDown) {
	ZZX bx, ax;
	long newlogq = cipher.logq - bitsDown;
	ZZ q = context.qpowvec[newlogq];

	Ring2Utils::mod(ax, cipher.ax[0], q, context.N);
	Ring2Utils::mod(bx, cipher.bx[0], q, context.N);

	return MFCiphertext(ax, bx, cipher.logp, newlogq, cipher.slots, cipher.isComplex);
}

void MFScheme::modDownByAndEqual(MFCiphertext& cipher, long bitsDown) {
	cipher.logq -= bitsDown;
	ZZ q = context.qpowvec[cipher.logq];

	Ring2Utils::modAndEqual(cipher.ax[0], q, context.N);
	Ring2Utils::modAndEqual(cipher.bx[0], q, context.N);
}

MFCiphertext MFScheme::modDownTo(MFCiphertext& cipher, long logq) {
	ZZX bx, ax;
	ZZ q = context.qpowvec[logq];

	Ring2Utils::mod(ax, cipher.ax[0], q, context.N);
	Ring2Utils::mod(bx, cipher.bx[0], q, context.N);
	return MFCiphertext(ax, bx, cipher.logp, logq, cipher.slots);
}

void MFScheme::modDownToAndEqual(MFCiphertext& cipher, long logq) {
	cipher.logq = logq;
	ZZ q = context.qpowvec[logq];

	Ring2Utils::modAndEqual(cipher.ax[0], q, context.N);
	Ring2Utils::modAndEqual(cipher.bx[0], q, context.N);
}


//----------------------------------------------------------------------------------
//   ROTATIONS & CONJUGATIONS
//----------------------------------------------------------------------------------


MFCiphertext MFScheme::leftRotateFast(MFCiphertext& cipher, long rotSlots) {
	ZZ q = context.qpowvec[cipher.logq];
	ZZ qQ = context.qpowvec[cipher.logq + context.logQ];

	ZZX bxrot, ax, bx;
	MFKey key = leftRotKeyMap.at(rotSlots);

	Ring2Utils::inpower(bxrot, cipher.bx[0], context.rotGroup[rotSlots], context.Q, context.N);
	Ring2Utils::inpower(bx, cipher.ax[0], context.rotGroup[rotSlots], context.Q, context.N);

	Ring2Utils::mult(ax, bx, key.ax, qQ, context.N);
	Ring2Utils::multAndEqual(bx, key.bx, qQ, context.N);

	Ring2Utils::rightShiftAndEqual(ax, context.logQ, context.N);
	Ring2Utils::rightShiftAndEqual(bx, context.logQ, context.N);

	Ring2Utils::addAndEqual(bx, bxrot, q, context.N);

	return MFCiphertext(ax, bx, cipher.logp, cipher.logq, cipher.slots, cipher.isComplex);
}

void MFScheme::leftRotateAndEqualFast(MFCiphertext& cipher, long rotSlots) {
	ZZ q = context.qpowvec[cipher.logq];
	ZZ qQ = context.qpowvec[cipher.logq + context.logQ];
	ZZX bxrot;
	MFKey key = leftRotKeyMap.at(rotSlots);

	Ring2Utils::inpower(bxrot, cipher.bx[0], context.rotGroup[rotSlots], context.Q, context.N);
	Ring2Utils::inpower(cipher.bx[0], cipher.ax[0], context.rotGroup[rotSlots], context.Q, context.N);

	Ring2Utils::mult(cipher.ax[0], cipher.bx[0], key.ax, qQ, context.N);
	Ring2Utils::multAndEqual(cipher.bx[0], key.bx, qQ, context.N);

	Ring2Utils::rightShiftAndEqual(cipher.ax[0], context.logQ, context.N);
	Ring2Utils::rightShiftAndEqual(cipher.bx[0], context.logQ, context.N);

	Ring2Utils::addAndEqual(cipher.bx[0], bxrot, q, context.N);
}

MFCiphertext MFScheme::leftRotateByPo2(MFCiphertext& cipher, long logrotSlots) {
	long rotSlots = (1 << logrotSlots);
	return leftRotateFast(cipher, rotSlots);
}

void MFScheme::leftRotateByPo2AndEqual(MFCiphertext& cipher, long logrotSlots) {
	long rotSlots = (1 << logrotSlots);
	leftRotateAndEqualFast(cipher, rotSlots);
}

MFCiphertext MFScheme::rightRotateByPo2(MFCiphertext& cipher, long logrotSlots) {
	long rotSlots = context.Nh - (1 << logrotSlots);
	return leftRotateFast(cipher, rotSlots);
}

void MFScheme::rightRotateByPo2AndEqual(MFCiphertext& cipher, long logrotSlots) {
	long rotSlots = context.Nh - (1 << logrotSlots);
	leftRotateAndEqualFast(cipher, rotSlots);
}

MFCiphertext MFScheme::leftRotate(MFCiphertext& cipher, long rotSlots) {
	MFCiphertext res = cipher;
	leftRotateAndEqual(res, rotSlots);
	return res;
}

void MFScheme::leftRotateAndEqual(MFCiphertext& cipher, long rotSlots) {
	long remrotSlots = rotSlots % cipher.slots;
	long logrotSlots = log2((double)remrotSlots) + 1;
	for (long i = 0; i < logrotSlots; ++i) {
		if(bit(remrotSlots, i)) {
			leftRotateByPo2AndEqual(cipher, i);
		}
	}
}

MFCiphertext MFScheme::rightRotate(MFCiphertext& cipher, long rotSlots) {
	MFCiphertext res = cipher;
	rightRotateAndEqual(res, rotSlots);
	return res;
}

void MFScheme::rightRotateAndEqual(MFCiphertext& cipher, long rotSlots) {
	long remrotSlots = rotSlots % cipher.slots;
	long logrotSlots = log2((double)remrotSlots) + 1;
	for (long i = 0; i < logrotSlots; ++i) {
		if(bit(remrotSlots, i)) {
			rightRotateByPo2AndEqual(cipher, i);
		}
	}
}

MFCiphertext MFScheme::conjugate(MFCiphertext& cipher) {
	ZZ q = context.qpowvec[cipher.logq];
	ZZ qQ = context.qpowvec[cipher.logq + context.logQ];

	ZZX bxconj, ax, bx;
	MFKey key = mfKeyMap.at(CONJUGATION);

	Ring2Utils::conjugate(bxconj, cipher.bx[0], context.N);
	Ring2Utils::conjugate(bx, cipher.ax[0], context.N);

	Ring2Utils::mult(ax, bx, key.ax, qQ, context.N);
	Ring2Utils::multAndEqual(bx, key.bx, qQ, context.N);

	Ring2Utils::rightShiftAndEqual(ax, context.logQ, context.N);
	Ring2Utils::rightShiftAndEqual(bx, context.logQ, context.N);

	Ring2Utils::addAndEqual(bx, bxconj, q, context.N);

	return MFCiphertext(ax, bx, cipher.logp, cipher.logq, cipher.slots, cipher.isComplex);
}

void MFScheme::conjugateAndEqual(MFCiphertext& cipher) {
	ZZ q = context.qpowvec[cipher.logq];
	ZZ qQ = context.qpowvec[cipher.logq + context.logQ];
	ZZX bxconj;
	MFKey key = mfKeyMap.at(CONJUGATION);

	Ring2Utils::conjugate(bxconj, cipher.bx[0], context.N);
	Ring2Utils::conjugate(cipher.bx[0], cipher.ax[0], context.N);

	Ring2Utils::mult(cipher.ax[0], cipher.bx[0], key.ax, qQ, context.N);
	Ring2Utils::multAndEqual(cipher.bx[0], key.bx, qQ, context.N);

	Ring2Utils::rightShiftAndEqual(cipher.ax[0], context.logQ, context.N);
	Ring2Utils::rightShiftAndEqual(cipher.bx[0], context.logQ, context.N);

	Ring2Utils::addAndEqual(cipher.bx[0], bxconj, q, context.N);
}
