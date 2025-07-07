/*
* Copyright (c) by Pengcheng Laboratory.
* This program is licensed under a
* Creative Commons Attribution-NonCommercial 3.0 Unported License.
* You should have received a copy of the license along with this
* work.  If not, see <http://creativecommons.org/licenses/by-nc/3.0/>.
*/
#include "MFTestScheme.h"

#include <NTL/BasicThreadPool.h>
#include <NTL/RR.h>
#include <NTL/ZZ.h>

#include "Common.h"
#include "MFCiphertext.h"
#include "EvaluatorUtils.h"
#include "NumUtils.h"
#include "MFScheme.h"
#include "MFSecretKey.h"
#include "StringUtils.h"
#include "TimeUtils.h"
#include "Context.h"
#include "MFSerializationUtils.h"

#include "Ring2Utils.h"

using namespace std;
using namespace NTL;


//----------------------------------------------------------------------------------
//   STANDARD TESTS
//----------------------------------------------------------------------------------

void MFTestScheme::testGadgetDecompose(long logN, long logQ, long logp, long logSlots, long num_parties){
	Context context(logN, logQ);
	MFScheme mfScheme(context);

    long bits_B = 8;
	long tau = 2*logQ/bits_B + 1; 
    ZZX logg; logg.SetLength(tau);
    for (int i = 0; i < tau; i++) {
        logg[i] = ZZ(bits_B) * i;
    }

	ZZX ax;
	NumUtils::sampleUniform2(ax, 3, context.logQQ);

	vector<ZZX> H = mfScheme.gadgetDecompose(ax, logg, context);	

	// Verify gadget decomposition
    if (mfScheme.verifyDecomposition(ax, H, logg, context)) {
		long QQ = 1 << context.logQQ;
        cout << "Gadget Decompose: Verification successful: <h, g> = " << ax << " (mod " << QQ << ")" << endl;
    } else {
        cout << "Gadget Decompose: Verification failed!" << endl;
    }
}

void MFTestScheme::testGadgetEncryption(long logN, long logQ, long logp, long logSlots, long num_parties) {
    Context context(logN, logQ);
    MFSecretKey mfSecretKey(logN);
    MFScheme mfScheme(mfSecretKey, context);
    long slots = 1 << logSlots;

    long bits_B = 8;
    long tau = 4;
    ZZX logg; logg.SetLength(tau);
    for (int i = 0; i < tau; i++) {
        logg[i] = ZZ(bits_B) * i;
    }	

    ZZX vx;
    NumUtils::sampleZO(vx, context.N);
    MFPlaintext msg_vx = MFPlaintext(vx, logp, logQ, slots, true);

    MFCiphertext cipher = mfScheme.gadgetEncryptMsg(msg_vx, mfSecretKey, logg, context);	

    // // Verify gadget encryption
	mfScheme.verifyGadgetEncryption(msg_vx, cipher, mfSecretKey, logg, context);
}

void MFTestScheme::testExternalProduct(long logN, long logQ, long logp, long logSlots) {
    Context context(logN, logQ);
    MFSecretKey mfSecretKey(logN);
    MFScheme mfScheme(mfSecretKey, context);
    long slots = 1 << logSlots;

	ZZX ax;
	NumUtils::sampleUniform2(ax, context.N, context.logQQ);

    long bits_B = 8;
	long tau = 2*logQ/bits_B + 1;
    ZZX logg; logg.SetLength(tau);
    for (int i = 0; i < tau; i++) {
        logg[i] = ZZ(bits_B) * i;
    }	

    ZZX vx;
    NumUtils::sampleZO(vx, context.N);
    MFPlaintext msg_vx = MFPlaintext(vx, logp, logQ, slots, true);
    MFCiphertext Gamma = mfScheme.gadgetEncryptMsg(msg_vx, mfSecretKey, logg, context);	

    // Verify external product
	if (mfScheme.verifyExternalProduct(msg_vx, mfSecretKey, ax, Gamma, logg, context)) {
		cout << "External product: Verification successful" << endl;
	} else {
		cout << "External product: Verification failed!" << endl;
	}
}

void MFTestScheme::testSecureMFHE(long logN, long logQ, long logp, long logSlots, long num_parties = 2) { 
	cout << "!!! START TEST Secure MKFHE MFScheme (MFHE) !!!" << endl;
	//-----------------------------------------
	TimeUtils timeutils;
	Context context(logN, logQ);
	long party_id1 = 1;
	long party_id2 = 2;
	MFSecretKey mfSecretKeyParty1(logN);
	MFSecretKey mfSecretKeyParty2(logN);
	long N = 1 << logN;
	ZZX key_ax;
	NumUtils::sampleUniform2(key_ax, context.N, context.logQQ);

	MFScheme mfSchemeServer(context);
	timeutils.start("KeyGen");
	MFScheme mfSchemeParty1(mfSecretKeyParty1, key_ax, context);
	timeutils.stop("KeyGen");
	timeutils.start("KeyGen");
	MFScheme mfSchemeParty2(mfSecretKeyParty2, key_ax, context);
	timeutils.stop("KeyGen");
	//-----------------------------------------
	SetNumThreads(1);
	//-----------------------------------------
	srand(time(NULL));
	//-----------------------------------------
	long slots = (1 << logSlots);
	// cout <<"!!! slots: "<< slots << endl;
	complex<double>* mvec1 = EvaluatorUtils::randomComplexArray(slots);
	complex<double>* mvec2 = EvaluatorUtils::randomComplexArray(slots);

	complex<double>* mvecAdd = new complex<double>[slots];
	complex<double>* mvecMult = new complex<double>[slots];
	complex<double>* mvecCMult = new complex<double>[slots];
	for(long i = 0; i < slots; i++) {
		mvecAdd[i] = mvec1[i] + mvec2[i];
	}

	timeutils.start("Encrypt two batch");
	MFCiphertext cipher1 = mfSchemeParty1.encrypt(mvec1, slots, logp, logQ);
	MFCiphertext cipher2 = mfSchemeParty2.encrypt(mvec2, slots, logp, logQ);
	timeutils.stop("Encrypt two batch");

	cipher1.party_id = 1;
	cipher2.party_id = 2;

	timeutils.start("Generate two random polynomials and two complex zero vectors");
	ZZX vx1, vx2;
	NumUtils::sampleZO(vx1, context.N);
	NumUtils::sampleZO(vx2, context.N);
	MFPlaintext msg_vx1 = MFPlaintext(vx1, logp, logQ, slots, true);
	MFPlaintext msg_vx2 = MFPlaintext(vx2, logp, logQ, slots, true);

	complex<double>* zvec1 = new complex<double>[slots];
	complex<double>* zvec2 = new complex<double>[slots];
	for (int i=0; i<slots; i++){
		zvec1[i] = std::complex<double>(0.0, 0.0);
		zvec2[i] = std::complex<double>(0.0, 0.0);
	}

	ZZX mxz1, mxz2;
	mxz1.SetLength(context.N);
	mxz2.SetLength(context.N);
	timeutils.stop("Generate two random polynomials and two complex zero vectors");

	// long bits_B = 8; // The smaller bits_B, the smaller the error of the decrypted results and the longer the runtime.
	long bits_B = 32;
	long tau = 2*logQ/bits_B + 1;
    ZZX logg; logg.SetLength(tau);
    for (size_t i = 0; i < tau; i++) {
        logg[i] = bits_B * i; 
    }
	ZZX g; g.SetLength(tau);
    for (int i = 0; i < tau; i++) {
        g[i] = power(ZZ(2), conv<long>(logg[i])); 
    }

	MaskResults MR1, MR2;

	timeutils.start("Masking Encryption (including gadget encryption)");
	MR1 = mfSchemeParty1.maskEncrypt(mfSecretKeyParty1.sx, vx1, mxz1, logg, slots, logp, logQ);
	MR2 = mfSchemeParty2.maskEncrypt(mfSecretKeyParty2.sx, vx2, mxz2, logg, slots, logp, logQ);
	timeutils.stop("Masking Encryption (including gadget encryption)");	

	MFKey key1 = mfSchemeParty1.mfKeyMap.at(ENCRYPTION);
	MFKey key2 = mfSchemeParty2.mfKeyMap.at(ENCRYPTION);

	timeutils.start("Masking Extend");
	MFCiphertext cx1 = mfSchemeParty1.maskExtend(MR1.Gamma, logg, key1.bx, key2.bx);
	MFCiphertext cx2 = mfSchemeParty2.maskExtend(MR2.Gamma, logg, key2.bx, key1.bx);
	timeutils.stop("Masking Extend");

	MR1.Gamma = cx1; // cx1 = Gamma1 \boxdot (b2-b1)
	MR2.Gamma = cx2; // cx2 = Gamma2 \boxdot (b1-b2)

	timeutils.start("Homomorphic Addition");
	MFCiphertext addCipher = mfSchemeServer.add(cipher1, cipher2, MR1, MR2);
	timeutils.stop("Homomorphic Addition");

	// timeutils.start("Decrypt batch of a addCipher (MFHE)");
	timeutils.start("Partial Decrypt batch of a addCipher (MFHE)");
	MFCiphertext partAddCipher11 = mfSchemeParty1.partDecrypt(mfSecretKeyParty1.sx, addCipher, party_id1=1);
	timeutils.stop("Partial Decrypt batch of a addCipher (MFHE)");
	MFCiphertext partAddCipher12 = mfSchemeParty2.partDecrypt(mfSecretKeyParty2.sx, addCipher, party_id2=2);
	timeutils.start("Full Decrypt batch of a addCipher (MFHE)");
	complex<double>* dvecAdd = mfSchemeServer.fullDecrypt(partAddCipher11, partAddCipher12);
	timeutils.stop("Full Decrypt batch of a addCipher (MFHE)");
	// timeutils.stop("Decrypt batch of a addCipher (MFHE)");
	StringUtils::showcompare(mvecAdd, dvecAdd, slots, "add");

	// timeutils.start("Homomorphic Multiplication");
	// MFCiphertext multCipher = mfSchemeServer.mult(cipher1, cipher2);
	// mfSchemeServer.reScaleByAndEqual(multCipher, logp);
	// timeutils.stop("Homomorphic Multiplication");

	// timeutils.start("Homomorphic Multiplication");
	// MFCiphertext cmultCipher = mfSchemeServer.multByConstVec(cipher1, cvec, slots, logp);
	// mfSchemeServer.reScaleByAndEqual(cmultCipher, logp);
	// timeutils.stop("Homomorphic Multiplication");

	// timeutils.start("Decrypt batch of a multCipher");
	// MFCiphertext partMultCipher11 = mfSchemeParty1.partDecrypt(mfSecretKeyParty1.sx, multCipher, party_id1);
	// MFCiphertext partMultCipher12 = mfSchemeParty2.partDecrypt(mfSecretKeyParty2.sx, multCipher, party_id2);
	// complex<double>* dvecMult = mfSchemeServer.fullDecrypt(partMultCipher11, partMultCipher12);
	// timeutils.stop("Decrypt batch of a multCipher");
	// StringUtils::showcompare(mvecMult, dvecMult, slots, "mult");
}
